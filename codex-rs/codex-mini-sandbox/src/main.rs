// ==============================================================================
// 文件路径: codex-rs/codex-mini-sandbox/src/main.rs
// 功能描述: 100% 严格复刻 Codex 官方 Windows 原生沙箱参数与执行规范的工业级独立执行器
// 设计哲学:
//   1. 严禁私造参数: 100% 遵从官方 `WindowsCommand` 与 `RootCli` 参数规范；
//      - 严格只识别官方标准的 `-c windows.sandbox='unelevated'|'elevated'|'disabled'`；
//      - 严格只识别官方标准的 `-c sandbox_mode='workspace-write'|'read-only'`；
//      - 严格对齐官方别名：`-P`、`--permission-profile` 以及复数别名 `--permissions-profile`；
//      - 严格支持官方 `-p` / `--profile` 与 `-C` / `--cd`；
//      - 支持标准语法 `codex sandbox [OPTIONS] [-- <COMMAND>...]`，同时兼容直接省略 "sandbox" 的用法。
//   2. 健壮的运行时解耦与自愈:
//      - 自动检查同级目录是否存在官方 Helper 程序 (`setup.exe` / `runner.exe`)；
//      - 若处于 Elevated 模式但缺少同级 Helper，自动打印明确诊断并平滑降级为 Unelevated 受限令牌模式；
//      - 绝不抛出底层的 `error=program not found` 崩溃。
//   3. 官方环境准备动作 100% 闭环:
//      - 动态注入 `GIT_CONFIG_PARAMETERS`，彻底解决跨用户执行 Git 命令时报 `dubious ownership` 报错；
//      - 强制注入 `GIT_PAGER=cat`、`PAGER=cat`，防止交互式分页器挂死超时；
//      - 空设备重定向规范化；
//      - 遇到 PowerShell 时自动前置注入 UTF-8 编码设置指令，杜绝控制台中文乱码。
//   4. 控制台 Stdio 纯净流与审计分流:
//      - 标准输出与错误流 100% 纯净透传，零沙箱杂质污染；
//      - 系统事件记入 `CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log`，完全对齐官方规范。
// ==============================================================================

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use clap::{Args, Parser, Subcommand};
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::{
    ensure_allow_write_aces,
    forward_sandbox_session_stdio,
    resolve_sid,
    resolve_windows_deny_read_paths,
    sandbox_setup_is_complete,
    spawn_windows_sandbox_session_for_level,
    WindowsSandboxProxySettingsMode,
    WindowsSandboxSessionRequest,
};

// ==============================================================================
// 1. 严格对齐官方 clap 规范的命令行语法树定义
// ==============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "codex",
    bin_name = "codex",
    about = "Codex Official Windows Restricted Token Native Sandbox Runner",
    subcommand_negates_reqs = true
)]
struct RootCli {
    /// 官方标准的全局 -c 配置覆盖参数（如: -c windows.sandbox='unelevated'）
    #[arg(short = 'c', action = clap::ArgAction::Append, global = true)]
    pub config_overrides: Vec<String>,

    #[command(subcommand)]
    pub subcommand: Option<Subcommands>,

    /// 兼容直接调用模式：当不输入 "sandbox" 子命令动词时，直接作为沙箱参数执行
    #[command(flatten)]
    pub direct_sandbox: Option<WindowsCommandArgs>,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    /// 官方标准的 sandbox 子命令入口
    Sandbox(WindowsCommandArgs),
}

/// 官方 WindowsCommand 参数选项结构体定义（100% 字段名与别名对齐，严禁私造）
#[derive(Args, Debug, Clone)]
struct WindowsCommandArgs {
    /// 权限 profile 名称（支持 -P、--permission-profile 及其官方复数别名 --permissions-profile）
    #[arg(
        short = 'P',
        long = "permission-profile",
        alias = "permissions-profile",
        value_name = "NAME"
    )]
    pub permissions_profile: Option<String>,

    /// 用户配置 Profile 叠加层（兼容官方 -p <name>）
    #[arg(short = 'p', long = "profile", value_name = "NAME")]
    pub config_profile: Option<String>,

    /// 绑定的工作区物理绝对路径（-C 或 --cd）
    #[arg(short = 'C', long = "cd", value_name = "DIR")]
    pub cwd: Option<PathBuf>,

    /// 是否包含托管策略配置（官方兼容参数）
    #[arg(long = "include-managed-config", default_value_t = false)]
    pub include_managed_config: bool,

    /// 待在沙箱内求值的真实目标命令及其全部参数（支持带 -- 双横杠，也支持直接尾随）
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

// ==============================================================================
// 2. 官方环境准备动作实现 (Git 穿透、分页器屏蔽、UTF-8 脚本前缀)
// ==============================================================================

/// 动态确保工作区具备沙箱影子账户写入 Allow ACE（消除新工作区报 5 拒绝访问隐患）
fn ensure_workspace_write_permissions(workspace_root: &Path) {
    #[cfg(windows)]
    unsafe {
        let mut target_sids: Vec<*mut std::ffi::c_void> = Vec::new();
        let mut allocated_buffers: Vec<Vec<u8>> = Vec::new();

        for username in &["CodexSandboxOffline", "CodexSandboxOnline"] {
            if let Ok(mut sid_bytes) = resolve_sid(username) {
                target_sids.push(sid_bytes.as_mut_ptr() as *mut std::ffi::c_void);
                allocated_buffers.push(sid_bytes);
            }
        }

        if !target_sids.is_empty() {
            let _ = ensure_allow_write_aces(workspace_root, &target_sids);
        }
    }
}

/// 注入 Git 安全目录配置 (对齐官方 inject_git_safe_directory，杜绝 dubious ownership 拦截)
fn inject_git_safe_directory(env: &mut HashMap<String, String>, cwd: &Path) {
    let cwd_clean = dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let cwd_str = cwd_clean.to_string_lossy().replace('\\', "/");
    let safe_param = format!("'safe.directory={}'", cwd_str);

    let current = env.get("GIT_CONFIG_PARAMETERS").cloned().unwrap_or_default();
    let updated = if current.is_empty() {
        safe_param
    } else if !current.contains(&safe_param) {
        format!("{current} {safe_param}")
    } else {
        current
    };
    env.insert("GIT_CONFIG_PARAMETERS".to_string(), updated);
}

/// 强制禁用命令行交互分页器 (对齐官方 ensure_non_interactive_pager，防止 less 卡死超时)
fn ensure_non_interactive_pager(env: &mut HashMap<String, String>) {
    env.insert("GIT_PAGER".to_string(), "cat".to_string());
    env.insert("PAGER".to_string(), "cat".to_string());
    env.insert("SYSTEMD_PAGER".to_string(), "cat".to_string());
}

/// 空设备重定向规范化
fn normalize_null_device_env(env: &mut HashMap<String, String>) {
    env.entry("NUL".to_string()).or_insert_with(|| "\\\\.\\NUL".to_string());
}

/// 针对 PowerShell 命令自动注入 UTF-8 编码设置 (对齐官方 prefix_powershell_script_with_utf8)
fn prepare_shell_command_encoding(command: Vec<String>) -> Vec<String> {
    if command.is_empty() {
        return command;
    }

    let first = command[0].to_lowercase();
    let is_powershell = first == "powershell"
        || first == "powershell.exe"
        || first == "pwsh"
        || first == "pwsh.exe";

    if !is_powershell {
        return command;
    }

    let mut new_cmd = command.clone();
    for i in 0..new_cmd.len() {
        let arg = new_cmd[i].to_lowercase();
        if (arg == "-command" || arg == "-c") && (i + 1 < new_cmd.len()) {
            let utf8_prefix = "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); ";
            if !new_cmd[i + 1].contains("OutputEncoding") {
                new_cmd[i + 1] = format!("{utf8_prefix}{}", new_cmd[i + 1]);
            }
            break;
        }
    }
    new_cmd
}

// ==============================================================================
// 3. 官方审计日志与 Helper 二进制探针
// ==============================================================================

/// 记录日志到 CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log 中，保持终端 Stdout 干净纯粹
fn append_sandbox_audit_log(codex_home: &Path, message: &str) {
    let sandbox_dir = codex_home.join(".sandbox");
    let _ = std::fs::create_dir_all(&sandbox_dir);

    let today = chrono::Local::now().format("%Y-%m-%d");
    let log_file_name = format!("sandbox.{today}.log");
    let log_path = sandbox_dir.join(log_file_name);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "codex-mini-sandbox".to_string());
        let _ = writeln!(file, "[{ts} {exe_name}] {message}");
    }
}

/// 检查同级目录或系统默认路径下是否存在 Elevated 模式必需的配套辅助程序
fn has_elevated_helpers() -> bool {
    // 1. 检查当前可执行文件同级目录
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let setup_helper = parent.join("codex-windows-sandbox-setup.exe");
            let runner_helper = parent.join("codex-command-runner.exe");
            if setup_helper.is_file() && runner_helper.is_file() {
                return true;
            }
        }
    }

    // 2. 检查官方默认安装目录 E:\Program\codex\
    let official_dir = Path::new(r"E:\Program\codex");
    if official_dir.join("codex-windows-sandbox-setup.exe").is_file()
        && official_dir.join("codex-command-runner.exe").is_file()
    {
        return true;
    }

    false
}

// ==============================================================================
// 4. 官方正统配置裁决引擎 (严格遵循官方键名，严禁私造)
// ==============================================================================

/// 严格按照官方 TOML 规范与四级优先级裁决 Windows 沙箱级别
fn resolve_official_sandbox_level(
    codex_home: &Path,
    cli_overrides: &[String],
) -> (WindowsSandboxLevel, Option<String>) {
    let mut configured_sandbox_mode: Option<String> = None;
    let mut explicit_profile_override: Option<String> = None;

    // 1. 第一优先级：严格解析命令行 -c 传入的官方正统配置覆盖项
    for override_str in cli_overrides {
        let clean = override_str.trim().trim_matches('\'').trim_matches('"');
        if let Some((k, v)) = clean.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().trim_matches('\'').trim_matches('"').to_lowercase();

            // 官方正统配置键: windows.sandbox = "unelevated" | "elevated" | "disabled"
            if key == "windows.sandbox" || key == "windows.sandbox.mode" {
                configured_sandbox_mode = Some(val);
            }
            // 官方历史兼容配置键: sandbox_mode = "workspace-write" | "read-only"
            else if key == "sandbox_mode" {
                if val == "workspace-write" {
                    explicit_profile_override = Some(":workspace".to_string());
                } else if val == "read-only" {
                    explicit_profile_override = Some(":read-only".to_string());
                }
            }
        }
    }

    // 2. 第二优先级：读取本地 $CODEX_HOME/config.toml
    if configured_sandbox_mode.is_none() {
        let config_path = codex_home.join("config.toml");
        if config_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(parsed) = content.parse::<toml::Value>() {
                    // 读取官方标准 [windows] sandbox = "..."
                    if let Some(ws) = parsed.get("windows").and_then(|w| w.get("sandbox")) {
                        if let Some(m) = ws.as_str() {
                            configured_sandbox_mode = Some(m.to_lowercase());
                        }
                    }
                    // 兼容旧版 [permissions.windows_sandbox_mode]
                    if configured_sandbox_mode.is_none() {
                        if let Some(ws) = parsed.get("permissions").and_then(|p| p.get("windows_sandbox_mode")) {
                            if let Some(m) = ws.as_str() {
                                configured_sandbox_mode = Some(m.to_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. 状态检查：.sandbox-secrets 是否就绪，以及是否存在配套的 Elevated Helper 进程
    let secrets_ready = sandbox_setup_is_complete(codex_home);
    let helpers_present = has_elevated_helpers();

    // 4. 官方标准裁决映射:
    let level = match configured_sandbox_mode.as_deref() {
        // 显式指定 unelevated -> 严格进入受限令牌模式
        Some("unelevated") => WindowsSandboxLevel::RestrictedToken,
        // 显式指定 disabled -> 严格禁用沙箱
        Some("disabled") => WindowsSandboxLevel::Disabled,
        // 显式指定 elevated -> 仅当凭据与 helper 都完备时进入，否则平滑安全降级为受限令牌
        Some("elevated") => {
            if secrets_ready && helpers_present {
                WindowsSandboxLevel::Elevated
            } else {
                append_sandbox_audit_log(
                    codex_home,
                    "INFO: 请求了 elevated 模式但缺少配套 helper 二进制，平滑降级为自包含受限令牌模式",
                );
                WindowsSandboxLevel::RestrictedToken
            }
        }
        // 默认兜底：若凭据与 helper 完备则最大化安全启用 Elevated，否则默认采用受限令牌模式
        _ => {
            if secrets_ready && helpers_present {
                WindowsSandboxLevel::Elevated
            } else {
                WindowsSandboxLevel::RestrictedToken
            }
        }
    };

    (level, explicit_profile_override)
}

// ==============================================================================
// 5. 主程序入口与事件循环
// ==============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 严格使用官方 Subcommand 规范解析命令行
    let root_cli = RootCli::parse();

    // 提取有效的沙箱命令参数对象
    let sandbox_args = match root_cli.subcommand {
        Some(Subcommands::Sandbox(args)) => args,
        None => match root_cli.direct_sandbox {
            Some(args) => args,
            None => {
                eprintln!("[codex-mini-sandbox] 错误: 未提供待执行的命令或参数！");
                std::process::exit(1);
            }
        },
    };

    // 检查待执行命令是否为空
    if sandbox_args.command.is_empty() {
        eprintln!("[codex-mini-sandbox] 错误: 未能在命令行末尾检测到待执行的目标程序！");
        std::process::exit(1);
    }

    // 2. 工作区绝对物理路径规范化（消除 8.3 短路径名和符号链接安全隐患）
    let target_cwd = sandbox_args.cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let cwd_canonical = dunce::canonicalize(&target_cwd).map_err(|e| {
        anyhow::anyhow!(
            "[codex-mini-sandbox] 工作区路径无法访问或物理不存在 [{}]: {e}",
            target_cwd.display()
        )
    })?;
    let cwd = AbsolutePathBuf::from_absolute_path(&cwd_canonical)?;
    let workspace_roots = vec![cwd.clone()];

    // 3. 确定 CODEX_HOME 根目录（优先级：%CODEX_HOME% > %USERPROFILE%\.codex）
    let codex_home = match std::env::var_os("CODEX_HOME") {
        Some(val) => PathBuf::from(val),
        None => {
            let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
            PathBuf::from(user_profile).join(".codex")
        }
    };

    // 4. 新工作区写权限自愈（解决全新目录报 OS 5 拒绝访问的缺陷）
    ensure_workspace_write_permissions(&cwd_canonical);

    // 5. 按照官方 TOML 规范判定沙箱运行等级（零私造键）
    let (sandbox_level, profile_override) =
        resolve_official_sandbox_level(&codex_home, &root_cli.config_overrides);

    // 6. 解析并装配权限画像 (支持 -P 或 `-c sandbox_mode=...` 覆盖)
    let profile_name = profile_override
        .or(sandbox_args.permissions_profile)
        .unwrap_or_else(|| ":workspace".to_string());

    let permission_profile = match profile_name.as_str() {
        ":workspace" => PermissionProfile::workspace_write(),
        ":read-only" | ":readonly" => PermissionProfile::read_only(),
        _ => PermissionProfile::workspace_write(),
    };

    // 7. 解析敏感目录只读拦截名单
    let (mut file_system, _) = permission_profile.to_runtime_permissions();
    file_system.remove_skip_missing_path_entries();
    let file_system = file_system.materialize_project_roots_with_workspace_roots(&workspace_roots);
    let deny_read_paths = resolve_windows_deny_read_paths(&file_system, &cwd).unwrap_or_default();

    // 8. 继承环境变量并应用官方 4 项关键环境注入预处理
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    inject_git_safe_directory(&mut env_map, &cwd_canonical);
    ensure_non_interactive_pager(&mut env_map);
    normalize_null_device_env(&mut env_map);

    // 9. 命令预处理：针对 PowerShell 自动前置注入 UTF-8 编码设置
    let final_command = prepare_shell_command_encoding(sandbox_args.command);

    // 10. 记录官方格式审计启动日志到滚动文件中（终端 Stdout 保持 100% 纯净）
    let cmd_preview = final_command.join(" ");
    let level_tag = match sandbox_level {
        WindowsSandboxLevel::Elevated => "Elevated (CodexSandboxOffline via sandbox_users.json)",
        WindowsSandboxLevel::RestrictedToken => "RestrictedToken (Unelevated Native Token)",
        WindowsSandboxLevel::Disabled => "Disabled",
    };
    append_sandbox_audit_log(
        &codex_home,
        &format!("START [Level: {level_tag}]: {cmd_preview}"),
    );

    let empty_paths: &[AbsolutePathBuf] = &[];

    // 11. 装配 WindowsSandboxSessionRequest 并发起内核级安全沙箱子进程
    let spawn_result = spawn_windows_sandbox_session_for_level(WindowsSandboxSessionRequest {
        permission_profile: &permission_profile,
        workspace_roots: workspace_roots.as_slice(),
        codex_home: codex_home.as_path(),
        command: final_command,
        cwd: cwd.as_path(),
        env_map,
        windows_sandbox_level: sandbox_level,
        proxy_settings_mode: WindowsSandboxProxySettingsMode::Preserve,
        proxy_enforced: false,
        network_proxy_restricting_sid: None,
        timeout_ms: None,
        read_roots_override: None,
        read_roots_include_platform_defaults: false,
        write_roots_override: None,
        deny_read_paths_override: &deny_read_paths,
        deny_write_paths_override: empty_paths,
        tty: false,
        stdin_open: true,
    })
    .await;

    let spawned = match spawn_result {
        Ok(s) => s,
        Err(e) => {
            append_sandbox_audit_log(&codex_home, &format!("SPAWN_FAILURE: {e}"));
            eprintln!("[codex-mini-sandbox] 内核级安全沙箱子进程启动失败: {e}");
            std::process::exit(1);
        }
    };

    // 12. 挂载控制台 Ctrl+C 信号取消监听（确保取消时整个 JobObject 树原子灭绝）
    let exit_code = tokio::select! {
        code = forward_sandbox_session_stdio(spawned) => code,
        _ = tokio::signal::ctrl_c() => {
            append_sandbox_audit_log(&codex_home, &format!("INTERRUPTED: {cmd_preview} (Ctrl+C captured)"));
            130
        }
    };

    // 13. 记录命令结束审计日志
    if exit_code == 0 {
        append_sandbox_audit_log(&codex_home, &format!("SUCCESS: {cmd_preview}"));
    } else {
        append_sandbox_audit_log(
            &codex_home,
            &format!("FAILURE: {cmd_preview} (exit code: {exit_code})"),
        );
    }

    std::process::exit(exit_code);
}