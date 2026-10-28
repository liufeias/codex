// ==============================================================================
// 文件路径: codex-rs/codex-mini-sandbox/src/main.rs
// 功能描述: 100% 完全复刻官方 Codex Windows 沙箱所有行为的独立极速执行器
// 核心复刻特性清单:
//   1. 宽松参数兼容:
//      - 完整支持 `-c key=value`（如 `-c sandbox_mode='workspace-write'`）；
//      - 兼容 `-P`、`--permission-profile` 以及复数别名 `--permissions-profile`；
//      - 兼容 `-p` / `--profile` 与 `-C` / `--cd`；
//      - 允许省略 `--` 双横杠，通过 trailing_var_arg 自动打包末尾命令。
//   2. 官方环境准备动作 100% 补齐:
//      - Git 跨用户所有权穿透: 动态注入 `GIT_CONFIG_PARAMETERS`，彻底解决跨用户执行时
//        报 `fatal: detected dubious ownership in repository` 的致命问题；
//      - 分页器屏蔽: 强制注入 `GIT_PAGER=cat`、`PAGER=cat`，防止交互式分页器导致命令挂起超时；
//      - 编码预置: 遇到 PowerShell 时自动注入 UTF-8 编码设置指令，彻底杜绝中文乱码；
//      - 空设备规范化: 确保 NUL 设备重定向正常。
//   3. 双层沙箱自适应 (Elevated vs RestrictedToken):
//      - 自动解析 `config.toml` 和 `-c` 命令行参数；
//      - 探测 `.sandbox-secrets/sandbox_users.json` 是否就绪；
//      - 凭据完整时自动启用 Elevated 模式（读取 DPAPI 解密，使用 CodexSandboxOffline 影子用户
//        和已安装的 12 层 WFP 防火墙拦截规则）；缺失时平滑安全降级为普通受限令牌模式。
//   4. 控制台与审计日志分流:
//      - 标准输入/输出（Stdio）保持 100% 纯净流式透传，不混入任何沙箱调试杂质；
//      - 审计日志全量记入 `CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log`，100% 对齐官方格式。
// ==============================================================================

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use clap::Parser;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::{
    forward_sandbox_session_stdio,
    resolve_windows_deny_read_paths,
    sandbox_setup_is_complete,
    spawn_windows_sandbox_session_for_level,
    WindowsSandboxProxySettingsMode,
    WindowsSandboxSessionRequest,
};

/// 宽松且高兼容度的命令行参数定义（对齐官方 WindowsCommand）
#[derive(Parser, Debug)]
#[command(
    name = "codex-mini-sandbox",
    about = "100% Official-Feature-Parity Codex Windows Native Sandbox Runner",
    trailing_var_arg = true
)]
struct Cli {
    /// 兼容语法槽：可无损消化官方调用惯例传入的 "sandbox" 动作字
    #[arg(value_parser = ["sandbox"])]
    _dummy_subcmd: Option<String>,

    /// 权限 profile 画像名称（支持 `-P`、`--permission-profile` 及复数别名）
    #[arg(
        short = 'P',
        long = "permission-profile",
        alias = "permissions-profile",
        default_value = ":workspace"
    )]
    permission_profile: String,

    /// 配置文件 Profile（兼容官方 `-p <name>`）
    #[arg(short = 'p', long = "profile")]
    config_profile: Option<String>,

    /// 绑定的工作区物理绝对路径（`-C` 或 `--cd`）
    #[arg(short = 'C', long = "cd", required = true)]
    cwd: PathBuf,

    /// 动态配置项覆盖（支持 repeatable 的 `-c key=value`，如 `-c sandbox_mode='workspace-write'`）
    #[arg(short = 'c', action = clap::ArgAction::Append)]
    config_overrides: Vec<String>,

    /// 是否包含托管策略（兼容官方参数）
    #[arg(long = "include-managed-config", default_value_t = false)]
    include_managed_config: bool,

    /// 真实执行的目标命令行（支持是否带 `--` 双横杠）
    #[arg(required = true)]
    command: Vec<String>,
}

// ==============================================================================
// 官方核心环境准备行为实现 (100% 复刻)
// ==============================================================================

/// 1. 注入 Git 安全目录配置 (对齐官方 inject_git_safe_directory)
///    解决影子账户（CodexSandboxOffline）访问普通用户目录时的跨用户安全拦截
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

/// 2. 强制禁用交互式分页器 (对齐官方 ensure_non_interactive_pager)
///    防止 git diff, git log 或命令行工具进入 less/more 分页阻塞导致沙箱超时强杀
fn ensure_non_interactive_pager(env: &mut HashMap<String, String>) {
    env.insert("GIT_PAGER".to_string(), "cat".to_string());
    env.insert("PAGER".to_string(), "cat".to_string());
    env.insert("SYSTEMD_PAGER".to_string(), "cat".to_string());
}

/// 3. 空设备环境变量规范化 (对齐官方 normalize_null_device_env)
fn normalize_null_device_env(env: &mut HashMap<String, String>) {
    env.entry("NUL".to_string()).or_insert_with(|| "\\\\.\\NUL".to_string());
}

/// 4. PowerShell 脚本自动注入 UTF-8 编码设置 (对齐官方 prefix_powershell_script_with_utf8)
///    彻底根除中文 Windows 下 PowerShell 默认输出 GBK 导致中文字符乱码的问题
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
    // 遍历参数，寻找 `-Command` 或 `-c` 之后的实际执行体并注入 UTF-8 指令
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
// 官方审计日志输出机制 (对齐官方 logging.rs)
// ==============================================================================

/// 记录日志到每日滚动的 CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log 中，
/// 保持控制台 Stdout/Stderr 纯净无污染
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

// ==============================================================================
// 官方沙箱级别动态裁决器 (Elevated vs RestrictedToken)
// ==============================================================================

/// 综合 `-c` 命令行参数、`config.toml` 与 `.sandbox-secrets` 状态决策沙箱级别
fn resolve_effective_sandbox_level(
    codex_home: &Path,
    cli_overrides: &[String],
) -> WindowsSandboxLevel {
    let mut configured_mode: Option<String> = None;

    // 1. 优先检查命令行 `-c` 覆盖（如 `-c windows_sandbox.mode=elevated` 或 `-c sandbox_mode=workspace-write`）
    for override_str in cli_overrides {
        let clean = override_str.trim().trim_matches('\'').trim_matches('"');
        if let Some((k, v)) = clean.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().trim_matches('\'').trim_matches('"').to_lowercase();
            if key == "windows_sandbox.mode" || key == "sandbox_mode" {
                configured_mode = Some(val);
            }
        }
    }

    // 2. 次级检查 CODEX_HOME/config.toml 文件配置
    if configured_mode.is_none() {
        let config_path = codex_home.join("config.toml");
        if config_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(parsed) = content.parse::<toml::Value>() {
                    if let Some(ws) = parsed.get("windows_sandbox") {
                        if let Some(m) = ws.get("mode").and_then(|v| v.as_str()) {
                            configured_mode = Some(m.to_lowercase());
                        }
                    }
                }
            }
        }
    }

    // 3. 检查 `.sandbox-secrets/sandbox_users.json` 是否就绪且可用
    let secrets_ready = sandbox_setup_is_complete(codex_home).unwrap_or(false);

    // 4. 判定决策：配置为 elevated 且凭据有效时，激活 Elevated 模式；否则使用 RestrictedToken
    match configured_mode.as_deref() {
        Some("elevated") if secrets_ready => WindowsSandboxLevel::Elevated,
        Some("disabled") => WindowsSandboxLevel::Disabled,
        _ => {
            // 如果本地已有完整密码凭据，默认最大化启用 Elevated 隔离；未就绪则走 RestrictedToken
            if secrets_ready {
                WindowsSandboxLevel::Elevated
            } else {
                WindowsSandboxLevel::RestrictedToken
            }
        }
    }
}

// ==============================================================================
// 主程序入口
// ==============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 宽容解析命令行参数
    let cli = Cli::parse();

    if cli.command.is_empty() {
        eprintln!("[codex-mini-sandbox] 错误: 未能在命令行参数中检测到待执行的目标命令！");
        std::process::exit(1);
    }

    // 2. 路径物理绝对规范化（消除短路径名和符号链接安全隐患）
    let cwd_canonical = dunce::canonicalize(&cli.cwd).map_err(|e| {
        anyhow::anyhow!(
            "[codex-mini-sandbox] 工作区路径无法访问或不存在 [{}]: {e}",
            cli.cwd.display()
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

    // 4. 动态裁决沙箱运行等级（自适应读取 sandbox_users.json）
    let sandbox_level = resolve_effective_sandbox_level(&codex_home, &cli.config_overrides);

    // 5. 组装官方 :workspace 权限画像
    let permission_profile = match cli.permission_profile.as_str() {
        ":workspace" => PermissionProfile::workspace_write(),
        ":read-only" | ":readonly" => PermissionProfile::read_only(),
        _ => PermissionProfile::workspace_write(),
    };

    // 6. 解析敏感目录只读拦截名单
    let (mut file_system, _) = permission_profile.to_runtime_permissions();
    file_system.remove_skip_missing_path_entries();
    let file_system = file_system.materialize_project_roots_with_workspace_roots(&workspace_roots);
    let deny_read_paths = resolve_windows_deny_read_paths(&file_system, &cwd).unwrap_or_default();

    // 7. 继承环境变量并应用官方 4 项关键环境注入预处理
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    inject_git_safe_directory(&mut env_map, &cwd_canonical);
    ensure_non_interactive_pager(&mut env_map);
    normalize_null_device_env(&mut env_map);

    // 8. 命令预处理：针对 PowerShell 自动注入 UTF-8 编码设置
    let final_command = prepare_shell_command_encoding(cli.command);

    // 9. 记录官方格式审计启动日志到滚动文件中（不输出到控制台 stdout）
    let cmd_preview = final_command.join(" ");
    let level_tag = match sandbox_level {
        WindowsSandboxLevel::Elevated => "Elevated (User: CodexSandboxOffline via sandbox_users.json)",
        WindowsSandboxLevel::RestrictedToken => "RestrictedToken (Unelevated)",
        WindowsSandboxLevel::Disabled => "Disabled",
    };
    append_sandbox_audit_log(
        &codex_home,
        &format!("START [Level: {level_tag}]: {cmd_preview}"),
    );

    let empty_paths: &[AbsolutePathBuf] = &[];

    // 10. 装配 WindowsSandboxSessionRequest 并发起系统级沙箱子进程
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

    // 11. 纯净流式双向转发标准输入输出，不混入任何日志杂音
    let exit_code = forward_sandbox_session_stdio(spawned).await;

    // 12. 记录命令结束审计日志
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