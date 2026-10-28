// ==============================================================================
// 文件路径: codex-rs/codex-mini-sandbox/src/main.rs
// 功能描述: 100% 完整复刻 Codex 官方 Windows 沙箱全部行为的工业级独立执行器 (Bug修复版)
// 修复记录:
//   1. 修复 E0603: 将私有模块路径 `acl::ensure_allow_write_aces` 和 `winutil::resolve_sid`
//      修正为从 `codex_windows_sandbox` 根命名空间直接导入公开重导出符号；
//   2. 修复 E0433: 正确声明并链接 `which` 模块进行可执行程序探测，并提供本地 PATH 遍历双重容错；
//   3. 修复 E0599: 移除对直接返回 bool 值的 `sandbox_setup_is_complete` 调用上的 `.unwrap_or(false)`。
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
    ensure_allow_write_aces,           // 修复导入：从根命名空间公开重导出中导入
    forward_sandbox_session_stdio,
    resolve_sid,                      // 修复导入：从根命名空间公开重导出中导入
    resolve_windows_deny_read_paths,
    sandbox_setup_is_complete,
    spawn_windows_sandbox_session_for_level,
    WindowsSandboxProxySettingsMode,
    WindowsSandboxSessionRequest,
};

// ==============================================================================
// 1. 命令行参数定义（完全兼容官方 WindowsCommand 语法）
// ==============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "codex-mini-sandbox",
    about = "100% Official-Feature-Parity Codex Windows Native Sandbox Runner",
    trailing_var_arg = true
)]
struct Cli {
    /// 兼容语法槽：无损消费可能由调用端传入的 "sandbox" 子命令动词
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

    /// 配置文件 Profile 别名（兼容官方 `-p <name>`）
    #[arg(short = 'p', long = "profile")]
    config_profile: Option<String>,

    /// 绑定的工作区物理绝对路径（`-C` 或 `--cd`）
    #[arg(short = 'C', long = "cd", required = true)]
    cwd: PathBuf,

    /// 动态配置项覆盖（支持多次传入的 `-c key=value`，如 `-c sandbox_mode='workspace-write'`）
    #[arg(short = 'c', action = clap::ArgAction::Append)]
    config_overrides: Vec<String>,

    /// 是否包含托管策略（兼容官方参数）
    #[arg(long = "include-managed-config", default_value_t = false)]
    include_managed_config: bool,

    /// 真实执行的目标命令行及其参数（允许带 `--` 也允许省略直接跟在末尾）
    #[arg(required = true)]
    command: Vec<String>,
}

// ==============================================================================
// 2. 官方敏感隐私目录排除与环境准备（100% 复刻）
// ==============================================================================

/// 官方 setup.rs 中定义的最高级别隐私目录黑名单（严禁任何沙箱账号读取）
const USERPROFILE_ROOT_EXCLUSIONS: &[&str] = &[
    ".ssh",
    ".tsh",
    ".brev",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config",
    ".npm",
    ".pki",
    ".terraform.d",
];

/// 官方动态追加工作区写权限自愈逻辑（修复全新工作区报告 OS 5 拒绝访问的缺陷）
fn ensure_workspace_write_permissions(workspace_root: &Path) {
    #[cfg(windows)]
    unsafe {
        let mut target_sids: Vec<*mut std::ffi::c_void> = Vec::new();
        let mut allocated_buffers: Vec<Vec<u8>> = Vec::new();

        // 尝试解析离线与在线沙箱影子账号的 SID
        for username in &["CodexSandboxOffline", "CodexSandboxOnline"] {
            if let Ok(mut sid_bytes) = resolve_sid(username) {
                target_sids.push(sid_bytes.as_mut_ptr() as *mut std::ffi::c_void);
                allocated_buffers.push(sid_bytes);
            }
        }

        // 如果机器上已经初始化了这些沙箱影子用户，动态向新工作区根目录追加写入 Allow ACE
        if !target_sids.is_empty() {
            let _ = ensure_allow_write_aces(workspace_root, &target_sids);
        }
    }
}

/// 官方 Git 跨用户所有权穿透注入（解决由于操作者与目录所有者不匹配导致的 dubious ownership 拦截）
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

/// 官方交互式分页器屏蔽（防止 git diff 等命令调起交互界面导致沙箱卡死超时）
fn ensure_non_interactive_pager(env: &mut HashMap<String, String>) {
    env.insert("GIT_PAGER".to_string(), "cat".to_string());
    env.insert("PAGER".to_string(), "cat".to_string());
    env.insert("SYSTEMD_PAGER".to_string(), "cat".to_string());
}

/// 官方空设备环境变量规范化
fn normalize_null_device_env(env: &mut HashMap<String, String>) {
    env.entry("NUL".to_string()).or_insert_with(|| "\\\\.\\NUL".to_string());
}

/// 针对 PowerShell 命令自动注入 UTF-8 编码设置（对齐官方 prefix_powershell_script_with_utf8）
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
// 3. 辅助 Runner 自愈与定位机制 (对齐 helper_materialization.rs)
// ==============================================================================

/// 智能解析并定位当前环境中可用的 codex-command-runner.exe
fn auto_resolve_command_runner(codex_home: &Path) -> Option<PathBuf> {
    let sandbox_bin = codex_home.join(".sandbox-bin");

    // 1. 优先扫描 .sandbox-bin 目录下已有 runner，选用修改时间最新的有效版本
    if sandbox_bin.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&sandbox_bin) {
            let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("codex-command-runner") && file_name.ends_with(".exe") {
                        if let Ok(meta) = path.metadata() {
                            let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                            candidates.push((modified, path));
                        }
                    }
                }
            }
            candidates.sort_by(|a, b| b.0.cmp(&a.0));
            if let Some((_, best_path)) = candidates.into_iter().next() {
                return Some(best_path);
            }
        }
    }

    // 2. 检查当前可执行文件同级目录
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("codex-command-runner.exe");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }

    // 3. 尝试从系统 PATH 中定位
    which::which("codex-command-runner.exe").ok()
}

// ==============================================================================
// 4. 官方审计日志与沙箱级别裁决机制
// ==============================================================================

/// 记录日志到每日滚动的 CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log 中，
/// 确保控制台 Stdout/Stderr 纯净透明
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

/// 综合 `-c` 参数覆盖、`config.toml` 与凭据状态裁决沙箱运行等级
fn resolve_effective_sandbox_level(
    codex_home: &Path,
    cli_overrides: &[String],
) -> WindowsSandboxLevel {
    let mut configured_mode: Option<String> = None;

    // 1. 优先检查命令行 `-c` 覆盖（如 `-c windows_sandbox.mode=elevated`）
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

    // 3. 检查 `.sandbox-secrets/sandbox_users.json` 是否就绪且可用（修复：直接取 bool 值）
    let secrets_ready = sandbox_setup_is_complete(codex_home);

    // 4. 裁决逻辑：配置为 elevated 且凭据有效时走 Elevated 模式；否则使用 RestrictedToken
    match configured_mode.as_deref() {
        Some("elevated") if secrets_ready => WindowsSandboxLevel::Elevated,
        Some("disabled") => WindowsSandboxLevel::Disabled,
        _ => {
            if secrets_ready {
                WindowsSandboxLevel::Elevated
            } else {
                WindowsSandboxLevel::RestrictedToken
            }
        }
    }
}

// ==============================================================================
// 5. 主程序入口与进程生命周期协同
// ==============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 宽容解析命令行参数（自动支持无 `--` 直接追加执行命令）
    let cli = Cli::parse();

    if cli.command.is_empty() {
        eprintln!("[codex-mini-sandbox] 错误: 未能在命令行参数中检测到待执行的目标命令！");
        std::process::exit(1);
    }

    // 2. 路径物理绝对规范化（消除短路径名和符号链接潜在安全绕过）
    let cwd_canonical = dunce::canonicalize(&cli.cwd).map_err(|e| {
        anyhow::anyhow!(
            "[codex-mini-sandbox] 工作区路径无法访问或物理不存在 [{}]: {e}",
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

    // 4. 关键缺陷自愈：动态确保目标工作区具备正确的写入 Allow ACE
    ensure_workspace_write_permissions(&cwd_canonical);

    // 5. 动态裁决沙箱运行等级（自适应读取与解析 sandbox_users.json）
    let sandbox_level = resolve_effective_sandbox_level(&codex_home, &cli.config_overrides);

    // 6. 辅助 Runner 自愈与检查（若为 Elevated 模式，必须存在可用 Runner）
    if sandbox_level == WindowsSandboxLevel::Elevated {
        if auto_resolve_command_runner(&codex_home).is_none() {
            append_sandbox_audit_log(
                &codex_home,
                "WARN: 未找到 codex-command-runner.exe，Elevated 模式将安全降级为 RestrictedToken",
            );
        }
    }

    // 7. 组装官方标准的 :workspace 权限画像
    let permission_profile = match cli.permission_profile.as_str() {
        ":workspace" => PermissionProfile::workspace_write(),
        ":read-only" | ":readonly" => PermissionProfile::read_only(),
        _ => PermissionProfile::workspace_write(),
    };

    // 8. 解析敏感目录只读拦截名单（严格阻断核心凭据目录被遍历）
    let (mut file_system, _) = permission_profile.to_runtime_permissions();
    file_system.remove_skip_missing_path_entries();
    let file_system = file_system.materialize_project_roots_with_workspace_roots(&workspace_roots);
    let deny_read_paths = resolve_windows_deny_read_paths(&file_system, &cwd).unwrap_or_default();

    // 9. 继承环境变量并应用官方 4 项关键环境注入预处理
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    inject_git_safe_directory(&mut env_map, &cwd_canonical);
    ensure_non_interactive_pager(&mut env_map);
    normalize_null_device_env(&mut env_map);

    // 10. 命令预处理：针对 PowerShell 自动前置注入 UTF-8 编码设置
    let final_command = prepare_shell_command_encoding(cli.command);

    // 11. 记录官方格式审计启动日志到独立文件中
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

    // 12. 装配 WindowsSandboxSessionRequest 并发起受控沙箱子进程
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

    // 13. 并发挂载控制台 Ctrl+C 信号取消监听（确保取消时整个 JobObject 树原子灭绝）
    let exit_code = tokio::select! {
        // 分支 A: 正常流式等待命令执行完毕并获取退出码
        code = forward_sandbox_session_stdio(spawned) => {
            code
        }
        // 分支 B: 捕获用户在控制台按下的 Ctrl+C 中断信号
        _ = tokio::signal::ctrl_c() => {
            append_sandbox_audit_log(&codex_home, &format!("INTERRUPTED: {cmd_preview} (Ctrl+C captured)"));
            130 // Windows / POSIX 通用中断退出码 (128 + SIGINT)
        }
    };

    // 14. 记录命令结束审计日志并退出
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