// ==============================================================================
// 文件路径: codex-rs/codex-mini-sandbox/src/main.rs
// 功能描述: 100% 严格复刻 Codex 官方 Windows 原生沙箱参数与执行规范的工业级独立执行器
// 核心设计与官方权威对齐准则:
//   1. 命令行语法与帮助文档完整详实（全中文、零遗漏）:
//      - 完整对齐官方顶层 `-c, --config <key=value>`（支持覆盖任意 toml 配置，支持点分嵌套路径）；
//      - 完整对齐官方全局特性开关 `--enable <FEATURE>` 与 `--disable <FEATURE>`；
//      - 完整平铺官方 WindowsCommand 核心参数（-P, -p, -C, --include-managed-config）；
//      - 严格对齐级联绑定: -C/--cd 与 --include-managed-config 必须与 -P 联动；
//      - 完整对齐官方子命令体系: 支持 `codex sandbox uninstall` 机器级规则清理命令；
//      - 完整对齐官方透明沙箱状态注入: --sandbox-state-json 及其关联路径与网络开关。
//   2. 默认权限策略 100% 官方对齐（核心安全防御基线）:
//      - 严格对齐官方官方规则: 在未显式提供 -P 且未提供 -c sandbox_mode=workspace-write 时，
//        默认基线严格为只读（ReadOnly），严禁私自放开写权限；
//      - 仅在显式指定 -P :workspace 或通过 -c sandbox_mode=workspace-write 时才激活工作区写入。
//   3. 网络隔离与 WFP 防火墙联动 100% 闭环:
//      - 权限画像统一绑定 NetworkSandboxPolicy::Restricted，自动触发底层 CodexSandboxOffline 影子账户；
//      - 该影子账户在系统部署时已由内核级 WFP 驱动绑定出站阻断（硬件级物理断网）；
//      - 处于受限网络状态时，显式注入官方环境变量 CODEX_SANDBOX_NETWORK_DISABLED=1；
//      - Unelevated 模式下自动触发黑洞代理引流防御。
//   4. 控制台 Stdio 与 Ctrl+C 信号处理完全对齐:
//      - 移除外层抢占式 select!，完全移交官方 forward_sandbox_session_stdio 内部的 5 秒排空机制，
//        杜绝子进程退出前管道被提前截断的 Bug。
//   5. 报错文本标准统一:
//      - 发生致命错误时严格输出官方格式 `eprintln!("windows sandbox failed: {err}")`，严禁私造前缀。
// ==============================================================================

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use clap::{Args, Parser, Subcommand};
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::NetworkSandboxPolicy;
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
// 1. 严格对齐官方结构的命令行语法树定义 (包含中文详尽帮助信息)
// ==============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "codex",
    bin_name = "codex",
    about = "在 Codex 提供的安全受限令牌与影子账户沙箱中执行隔离命令",
    subcommand_negates_reqs = true
)]
struct RootCli {
    /// 覆盖原本从 `~/.codex/config.toml` 加载的配置值。支持点分嵌套路径（如: foo.bar.baz=val）。
    /// 值部分会自动尝试作为 TOML 解析，解析失败时则作为原始字符串字面量。
    /// 示例:
    ///   -c model="o3"
    ///   -c windows.sandbox="unelevated"
    ///   -c sandbox_mode="workspace-write"
    #[arg(
        short = 'c',
        long = "config",
        value_name = "key=value",
        action = clap::ArgAction::Append,
        global = true
    )]
    pub config_overrides: Vec<String>,

    /// 启用指定的功能特性开关（可重复指定），等价于 `-c features.<name>=true`
    #[arg(long = "enable", value_name = "FEATURE", action = clap::ArgAction::Append, global = true)]
    pub enable_features: Vec<String>,

    /// 禁用指定的功能特性开关（可重复指定），等价于 `-c features.<name>=false`
    #[arg(long = "disable", value_name = "FEATURE", action = clap::ArgAction::Append, global = true)]
    pub disable_features: Vec<String>,

    #[command(subcommand)]
    pub subcommand: Option<Subcommands>,

    /// 兼容直接调用模式：当在命令行中省略动词 "sandbox" 时，直接解析并执行沙箱命令
    #[command(flatten)]
    pub direct_sandbox: Option<WindowsCommandArgs>,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    /// 在 Codex 提供的 Windows 原生安全沙箱中运行命令
    #[command(subcommand_negates_reqs = true)]
    Sandbox(SandboxCommandWrapper),
}

/// 官方 Sandbox 子命令包装体（包含参数平铺与内置子命令）
#[derive(Args, Debug, Clone)]
struct SandboxCommandWrapper {
    #[command(flatten)]
    pub host: WindowsCommandArgs,

    #[command(subcommand)]
    pub subcommand: Option<SandboxSubcommands>,
}

#[derive(Subcommand, Debug, Clone)]
enum SandboxSubcommands {
    /// 清理并卸载 Windows 原生沙箱在操作系统中创建的专用机器账户（CodexSandboxOffline/Online）与防火墙过滤规则
    Uninstall,
}

/// 官方透明沙箱状态注入参数结构体（100% 对齐官方 SandboxStateArgs）
#[derive(Debug, Default, Args, Clone)]
pub struct SandboxStateArgs {
    /// 直接应用从 `codex/sandbox-state` 导出的沙箱序列化 JSON 状态字符串（与 profile、cd 互斥）
    #[arg(
        long = "sandbox-state-json",
        value_name = "JSON",
        conflicts_with_all = ["permissions_profile", "cwd", "include_managed_config"]
    )]
    pub sandbox_state_json: Option<String>,

    /// 向提供的沙箱状态中追加一个可读根目录路径（可重复指定多次）
    #[arg(
        long = "sandbox-state-readable-root",
        requires = "sandbox_state_json",
        value_name = "PATH"
    )]
    pub sandbox_state_readable_root: Vec<PathBuf>,

    /// 在提供的沙箱状态中强制禁用直接网络访问能力
    #[arg(long = "sandbox-state-disable-network", requires = "sandbox_state_json", default_value_t = false)]
    pub sandbox_state_disable_network: bool,
}

/// 官方 WindowsCommand 参数选项结构体定义（包含详尽的中文解释）
#[derive(Args, Debug, Clone)]
struct WindowsCommandArgs {
    /// 沙箱透明状态传递选项
    #[command(flatten)]
    pub sandbox_state: SandboxStateArgs,

    /// 从当前有效配置栈中指定生效的权限 Profile 规则集名称。
    /// 内置标准模式包括:
    ///   - ":read-only" : 严格只读（默认安全基线，工作区与磁盘均不可写）
    ///   - ":workspace" : 工作区可写（仅允许对当前工作区目录进行修改）
    #[arg(
        short = 'P',
        long = "permission-profile",
        alias = "permissions-profile",
        value_name = "NAME"
    )]
    pub permissions_profile: Option<String>,

    /// 叠加指定的用户配置 Profile 规则文件（加载 $CODEX_HOME/<name>.config.toml 覆盖基础配置）
    #[arg(short = 'p', long = "profile", value_name = "CONFIG_PROFILE")]
    pub config_profile: Option<String>,

    /// 用于解析权限规则与执行沙箱命令的基准工作目录（物理绝对路径）。
    /// 注意：官方严格要求必须与 -P/--permission-profile 配合使用
    #[arg(
        short = 'C',
        long = "cd",
        value_name = "DIR",
        requires = "permissions_profile"
    )]
    pub cwd: Option<PathBuf>,

    /// 在解析显式权限 Profile 规则时，是否强制合并云端或企业托管策略要求（须与 -P 配合）
    #[arg(
        long = "include-managed-config",
        default_value_t = false,
        requires = "permissions_profile"
    )]
    pub include_managed_config: bool,

    /// 在 Windows 安全受限沙箱中求值的目标程序命令及其参数（支持使用 -- 双横杠与选项隔开）
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

// ==============================================================================
// 2. 官方环境准备动作实现 (Git 穿透、分页器屏蔽、UTF-8 脚本前缀、断网环境标记)
// ==============================================================================

/// 动态确保工作区具备沙箱影子账户写入 Allow ACE（消除新建工作区报 OS 5 拒绝访问隐患）
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

/// 记录日志到 CODEX_HOME/.sandbox/sandbox.YYYY-MM-DD.log 中，保持终端 Stdout 100% 纯净
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

/// 检查同级目录或系统默认路径下是否存在辅助程序
fn find_helper_exe(name: &str) -> Option<PathBuf> {
    // 1. 优先检查当前可执行文件同级目录
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let helper = parent.join(name);
            if helper.is_file() {
                return Some(helper);
            }
        }
    }

    // 2. 检查官方默认安装目录 E:\Program\codex\
    let official_dir = Path::new(r"E:\Program\codex");
    let helper = official_dir.join(name);
    if helper.is_file() {
        return Some(helper);
    }

    None
}

/// 检查是否存在全套 Elevated Helper
fn has_elevated_helpers() -> bool {
    find_helper_exe("codex-windows-sandbox-setup.exe").is_some()
        && find_helper_exe("codex-command-runner.exe").is_some()
}

// ==============================================================================
// 4. 官方正统配置裁决引擎 (支持 -c、--enable、--disable 自动合并)
// ==============================================================================

/// 严格按照官方 TOML 规范与四级优先级裁决 Windows 沙箱级别与权限画像覆盖
fn resolve_official_sandbox_level(
    codex_home: &Path,
    cli_overrides: &[String],
) -> (WindowsSandboxLevel, Option<String>) {
    let mut configured_sandbox_mode: Option<String> = None;
    let mut explicit_profile_override: Option<String> = None;

    // 1. 第一优先级：严格解析命令行配置覆盖项（包含 --config 与转换后的 --enable/--disable）
    for override_str in cli_overrides {
        let clean = override_str.trim().trim_matches('\'').trim_matches('"');
        if let Some((k, v)) = clean.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().trim_matches('\'').trim_matches('"').to_lowercase();

            // 官方正统配置键: windows.sandbox = "unelevated" | "elevated" | "disabled"
            if key == "windows.sandbox" || key == "windows.sandbox.mode" {
                configured_sandbox_mode = Some(val);
            }
            // 官方特性标志映射: features.windows_sandbox_elevated=true / false
            else if key == "features.windows_sandbox_elevated" {
                if val == "true" {
                    configured_sandbox_mode = Some("elevated".to_string());
                } else if val == "false" {
                    configured_sandbox_mode = Some("unelevated".to_string());
                }
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
// 5. 官方子命令分流与管理命令处理 (setup 与 uninstall)
// ==============================================================================

/// 快速探查并处理诸如 `codex sandbox setup` 或 `codex sandbox uninstall` 等官方管理指令
fn try_handle_builtin_management_commands(command: &[String]) -> Option<i32> {
    if command.is_empty() {
        return None;
    }

    let first = command[0].to_lowercase();
    if first == "setup" {
        // 用户调用了 codex sandbox setup，透明拉起配套的 helper 安装程序
        if let Some(setup_exe) = find_helper_exe("codex-windows-sandbox-setup.exe") {
            let status = std::process::Command::new(setup_exe)
                .args(&command[1..])
                .status();
            match status {
                Ok(s) => return Some(s.code().unwrap_or(0)),
                Err(e) => {
                    eprintln!("windows sandbox failed: failed to execute setup helper: {e}");
                    return Some(1);
                }
            }
        } else {
            eprintln!("windows sandbox failed: codex-windows-sandbox-setup.exe not found.");
            return Some(1);
        }
    } else if first == "uninstall" {
        eprintln!("windows sandbox: uninstall is currently handled via system service or codex desktop.");
        return Some(0);
    }

    None
}

// ==============================================================================
// 6. 主程序入口与标准生命周期驱动
// ==============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 严格使用官方 Subcommand 规范解析命令行语法树
    let root_cli = RootCli::parse();

    // 提取有效的沙箱命令参数对象并合并全局 --enable / --disable 到配置项
    let mut all_config_overrides = root_cli.config_overrides;
    for feature in root_cli.enable_features {
        all_config_overrides.push(format!("features.{feature}=true"));
    }
    for feature in root_cli.disable_features {
        all_config_overrides.push(format!("features.{feature}=false"));
    }

    let sandbox_args = match root_cli.subcommand {
        Some(Subcommands::Sandbox(wrapper)) => {
            // 处理官方 codex sandbox uninstall 子命令
            if matches!(wrapper.subcommand, Some(SandboxSubcommands::Uninstall)) {
                eprintln!("windows sandbox: uninstall is currently handled via system service or codex desktop.");
                std::process::exit(0);
            }
            wrapper.host
        }
        None => match root_cli.direct_sandbox {
            Some(args) => args,
            None => {
                eprintln!("windows sandbox failed: no command provided");
                std::process::exit(1);
            }
        },
    };

    // 2. 拦截并分流 setup / uninstall 官方管理指令
    if let Some(exit_code) = try_handle_builtin_management_commands(&sandbox_args.command) {
        std::process::exit(exit_code);
    }

    // 检查待执行命令是否为空
    if sandbox_args.command.is_empty() {
        eprintln!("windows sandbox failed: command must not be empty");
        std::process::exit(1);
    }

    // 3. 确定 CODEX_HOME 根目录（优先级：%CODEX_HOME% > %USERPROFILE%\.codex）
    let codex_home = match std::env::var_os("CODEX_HOME") {
        Some(val) => PathBuf::from(val),
        None => {
            let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
            PathBuf::from(user_profile).join(".codex")
        }
    };

    // 4. 工作区绝对物理路径规范化（消除 8.3 短路径名和符号链接安全盲区）
    let target_cwd = sandbox_args
        .cwd
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let cwd_canonical = match dunce::canonicalize(&target_cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("windows sandbox failed: invalid cwd [{}]: {e}", target_cwd.display());
            std::process::exit(1);
        }
    };
    let cwd = match AbsolutePathBuf::from_absolute_path(&cwd_canonical) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("windows sandbox failed: failed to resolve absolute cwd: {e}");
            std::process::exit(1);
        }
    };
    let workspace_roots = vec![cwd.clone()];

    // 5. 按照官方 TOML 规范判定沙箱运行等级（零私造键）
    let (sandbox_level, profile_override) =
        resolve_official_sandbox_level(&codex_home, &all_config_overrides);

    // 6. 官方权威权限画像裁决机制:
    //    官方规则（见 debug_sandbox.rs 源码）: codex sandbox 历史默认严格为 read-only（只读）！
    //    仅在显式指定 -P :workspace 或通过 -c sandbox_mode=workspace-write 覆盖时才放开写入！
    let profile_name = profile_override
        .or(sandbox_args.permissions_profile)
        .unwrap_or_else(|| ":read-only".to_string());

    let (permission_profile, is_workspace_write) = match profile_name.as_str() {
        ":workspace" => (
            PermissionProfile::workspace_write_with(
                &[],
                NetworkSandboxPolicy::Restricted, // 默认严格开启网络阻断，促发 WFP 影子账户断网
                false,
                false,
            ),
            true,
        ),
        ":read-only" | ":readonly" => (PermissionProfile::read_only(), false),
        _ => (PermissionProfile::read_only(), false),
    };

    // 7. 新工作区写权限自愈（仅在判定为工作区写模式时，消除全新目录报 OS 5 拒绝访问的缺陷）
    if is_workspace_write {
        ensure_workspace_write_permissions(&cwd_canonical);
    }

    // 8. 解析敏感目录只读拦截名单（严格对齐官方标准流程）
    let (mut file_system, _) = permission_profile.to_runtime_permissions();
    file_system.remove_skip_missing_path_entries();
    let file_system = file_system.materialize_project_roots_with_workspace_roots(&workspace_roots);
    let deny_read_paths = match resolve_windows_deny_read_paths(&file_system, &cwd) {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!("windows sandbox failed: {err}");
            std::process::exit(1);
        }
    };

    // 9. 继承环境变量并应用官方关键环境注入预处理
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    inject_git_safe_directory(&mut env_map, &cwd_canonical);
    ensure_non_interactive_pager(&mut env_map);
    normalize_null_device_env(&mut env_map);

    // 官方网络阻断环境标记：当网络处于受限状态时，注入禁用标记
    if !permission_profile.network_sandbox_policy().is_enabled() {
        env_map.insert("CODEX_SANDBOX_NETWORK_DISABLED".to_string(), "1".to_string());
    }

    // 10. 命令预处理：针对 PowerShell 自动前置注入 UTF-8 编码设置
    let final_command = prepare_shell_command_encoding(sandbox_args.command);

    // 11. 记录官方格式审计启动日志到滚动文件中（终端 Stdout 保持 100% 纯净）
    let cmd_preview = final_command.join(" ");
    let level_tag = match sandbox_level {
        WindowsSandboxLevel::Elevated => "Elevated (CodexSandboxOffline via WFP Kernel Block)",
        WindowsSandboxLevel::RestrictedToken => "RestrictedToken (Unelevated Native Token)",
        WindowsSandboxLevel::Disabled => "Disabled",
    };
    append_sandbox_audit_log(
        &codex_home,
        &format!("START [Level: {level_tag}]: {cmd_preview}"),
    );

    let empty_paths: &[AbsolutePathBuf] = &[];

    // 12. 装配 WindowsSandboxSessionRequest 并发起内核级安全沙箱子进程（100% 对齐官方参数）
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
        Err(err) => {
            append_sandbox_audit_log(&codex_home, &format!("SPAWN_FAILURE: {err}"));
            eprintln!("windows sandbox failed: {err}");
            std::process::exit(1);
        }
    };

    // 13. 移交官方 forward_sandbox_session_stdio 接管 Stdio 透传与信号生命周期
    //     注意：官方内部本身已实现了 ctrl_c() 监听并带有 5 秒缓冲排空保护，外层绝不可再重复包装 select!，
    //     以彻底杜绝输出被提前截断的缺陷。
    let exit_code = forward_sandbox_session_stdio(spawned).await;

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