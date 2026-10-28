// ==============================================================================
// 文件路径: codex-rs/codex-mini-sandbox/src/main.rs
// 功能描述: 独立轻量级 Windows 原生受限令牌沙箱主入口 (Codex Native Sandbox Runner)
// 技术实现:
//   1. 物理绝对路径规范化 (dunce::canonicalize) 根治 8.3 短路径与软链接穿越；
//   2. 权限画像锁定 (PermissionProfile::workspace_write) 锚定工作区边界；
//   3. 敏感路径只读拦截 (resolve_windows_deny_read_paths) 屏蔽核心文件扫描；
//   4. 操作系统受限令牌启动 (spawn_windows_sandbox_session_for_level) 激活限制令牌与 Job 对象；
//   5. 状态码无损穿透 (forward_sandbox_session_stdio) 真实回传执行器退出状态。
// ==============================================================================

use std::collections::HashMap;
use std::path::PathBuf;
use clap::Parser;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::{
    forward_sandbox_session_stdio,
    resolve_windows_deny_read_paths,
    spawn_windows_sandbox_session_for_level,
    WindowsSandboxProxySettingsMode,
    WindowsSandboxSessionRequest,
};

/// 命令行参数结构体定义：完美兼容官方 `codex sandbox` 与独立直接调用
#[derive(Parser, Debug)]
#[command(
    name = "codex-mini-sandbox",
    about = "Codex Official Windows Restricted Token Native Sandbox Runner (Ultra-fast & Lightweight)",
    trailing_var_arg = true
)]
struct Cli {
    /// 兼容语法槽：允许无损接收可能由上层调用传过来的 "sandbox" 子命令（如果有则消费，没有也不报错）
    #[arg(value_parser = ["sandbox"])]
    _dummy_subcmd: Option<String>,

    /// 权限配置文件画像名称（默认使用官方标准 ":workspace" 画像）
    #[arg(short = 'P', long = "permission-profile", default_value = ":workspace")]
    permission_profile: String,

    /// 绑定的工作区绝对路径（工作区内部完全控制，工作区外部强制只读）
    #[arg(short = 'C', long = "cd")]
    cwd: PathBuf,

    /// 双横杠 `--` 之后被沙箱执行的真实目标命令及其全部参数列表
    #[arg(required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 解析输入的命令行参数
    let cli = Cli::parse();

    // 健壮性检查：若未传入任何待求值的有效命令，立即阻断退出
    if cli.command.is_empty() {
        eprintln!("[codex-mini-sandbox] 错误: 未能在命令行参数中检测到待执行的有效目标程序！");
        std::process::exit(1);
    }

    // 2. 对工作区路径执行工业级物理规范化（展开软链接、解析相对路径、消除 8.3 短路径别名）
    let cwd_canonical = dunce::canonicalize(&cli.cwd).map_err(|e| {
        anyhow::anyhow!(
            "[codex-mini-sandbox] 目标工作区目录无法访问或物理不存在 [{}]: {e}",
            cli.cwd.display()
        )
    })?;
    let cwd = AbsolutePathBuf::from_absolute_path(&cwd_canonical)?;
    let workspace_roots = vec![cwd.clone()];

    // 3. 严格遵循官方对 CODEX_HOME 的解析优先级（用于存放 Capability SID 凭据与安全日志）
    let codex_home = match std::env::var_os("CODEX_HOME") {
        Some(val) => PathBuf::from(val),
        None => {
            let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
            PathBuf::from(user_profile).join(".codex")
        }
    };

    // 4. 解析并装配官方权限配置文件画像
    //    `:workspace` 画像赋予沙箱对当前绑定的根目录写权限，其余磁盘全域只读；
    //    内部会自动通过 DACL 挂载 Deny-Write ACE 保护工作区内的 `.git`, `.codex` 等关键系统目录
    let permission_profile = match cli.permission_profile.as_str() {
        ":workspace" => PermissionProfile::workspace_write(),
        ":read-only" | ":readonly" => PermissionProfile::read_only(),
        _ => PermissionProfile::workspace_write(),
    };

    // 5. 探查并解析 Windows 平台下的系统敏感只读拦截路径列表（例如系统核心配置、SSH 密钥等）
    let (mut file_system, _) = permission_profile.to_runtime_permissions();
    file_system.remove_skip_missing_path_entries();
    let file_system = file_system.materialize_project_roots_with_workspace_roots(&workspace_roots);
    let deny_read_paths = resolve_windows_deny_read_paths(&file_system, &cwd).unwrap_or_default();

    // 6. 继承父进程当前上下文的环境变量表
    let env_map: HashMap<String, String> = std::env::vars().collect();
    let empty_paths: &[AbsolutePathBuf] = &[];

    // 7. 调用 Windows 限制令牌沙箱核心引擎发起进程装配
    //    底层将执行：
    //      - CreateRestrictedToken（移除管理员组，启用 LUA 限制令牌）；
    //      - 注入唯一工作区 Capability SID；
    //      - 在工作区根目录追加 Capability SID 允许写 ACE；
    //      - 绑定 JobObject 限制子进程资源逃逸。
    let spawned = spawn_windows_sandbox_session_for_level(WindowsSandboxSessionRequest {
        permission_profile: &permission_profile,
        workspace_roots: workspace_roots.as_slice(),
        codex_home: codex_home.as_path(),
        command: cli.command,
        cwd: cwd.as_path(),
        env_map,
        windows_sandbox_level: WindowsSandboxLevel::RestrictedToken,
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
    .await
    .map_err(|e| anyhow::anyhow!("[codex-mini-sandbox] 内核级安全沙箱子进程派发启动失败: {e}"))?;

    // 8. 实时流式转发标准输入输出（Stdio），并无损提取、传递子进程的最终退出码
    let exit_code = forward_sandbox_session_stdio(spawned).await;
    std::process::exit(exit_code);
}