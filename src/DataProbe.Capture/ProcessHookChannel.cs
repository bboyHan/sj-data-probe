using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 进程 Hook 通道 — 通过 DLL 注入目标进程，Hook SSL 函数调用，
/// 在加密发生前直接获取明文数据。
///
/// 这是突破证书锁定的关键技术。原理：
///   目标进程调用 SSL_write("POST /api/data...") →
///   Hook 拦截明文参数 → 通过 IPC 回传 DataProbe →
///   原始 SSL_write 继续执行（目标进程无感知）
///
/// 支持的 SSL 库：
///   - OpenSSL 1.1.x / 3.x    → Hook SSL_write/SSL_read
///   - BoringSSL (Chrome)      → Hook CRYPTO_get_ex_data
///   - Schannel (Windows)      → 不需要 Hook（已有 TlsProxy）
///   - NSS (Firefox)           → Hook PR_Write/PR_Read
///   - .NET SslStream          → .NET Profiler（Phase 4 后续）
///
/// 架构：
///   ProcessHookChannel (C#)    ← 管理端
///       │
///       ├─ Injector: CreateRemoteThread → LoadLibrary(hook.dll)
///       │
///       ├─ hook.dll (C/C++)   ← 目标进程内运行
///       │   ├─ MinHook 拦截 SSL_write/SSL_read
///       │   └─ NamedPipe IPC 回传数据
///       │
///       └─ SessionBuilder → 数据进入 SessionSnapshot
/// </summary>
public class ProcessHookChannel : ICaptureChannel
{
    private bool _isInitialized;
    private bool _isRunning;
    private string? _targetProcessName;

    /// <summary>Hook 管道数据接收事件（用于桥接 SessionBuilder）</summary>
    public event Action<NormalizedTransaction>? OnTransactionCaptured;

    public string Name => "ProcessHook";
    public string Description => "进程注入 Hook — 突破证书锁定，在加密前获取明文";

    public ChannelCapability Capability => new()
    {
        Layer = CaptureLayer.Process,
        RequiresAdmin = false,
        RequiresCertInstall = false,
        CanIntercept = true,
        CanDecryptTls = true,
        CanModify = false,
        CanInject = true,
        SupportedProtocols = new[] { "HTTPS", "HTTP", "TCP" },
        SupportedPlatforms = new[] { "windows" },
        TargetScenarios = new[] { "app", "game" },
        AntiCheatConflicts = new[] { "ace", "tensafe", "eac", "battleye" },
        Limitations = new[]
        {
            "可能被反作弊系统检测",
            "需要目标进程使用 OpenSSL/BoringSSL/NSS",
            "32/64 位 DLL 需分别编译",
            "部分杀软会拦截 DLL 注入"
        },
        ScopeDescription = "进程内 SSL Hook — 绕过证书锁定，获取应用层明文"
    };

    public bool IsHealthy => _isRunning;

    public event Action<RawPacket>? OnPacket;

    /// <summary>目标进程名称（不含 .exe）</summary>
    public string? TargetProcessName
    {
        get => _targetProcessName;
        set => _targetProcessName = value;
    }

    /// <summary>Hook DLL 完整路径</summary>
    public string HookDllPath { get; set; } = "";

    /// <summary>IPC 管道名称</summary>
    public string PipeName { get; set; } = "DataProbeHookPipe";

    public Task<bool> InitializeAsync()
    {
        _isInitialized = true;
        Console.Error.WriteLine("[ProcessHookChannel] Initialized");
        return Task.FromResult(true);
    }

    public Task StartAsync()
    {
        if (_isRunning) return Task.CompletedTask;

        if (string.IsNullOrEmpty(_targetProcessName))
        {
            Console.Error.WriteLine("[ProcessHookChannel] No target process specified");
            return Task.CompletedTask;
        }

        try
        {
            // Phase 4 完整实现：
            // 1. 查找目标进程 (Process.GetProcessesByName)
            // 2. 检测进程位数 (32/64)
            // 3. 选择对应架构的 hook.dll
            // 4. CreateRemoteThread → LoadLibrary(hook.dll)
            // 5. hook.dll 内部:
            //    a. MinHook 初始化
            //    b. 扫描导入表定位 SSL_write/SSL_read
            //    c. Hook 安装
            //    d. 建立 NamedPipe 连接
            // 6. 开始接收 IPC 数据

            StartHookSession();
            _isRunning = true;
            Console.Error.WriteLine($"[ProcessHookChannel] Hook started on {_targetProcessName}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ProcessHookChannel] Start failed: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;

        try
        {
            // Phase 4 完整实现：
            // 1. 发送 IPC 关闭信号到 hook.dll
            // 2. 等待 hook.dll 卸载 (FreeLibrary)
            // 3. 关闭管道连接
            StopHookSession();
            _isRunning = false;
            Console.Error.WriteLine("[ProcessHookChannel] Stopped");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ProcessHookChannel] Stop error: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// 设置目标进程并自动检测其 SSL 库
    /// </summary>
    public bool SetTarget(string processName)
    {
        _targetProcessName = processName;

        // 查找目标进程
        var processes = System.Diagnostics.Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            Console.Error.WriteLine($"[ProcessHookChannel] Process '{processName}' not found");
            return false;
        }

        var process = processes[0];
        bool is64Bit = false;

        try
        {
            is64Bit = !process.Modules.Cast<System.Diagnostics.ProcessModule>()
                .Any(m => m.ModuleName?.Contains("wow64") == true);
        }
        catch { }

        // 选择 Hook DLL
        var arch = is64Bit ? "x64" : "x86";
        HookDllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "hooks", arch, "hook.dll");

        Console.Error.WriteLine($"[ProcessHookChannel] Target: {processName} ({arch})");
        return true;
    }

    /// <summary>Hook session 骨架 — Phase 4 实现</summary>
    private void StartHookSession()
    {
        // 1. 创建 NamedPipe 服务端监听
        // 2. 注入 hook.dll 到目标进程
        // 3. 等待 hook.dll 连接管道
        // 4. 开始异步读取 IPC 数据
        // 5. IPC 数据 → NormalizedTransaction → OnTransactionCaptured
    }

    /// <summary>Hook session 停止 — Phase 4 实现</summary>
    private void StopHookSession()
    {
        // 1. 发送关闭命令到管道
        // 2. 关闭管道
        // 3. 清理资源
    }

    /// <summary>
    /// 检测目标进程的反作弊状态（Phase 4 实现）
    /// </summary>
    public static AntiCheatStatus DetectAntiCheat(string processName)
    {
        // 扫描进程模块 → 匹配已知反作弊
        try
        {
            var process = System.Diagnostics.Process.GetProcessesByName(processName).FirstOrDefault();
            if (process == null) return AntiCheatStatus.NotDetected;

            foreach (System.Diagnostics.ProcessModule module in process.Modules)
            {
                var name = module.ModuleName?.ToLower() ?? "";
                if (name.Contains("ace") || name.Contains("aceguard"))
                    return AntiCheatStatus.AceDetected;
                if (name.Contains("tensafe") || name.Contains("tenprotect"))
                    return AntiCheatStatus.TenSafeDetected;
                if (name.Contains("eac") || name.Contains("easyanticheat"))
                    return AntiCheatStatus.EacDetected;
                if (name.Contains("battleye") || name.Contains("beservice"))
                    return AntiCheatStatus.BattlEyeDetected;
                if (name.Contains("mhyprot") || name.Contains("mhyp"))
                    return AntiCheatStatus.MiHoYoDetected;
            }
        }
        catch { }

        return AntiCheatStatus.NotDetected;
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }
}

/// <summary>反作弊检测状态</summary>
public enum AntiCheatStatus
{
    NotDetected,
    AceDetected,        // Tencent ACE
    TenSafeDetected,    // Tencent TenSafe
    EacDetected,        // EasyAntiCheat
    BattlEyeDetected,   // BattlEye
    MiHoYoDetected,     // miHoYo Protect
    Unknown
}
