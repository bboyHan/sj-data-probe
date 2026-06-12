using System.Net;
using System.Net.Sockets;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// TUN 虚拟网卡通道 — 通过 WinTUN 驱动创建虚拟网卡，捕获 L3 全流量。
/// 支持 TCP/UDP/ICMP，弥补 WinDivert 仅支持 TCP 的局限。
///
/// 技术原理：
///   WinTUN (WireGuard 项目) 创建虚拟网卡接口
///   系统路由将流量指向 TUN 接口
///   用户态读取 IP 包 → 分类 → TCP/UDP 分流
///
/// 覆盖场景：
///   - UDP 流量（QUIC/DoQ/游戏/视频通话）
///   - 不走系统代理的原生 App
///   - 非 443 端口的 TCP 流量
///   - 跨平台（Windows/Linux/macOS 均有 TUN 实现）
/// </summary>
public class TunChannel : ICaptureChannel
{
    private CancellationTokenSource? _cts;
    private Task? _readTask;
    private bool _isRunning;

    public string Name => "TUN";
    public string Description => "TUN 虚拟网卡 — L3 全流量捕获（UDP + TCP + ICMP）";

    public ChannelCapability Capability => new()
    {
        Layer = CaptureLayer.L3,
        RequiresAdmin = true,
        RequiresCertInstall = false,
        CanIntercept = true,
        CanDecryptTls = false,
        CanModify = false,
        CanInject = false,
        SupportedProtocols = new[] { "TCP", "UDP", "ICMP", "QUIC" },
        SupportedPlatforms = new[] { "windows", "linux", "macos" },
        TargetScenarios = new[] { "app", "game", "mobile" },
        AntiCheatConflicts = Array.Empty<string>(),
        Limitations = new[]
        {
            "需要管理员权限创建虚拟网卡",
            "不解密 TLS（需配合 TlsProxy）",
            "用户态读取 IP 包有额外 CPU 开销"
        },
        ScopeDescription = "TUN 虚拟网卡 — 全流量 L3 捕获"
    };

    public bool IsHealthy => _isRunning;

    public event Action<RawPacket>? OnPacket;

    /// <summary>TUN 网卡名称</summary>
    public string InterfaceName { get; set; } = "dataprobe_tun";

    /// <summary>TUN 网卡 IP 地址</summary>
    public string InterfaceAddress { get; set; } = "10.0.8.1";

    /// <summary>TUN 网卡子网掩码</summary>
    public string InterfaceNetmask { get; set; } = "255.255.255.0";

    /// <summary>TlsProxy 地址（TCP/443 流量转发目标）</summary>
    public string TlsProxyAddress { get; set; } = "127.0.0.1";

    /// <summary>TlsProxy 端口</summary>
    public int TlsProxyPort { get; set; } = 18802;

    public Task<bool> InitializeAsync()
    {
        Console.Error.WriteLine("[TUN] Initialized");
        return Task.FromResult(true);
    }

    public Task StartAsync()
    {
        if (_isRunning) return Task.CompletedTask;

        _cts = new CancellationTokenSource();
        _isRunning = true;

        // TUN 通道启动分为两步：
        // 1. 安装/打开 TUN 接口（需要 WinTUN 驱动）
        // 2. 启动 IP 包读取循环（用户态读取原始 IP 包）
        _readTask = Task.Run(() => PacketReadLoop(_cts.Token));

        Console.Error.WriteLine($"[TUN] Started (addr={InterfaceAddress}, tls_proxy={TlsProxyAddress}:{TlsProxyPort})");
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;

        _cts?.Cancel();
        _isRunning = false;
        Console.Error.WriteLine("[TUN] Stopped");
        return Task.CompletedTask;
    }

    /// <summary>
    /// IP 包读取循环（骨架 — 完整实现在 Phase 6 中由 WinTUN P/Invoke 驱动）
    /// </summary>
    private async Task PacketReadLoop(CancellationToken ct)
    {
        // Phase 6 完整实现：
        // 1. WinTUN P/Invoke: wintun_open() → 获取 TUN 会话句柄
        // 2. 循环: wintun_read() → 获取原始 IP 包
        // 3. IP 包分类器判断协议类型
        //    ├─ TCP/443 → 重写目标地址为 TlsProxy → TUN 写出
        //    ├─ TCP/80  → 解析 HTTP → 提取
        //    ├─ UDP/443 → QUIC 检测 → SNI 提取
        //    ├─ UDP/53  → DNS 劫持
        //    └─ 其他    → RawPacket 输出
        // 4. 非目标流量 → 直接路由到真实网关

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(100, ct); // 占位：等待真实实现
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// IP 包分类器 — 判断协议类型并决定处理方式
    /// </summary>
    public static PacketClassifyResult ClassifyPacket(byte[] ipPacket, int length)
    {
        if (length < 20) return new PacketClassifyResult { Action = PacketAction.Pass };

        // IPv4 版本检测 (version 4 = 0x45-0x4F)
        int version = (ipPacket[0] >> 4) & 0x0F;
        if (version != 4) return new PacketClassifyResult { Action = PacketAction.Pass };

        int headerLen = (ipPacket[0] & 0x0F) * 4;
        if (headerLen < 20 || headerLen > length) return new PacketClassifyResult { Action = PacketAction.Pass };

        byte protocol = ipPacket[9]; // Protocol field
        int totalLen = (ipPacket[2] << 8) | ipPacket[3];
        if (totalLen > length) totalLen = length;

        var destIp = new IPAddress(ipPacket[headerLen..(headerLen + 4)]);
        int destPort = 0;

        if (protocol == 6) // TCP
        {
            if (headerLen + 2 <= length)
                destPort = (ipPacket[headerLen + 2] << 8) | ipPacket[headerLen + 3];
        }
        else if (protocol == 17) // UDP
        {
            if (headerLen + 2 <= length)
                destPort = (ipPacket[headerLen] << 8) | ipPacket[headerLen + 1];
        }

        return new PacketClassifyResult
        {
            Action = ClassifyAction(protocol, destPort),
            Protocol = protocol,
            DestPort = destPort,
            DestAddress = destIp
        };
    }

    private static PacketAction ClassifyAction(byte protocol, int destPort)
    {
        return protocol switch
        {
            6 when destPort == 443 => PacketAction.RedirectTls,    // TCP/443 → TLS Proxy
            6 when destPort == 80 => PacketAction.ParseHttp,       // TCP/80 → HTTP 解析
            17 when destPort == 443 => PacketAction.QuicDetect,    // UDP/443 → QUIC 检测
            17 when destPort == 53 => PacketAction.DnsIntercept,   // UDP/53 → DNS 劫持
            _ => PacketAction.Pass                                 // 其他 → 直通
        };
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }
}

/// <summary>
/// IP 包分类结果
/// </summary>
public class PacketClassifyResult
{
    public PacketAction Action { get; set; }
    public byte Protocol { get; set; }
    public int DestPort { get; set; }
    public IPAddress? DestAddress { get; set; }
}

/// <summary>
/// IP 包处理动作
/// </summary>
public enum PacketAction
{
    Pass,           // 直通（不拦截）
    RedirectTls,    // 重定向到 TLS Proxy
    ParseHttp,      // 解析 HTTP
    QuicDetect,     // QUIC 检测 + SNI 提取
    DnsIntercept    // DNS 劫持
}
