using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// TUN 虚拟网卡通道 — 通过 WinTUN 驱动捕获 L3 全流量。
/// WinTUN 是 WireGuard 项目开源的虚拟网卡驱动，轻量、高性能。
///
/// 设计：
///   1. wintun.dll 创建虚拟网卡接口
///   2. IP 包到达 TUN → PacketClassify 分类
///   3. TCP/443 → 重写目标地址到 TlsProxy
///   4. UDP/443 → QUIC 检测
///   5. UDP/53 → DNS 劫持
///   6. 其他 → 直通
/// </summary>
public class TunChannel : ICaptureChannel
{
    // ── WinTUN P/Invoke ──

    private const string WinTunDll = "wintun.dll";

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WintunOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WintunStartSession(nint adapter, int capacity);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WintunReceivePacket(nint session, out int size);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunReleaseReceive(nint session, nint packet);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WintunAllocateSendPacket(nint session, int size);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunSendPacket(nint session, nint packet);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void WintunCloseAdapter(nint adapter);

    [DllImport(WinTunDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.LPWStr)]
    private static extern string WintunGetLastError(nint adapter);

    // ── 成员 ──

    private nint _adapter;
    private nint _session;
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
        CanModify = true,
        CanInject = false,
        SupportedProtocols = new[] { "TCP", "UDP", "ICMP", "QUIC" },
        SupportedPlatforms = new[] { "windows" },
        TargetScenarios = new[] { "app", "game", "mobile" },
        Limitations = new[]
        {
            "需要管理员权限 + WinTUN 驱动",
            "不解密 TLS（需配合 TlsProxy）",
            "用户态读取有额外 CPU 开销"
        },
        ScopeDescription = "TUN 虚拟网卡 — L3 全流量"
    };

    public bool IsHealthy => _isRunning;
    public event Action<RawPacket>? OnPacket;

    /// <summary>TlsProxy 目标地址</summary>
    public string TlsProxyAddress { get; set; } = "127.0.0.1";
    public int TlsProxyPort { get; set; } = 18802;

    /// <summary>目标域名列表（仅这些域名的流量会被深度处理）</summary>
    public string[] TargetDomains { get; set; } = Array.Empty<string>();

    /// <summary>发包计数器</summary>
    public long PacketsRead => Interlocked.Read(ref _packetsRead);
    public long PacketsClassified => Interlocked.Read(ref _packetsClassified);
    private long _packetsRead;
    private long _packetsClassified;

    public Task<bool> InitializeAsync()
    {
        Console.Error.WriteLine("[TUN] Initialized");
        return Task.FromResult(true);
    }

    public Task StartAsync()
    {
        if (_isRunning) return Task.CompletedTask;

        _cts = new CancellationTokenSource();

        try
        {
            // 1) 打开 WinTUN 适配器
            _adapter = WintunOpen("DataProbeTun");
            if (_adapter == nint.Zero)
            {
                Console.Error.WriteLine("[TUN] Failed to open adapter (run as admin)");
                return Task.CompletedTask;
            }

            // 2) 创建会话
            _session = WintunStartSession(_adapter, 0x100000); // 1MB ring buffer
            if (_session == nint.Zero)
            {
                Console.Error.WriteLine("[TUN] Failed to start session");
                WintunCloseAdapter(_adapter);
                return Task.CompletedTask;
            }

            // 3) 启动读取循环
            _isRunning = true;
            _readTask = Task.Run(() => PacketReadLoop(_cts.Token));

            Console.Error.WriteLine($"[TUN] Started (proxy={TlsProxyAddress}:{TlsProxyPort})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TUN] Start failed: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;

        _cts?.Cancel();
        _isRunning = false;

        if (_session != nint.Zero)
        {
            // 释放 session（WinTUN 会在 CloseAdapter 时自动清理）
            _session = nint.Zero;
        }

        if (_adapter != nint.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = nint.Zero;
        }

        Console.Error.WriteLine("[TUN] Stopped");
        return Task.CompletedTask;
    }

    /// <summary>
    /// IP 包读取循环 — 从 TUN 读取原始 IP 包，分类处理
    /// </summary>
    private async Task PacketReadLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _session != nint.Zero)
            {
                // 1) 从 TUN 读取原始 IP 包
                var packet = WintunReceivePacket(_session, out int size);
                if (packet == nint.Zero || size < 20)
                {
                    await Task.Delay(1, ct); // 无包时短暂休眠
                    continue;
                }

                Interlocked.Increment(ref _packetsRead);

                // 2) 复制到托管数组
                var ipPacket = new byte[size];
                Marshal.Copy(packet, ipPacket, 0, size);
                WintunReleaseReceive(_session, packet);

                // 3) 分类
                var classification = ClassifyPacket(ipPacket, size);
                if (classification.Action == PacketAction.Pass)
                    continue; // 非目标流量，直接放行（不在 TUN 中处理）

                Interlocked.Increment(ref _packetsClassified);

                // 4) 按分类处理
                switch (classification.Action)
                {
                    case PacketAction.RedirectTls:
                        RedirectToTlsProxy(ipPacket, size);
                        break;

                    case PacketAction.DnsIntercept:
                        HandleDnsIntercept(ipPacket, size);
                        break;

                    case PacketAction.QuicDetect:
                        ExtractQuicSni(ipPacket, size);
                        break;

                    default:
                        // 输出 RawPacket 供其他通道处理
                        OnPacket?.Invoke(new RawPacket
                        {
                            Data = ipPacket,
                            SourceChannel = Name,
                            Timestamp = DateTime.UtcNow,
                            Metadata = new PacketMetadata
                            {
                                DestPort = classification.DestPort,
                                DestAddress = classification.DestAddress?.ToString(),
                                Protocol = classification.Protocol == 6 ? "TCP" :
                                           classification.Protocol == 17 ? "UDP" : "Other"
                            }
                        });
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TUN] Loop error: {ex.Message}");
        }
    }

    /// <summary>
    /// 重写 IP 包目标地址到 TlsProxy（内核旁路）
    /// </summary>
    private void RedirectToTlsProxy(byte[] ipPacket, int length)
    {
        try
        {
            if (length < 40) return;

            // 修改目标 IP 为 127.0.0.1
            var proxyBytes = new IPEndPoint(IPAddress.Parse(TlsProxyAddress), 0).Address.GetAddressBytes();
            // IPv4 目标地址在偏移 16-19
            Buffer.BlockCopy(proxyBytes, 0, ipPacket, 16, 4);

            // 修改目标端口（TCP 头偏移 = IP 头长度，源端口在偏移 0, 目标端口在 2）
            int ipHeaderLen = (ipPacket[0] & 0x0F) * 4;
            ipPacket[ipHeaderLen + 2] = (byte)(TlsProxyPort >> 8);
            ipPacket[ipHeaderLen + 3] = (byte)(TlsProxyPort & 0xFF);

            // 重新计算 IP 校验和
            UpdateChecksum(ipPacket, length);

            // 写回 TUN
            var sendPacket = WintunAllocateSendPacket(_session, length);
            if (sendPacket != nint.Zero)
            {
                Marshal.Copy(ipPacket, 0, sendPacket, length);
                WintunSendPacket(_session, sendPacket);
            }
        }
        catch { }
    }

    private static void HandleDnsIntercept(byte[] ipPacket, int length)
    {
        // DNS 劫持由 DnsSpoofChannel 处理，此处仅输出事件
        // TUN 中检测到 DNS 查询时转发事件
    }

    private static void ExtractQuicSni(byte[] ipPacket, int length)
    {
        // QUIC Initial Packet 中的 TLS ClientHello 包含 SNI
        // 在后续 Phase 中实现完整 QUIC 检测
    }

    /// <summary>简单 IP 校验和计算</summary>
    private static void UpdateChecksum(byte[] ipPacket, int length)
    {
        if (length < 20) return;

        // 清零原校验和
        ipPacket[10] = 0;
        ipPacket[11] = 0;

        int headerLen = (ipPacket[0] & 0x0F) * 4;
        long sum = 0;
        for (int i = 0; i < headerLen; i += 2)
        {
            if (i + 1 < length)
                sum += (ipPacket[i] << 8) | ipPacket[i + 1];
        }

        while (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);

        ipPacket[10] = (byte)(~sum >> 8);
        ipPacket[11] = (byte)(~sum & 0xFF);
    }

    // ── IP 包分类 ──

    public static PacketClassifyResult ClassifyPacket(byte[] ipPacket, int length)
    {
        if (length < 20) return new PacketClassifyResult { Action = PacketAction.Pass };

        int version = (ipPacket[0] >> 4) & 0x0F;
        if (version != 4) return new PacketClassifyResult { Action = PacketAction.Pass };

        int headerLen = (ipPacket[0] & 0x0F) * 4;
        if (headerLen < 20 || headerLen > length)
            return new PacketClassifyResult { Action = PacketAction.Pass };

        byte protocol = ipPacket[9];

        var destAddr = new IPAddress(ipPacket[16..20]);
        int destPort = 0;

        if (protocol == 6 && headerLen + 4 <= length) // TCP
            destPort = (ipPacket[headerLen + 2] << 8) | ipPacket[headerLen + 3];
        else if (protocol == 17 && headerLen + 2 <= length) // UDP
            destPort = (ipPacket[headerLen] << 8) | ipPacket[headerLen + 1];

        // 127.0.0.1 回环流量跳过
        if (destAddr.Equals(IPAddress.Loopback))
            return new PacketClassifyResult { Action = PacketAction.Pass };

        return new PacketClassifyResult
        {
            Action = ClassifyAction(protocol, destPort),
            Protocol = protocol,
            DestPort = destPort,
            DestAddress = destAddr
        };
    }

    private static PacketAction ClassifyAction(byte protocol, int port)
    {
        return protocol switch
        {
            6 when port == 443 => PacketAction.RedirectTls,
            6 when port == 80 => PacketAction.Pass,       // HTTP 暂不处理
            17 when port == 53 => PacketAction.DnsIntercept,
            17 when port == 443 => PacketAction.QuicDetect,
            _ => PacketAction.Pass
        };
    }

    public void Dispose() => StopAsync().GetAwaiter().GetResult();
}

public class PacketClassifyResult
{
    public PacketAction Action { get; set; }
    public byte Protocol { get; set; }
    public int DestPort { get; set; }
    public IPAddress? DestAddress { get; set; }
}

public enum PacketAction { Pass, RedirectTls, DnsIntercept, QuicDetect }
