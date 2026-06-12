namespace DataProbe.Core;

/// <summary>
/// 通道能力声明 — 描述一个采集通道能做什么、不能做什么。
/// ADE 根据此信息自动选择通道组合。
/// </summary>
public class ChannelCapability
{
    /// <summary>操作层级</summary>
    public CaptureLayer Layer { get; set; } = CaptureLayer.L7;

    // ── 权限需求 ──

    /// <summary>是否需要管理员权限</summary>
    public bool RequiresAdmin { get; set; }

    /// <summary>是否需要安装 CA 证书</summary>
    public bool RequiresCertInstall { get; set; }

    /// <summary>是否需要 root（移动端）</summary>
    public bool RequiresRoot { get; set; }

    // ── 能力声明 ──

    /// <summary>能否拦截流量</summary>
    public bool CanIntercept { get; set; }

    /// <summary>能否解密 TLS</summary>
    public bool CanDecryptTls { get; set; }

    /// <summary>能否修改流量</summary>
    public bool CanModify { get; set; }

    /// <summary>能否注入进程</summary>
    public bool CanInject { get; set; }

    // ── 覆盖范围 ──

    /// <summary>支持的协议</summary>
    public string[] SupportedProtocols { get; set; } = Array.Empty<string>();

    /// <summary>支持的平台</summary>
    public string[] SupportedPlatforms { get; set; } = Array.Empty<string>();  // windows / android / ios

    /// <summary>适用场景</summary>
    public string[] TargetScenarios { get; set; } = Array.Empty<string>();  // browser / app / game / miniapp

    // ── 限制 ──

    /// <summary>与此通道冲突的反作弊系统</summary>
    public string[] AntiCheatConflicts { get; set; } = Array.Empty<string>();

    /// <summary>其他限制说明</summary>
    public string[] Limitations { get; set; } = Array.Empty<string>();

    /// <summary>人类可读的作用范围描述</summary>
    public string ScopeDescription { get; set; } = "";
}

/// <summary>
/// 原始数据包 — Channel 产出的统一格式。
/// 后续由协议解析层处理为 HttpTransaction。
/// </summary>
public class RawPacket
{
    /// <summary>原始字节</summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>来源通道名称</summary>
    public string SourceChannel { get; set; } = "";

    /// <summary>捕获时间</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>包元数据</summary>
    public PacketMetadata Metadata { get; set; } = new();
}

/// <summary>
/// 包元数据
/// </summary>
public class PacketMetadata
{
    public string? Sni { get; set; }
    public int SourcePort { get; set; }
    public int DestPort { get; set; }
    public string? SourceAddress { get; set; }
    public string? DestAddress { get; set; }
    public int ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? Protocol { get; set; }
}

/// <summary>
/// 标准化事务 — 协议层解析后输出的统一格式。
/// 此为内部流转格式，最终被聚合为 HttpTransaction。
/// </summary>
public class NormalizedTransaction
{
    public string Domain { get; set; } = "";
    public string Method { get; set; } = "";
    public string Path { get; set; } = "";
    public string QueryString { get; set; } = "";
    public string Url { get; set; } = "";
    public int StatusCode { get; set; }
    public string RequestBody { get; set; } = "";
    public string ResponseBody { get; set; } = "";
    public string? ResponseBodyBase64 { get; set; }
    public Dictionary<string, string> RequestHeaders { get; set; } = new();
    public Dictionary<string, string> ResponseHeaders { get; set; } = new();
    public DateTime CapturedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// 采集通道接口 — 每种数据采集方式实现一个 Channel。
/// 实现此接口即可被 ChannelManager 注册和管理。
/// 这是系统的 SPI（Service Provider Interface），所有通道可插拔。
/// </summary>
public interface ICaptureChannel
{
    /// <summary>通道唯一标识，如 "WinDivert"、"DnsSpoof"</summary>
    string Name { get; }

    /// <summary>人类可读的描述</summary>
    string Description { get; }

    /// <summary>通道能力声明 — ADE 据此选择通道</summary>
    ChannelCapability Capability { get; }

    /// <summary>初始化（安装驱动、分配资源等）。返回 true 表示成功。</summary>
    Task<bool> InitializeAsync();

    /// <summary>开始采集</summary>
    Task StartAsync();

    /// <summary>停止采集</summary>
    Task StopAsync();

    /// <summary>健康检查 — 返回 true 表示通道正常运行</summary>
    bool IsHealthy { get; }

    /// <summary>采集到的原始数据事件</summary>
    event Action<RawPacket>? OnPacket;
}

/// <summary>
/// TCP 连接标识（四元组）
/// </summary>
public readonly struct ConnectionKey : IEquatable<ConnectionKey>
{
    public uint SrcAddr { get; }
    public ushort SrcPort { get; }
    public uint DstAddr { get; }
    public ushort DstPort { get; }

    public ConnectionKey(uint srcAddr, ushort srcPort, uint dstAddr, ushort dstPort)
    {
        SrcAddr = srcAddr; SrcPort = srcPort; DstAddr = dstAddr; DstPort = dstPort;
    }

    public override string ToString() => $"{SrcAddr}:{SrcPort}→{DstAddr}:{DstPort}";
    public bool Equals(ConnectionKey other) => SrcAddr == other.SrcAddr && SrcPort == other.SrcPort && DstAddr == other.DstAddr && DstPort == other.DstPort;
    public override bool Equals(object? obj) => obj is ConnectionKey other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(SrcAddr, SrcPort, DstAddr, DstPort);
    public static bool operator ==(ConnectionKey left, ConnectionKey right) => left.Equals(right);
    public static bool operator !=(ConnectionKey left, ConnectionKey right) => !left.Equals(right);
}
