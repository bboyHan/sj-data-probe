namespace DataProbe.Core;

/// <summary>
/// 通道能力声明 — 描述一个采集通道能做什么。
/// </summary>
public class ChannelCapability
{
    public bool RequiresAdmin { get; set; }
    public bool CanDecryptTls { get; set; }
    public string[] SupportedProtocols { get; set; } = Array.Empty<string>();
    public bool RequiresCertInstall { get; set; }
    public string ScopeDescription { get; set; } = "";
}

/// <summary>
/// 原始数据包 — Channel 产出的统一格式。
/// 后续由协议层 (Protocol Parser) 解析为 NormalizedTransaction。
/// </summary>
public class RawPacket
{
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public string SourceChannel { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public PacketMetadata Metadata { get; set; } = new();
}

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
/// 采集通道接口 — 每种数据采集方式实现一个 Channel。
/// Channel 之间完全独立，互不依赖。
/// 实现此接口即可被 ChannelManager 注册和管理。
/// </summary>
public interface ICaptureChannel
{
    /// <summary>通道唯一标识，如 "WinDivert"、"DnsSpoof"</summary>
    string Name { get; }

    /// <summary>人类可读的描述</summary>
    string Description { get; }

    /// <summary>通道能力声明</summary>
    ChannelCapability Capability { get; }

    /// <summary>初始化（安装驱动、分配资源等）</summary>
    Task<bool> InitializeAsync();

    /// <summary>开始采集</summary>
    Task StartAsync();

    /// <summary>停止采集</summary>
    Task StopAsync();

    /// <summary>健康检查</summary>
    bool IsHealthy { get; }

    /// <summary>采集到的原始数据事件</summary>
    event Action<RawPacket>? OnPacket;
}

/// <summary>
/// 标准化事务 — 协议层解析后输出的统一格式，供 RuleEngine 匹配和提取。
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
/// TCP 连接标识。
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
