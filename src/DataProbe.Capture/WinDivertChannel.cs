using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// WinDivert 采集通道 — 封装 WinDivertDriver 为 ICaptureChannel。
/// SNIFF 模式监控 TCP/443 流量，提取 SNI 用于域名匹配。
/// </summary>
public class WinDivertChannel : ICaptureChannel
{
    private readonly WinDivertDriver _driver;
    private readonly ConnectionTracker _tracker;
    private readonly PacketFilter _filter;

    public string Name => "WinDivert";
    public string Description => "WinDivert 内核驱动 — 监控 TCP/443 流量";
    public ChannelCapability Capability => new()
    {
        RequiresAdmin = true,
        CanDecryptTls = false,
        SupportedProtocols = new[] { "TLS" },
        ScopeDescription = "PC 全流量监控（SNI 提取、包统计）",
    };

    public bool IsHealthy => _driver != null;

    public event Action<RawPacket>? OnPacket;

    public WinDivertChannel(DataProbeConfig config, ConnectionTracker tracker, PacketFilter filter)
    {
        _driver = new WinDivertDriver();
        _tracker = tracker;
        _filter = filter;
    }

    public Task<bool> InitializeAsync()
    {
        try
        {
            // Driver is created in constructor; Open() is called in StartAsync
            Console.Error.WriteLine("[WinDivertChannel] Driver ready");
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WinDivertChannel] Init failed: {ex.Message}");
            return Task.FromResult(false);
        }
    }

    public Task StartAsync()
    {
        _driver.OnPacketCaptured += OnDriverPacket;
        _driver.Open();
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _driver.OnPacketCaptured -= OnDriverPacket;
        _driver.Close();
        return Task.CompletedTask;
    }

    private void OnDriverPacket(CapturedPacket packet)
    {
        var sni = packet.ExtractSni();
        var raw = new RawPacket
        {
            Data = packet.RawData,
            SourceChannel = Name,
            Timestamp = DateTime.UtcNow,
            Metadata = new PacketMetadata
            {
                Sni = sni,
                SourcePort = packet.SrcPort,
                DestPort = packet.DstPort,
                SourceAddress = packet.SrcAddr?.ToString(),
                DestAddress = packet.DstAddr?.ToString(),
            },
        };
        OnPacket?.Invoke(raw);
    }

    public long PacketsCaptured => _driver.DirectPacketCount;

    /// <summary>
    /// 设置 SNI 关键词列表。命中任意关键词的 TLS SNI 会被转发到 TlsProxy。
    /// </summary>
    public void SetSniKeywords(string[] keywords)
    {
        _driver.SetSniKeywords(keywords);
    }
}
