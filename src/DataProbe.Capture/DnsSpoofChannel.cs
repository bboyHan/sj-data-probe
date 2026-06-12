using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// DNS 劫持通道 — 封装 DnsSpoofer 为 ICaptureChannel。
/// 拦截 DNS 响应，将支付域名指向 127.0.0.1 实现流量重定向。
/// </summary>
public class DnsSpoofChannel : ICaptureChannel
{
    private DnsSpoofer? _spoofer;
    private string[] _spoofDomains = Array.Empty<string>();

    public string Name => "DnsSpoof";
    public string Description => "DNS 劫持 — 目标域名指向本地代理";
    public ChannelCapability Capability => new()
    {
        RequiresAdmin = true,
        CanDecryptTls = false,
        SupportedProtocols = new[] { "DNS" },
        ScopeDescription = "DNS 响应劫持，覆盖所有走系统 DNS 解析的应用",
    };

    public bool IsHealthy => _spoofer?.IsRunning ?? false;
    public event Action<RawPacket>? OnPacket;

    public long SpoofedCount => _spoofer?.SpoofedCount ?? 0;

    public void SetSpoofDomains(string[] domains)
    {
        _spoofDomains = domains ?? Array.Empty<string>();
    }

    public Task<bool> InitializeAsync()
    {
        try
        {
            _spoofer = new DnsSpoofer();
            _spoofer.SetSpoofDomains(_spoofDomains);
            Console.Error.WriteLine("[DnsSpoofChannel] Created");
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[DnsSpoofChannel] Init failed: {ex.Message}");
            return Task.FromResult(false);
        }
    }

    public Task StartAsync()
    {
        _spoofer?.Start();
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _spoofer?.Stop();
        return Task.CompletedTask;
    }

    public void Dispose() => _spoofer?.Dispose();
}
