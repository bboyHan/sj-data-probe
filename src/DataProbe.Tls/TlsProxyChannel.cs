using DataProbe.Capture;
using DataProbe.Core;

namespace DataProbe.Tls;

/// <summary>
/// TLS 代理通道 — 封装 TlsProxy 为 ICaptureChannel。
/// 提供 CONNECT 代理和 DNS 劫持流量的 MITM 解密。
/// </summary>
public class TlsProxyChannel : ICaptureChannel
{
    private readonly TlsProxy _proxy;
    private bool _initialized;

    public string Name => "TlsProxy";
    public string Description => "SChannel MITM 代理 — HTTPS 解密 + 凭证提取";

    /// <summary>转发 TlsProxy 的事务捕获事件（供 SessionBuilder 桥接）</summary>
    public event Action<NormalizedTransaction>? OnTransactionCaptured
    {
        add => _proxy.OnTransactionCaptured += value;
        remove => _proxy.OnTransactionCaptured -= value;
    }
    public ChannelCapability Capability => new()
    {
        RequiresAdmin = false,
        CanDecryptTls = true,
        RequiresCertInstall = true,
        SupportedProtocols = new[] { "HTTPS", "HTTP" },
        ScopeDescription = "浏览器 CONNECT 代理 + DNS 劫持 443 端口",
    };

    public bool IsHealthy => _proxy?.IsRunning ?? false;
    public event Action<RawPacket>? OnPacket;

    public long TotalConnections => _proxy?.TotalConnections ?? 0;
    public long ActiveConnections => _proxy?.ActiveConnections ?? 0;
    public long FailedConnections => _proxy?.FailedConnections ?? 0;

    public TlsProxyChannel(DataProbeConfig config, CertificateManager certMgr,
        CredentialQueue credentialQueue, DataProbe.Extractor.RuleEngine? ruleEngine,
        DataProbe.Http.ProtocolRegistry? protocolRegistry = null,
            DataProbe.Core.TrafficBuffer? trafficBuffer = null)
    {
        _proxy = new TlsProxy(config, certMgr, credentialQueue, ruleEngine, protocolRegistry, trafficBuffer);
    }

    public Task<bool> InitializeAsync()
    {
        _initialized = true;
        Console.Error.WriteLine("[TlsProxyChannel] Ready");
        return Task.FromResult(true);
    }

    public Task StartAsync()
    {
        _proxy.Start();
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _proxy.Stop();
        return Task.CompletedTask;
    }
}
