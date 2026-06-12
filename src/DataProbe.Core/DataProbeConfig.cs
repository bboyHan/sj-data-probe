namespace DataProbe.Core;

/// <summary>
/// 万能数据采集引擎 — 全局配置。
/// 所有配置项均有默认值，可通过 config.json 或环境变量覆盖。
/// 不包含任何业务语义，TargetDomains/SpoofDomains/SniKeywords 由调用方注入。
/// </summary>
public class DataProbeConfig
{
    // ── WinDivert ─────────────────────────────────────
    public int WinDivertQueueLen { get; set; } = 8192;
    public int MaxConnections { get; set; } = 50000;
    public int ConnectionTimeoutSec { get; set; } = 60;
    public int ConnectionCleanupIntervalSec { get; set; } = 10;
    public int PacketQueueSize { get; set; } = 10000;

    // ── TLS Proxy ─────────────────────────────────────
    public int TlsProxyPort { get; set; } = 18802;
    public int CertCacheSize { get; set; } = 1024;
    public int CertValidHours { get; set; } = 1;
    public string CaSubject { get; set; } = "CN=DataProbe CA, O=DataProbe, C=CN";
    public int TlsHandshakeTimeoutMs { get; set; } = 5000;
    public int TlsRelayBufferSize { get; set; } = 65536;

    // ── Management API ────────────────────────────────
    public int ApiPort { get; set; } = 18801;
    public string ApiBindAddress { get; set; } = "127.0.0.1";

    // ── Output Backend ────────────────────────────────
    public string? BackendUrl { get; set; } = null;
    public string IngestEndpoint { get; set; } = "/api/capture/ingest";
    public int BatchSize { get; set; } = 10;
    public int BatchIntervalMs { get; set; } = 1000;
    public int HttpTimeoutSec { get; set; } = 5;

    // ── Target Domain List ────────────────────────────
    // 引擎只会深度处理命中此列表的流量（TLS 解密、正文提取）。
    // 空列表 = 处理所有流量（性能较低）。
    public string[] TargetDomains { get; set; } = Array.Empty<string>();

    // ── DNS Spoof List ────────────────────────────────
    // DNS 劫持目标。命中此列表的 DNS 响应会被篡改为 127.0.0.1。
    public string[] SpoofDomains { get; set; } = Array.Empty<string>();

    // ── SNI Keywords ──────────────────────────────────
    // WinDivert 通道使用此列表判断是否将连接交给 TlsProxy。
    public string[] SniKeywords { get; set; } = Array.Empty<string>();

    // ── Storage ───────────────────────────────────────
    public string AppDataPath { get; set; } = "";
    public string CaCertFileName { get; set; } = "dataprobe_ca.p12";
    public string ConfigFileName { get; set; } = "config.json";

    public string GetCaCertPath()
    {
        var basePath = AppDataPath;
        if (string.IsNullOrEmpty(basePath))
        {
            basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataProbe");
        }
        Directory.CreateDirectory(basePath);
        return Path.Combine(basePath, CaCertFileName);
    }

    public string GetConfigPath()
    {
        var basePath = AppDataPath;
        if (string.IsNullOrEmpty(basePath))
        {
            basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataProbe");
        }
        Directory.CreateDirectory(basePath);
        return Path.Combine(basePath, ConfigFileName);
    }
}
