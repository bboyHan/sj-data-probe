namespace DataProbe.Core;

/// <summary>
/// 全局配置。
/// 所有配置项均有默认值，可通过 config.json 或 CLI 参数覆盖。
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
    public string[] TargetDomains { get; set; } = Array.Empty<string>();

    // ── DNS Spoof List ────────────────────────────────
    public string[] SpoofDomains { get; set; } = Array.Empty<string>();

    // ── SNI Keywords ──────────────────────────────────
    public string[] SniKeywords { get; set; } = Array.Empty<string>();

    // ── Storage ───────────────────────────────────────
    public string AppDataPath { get; set; } = "";
    public string CaCertFileName { get; set; } = "dataprobe_ca.p12";
    public string ConfigFileName { get; set; } = "config.json";

    // ── 新增：Session 配置 ────────────────────────────
    /// <summary>Session 快照最大步骤数</summary>
    public int MaxSessionSteps { get; set; } = 1000;

    /// <summary>Session 快照最大 HTTP 事务数</summary>
    public int MaxSessionTransactions { get; set; } = 10000;

    /// <summary>是否启用启发式提取</summary>
    public bool EnableHeuristicExtraction { get; set; } = true;

    /// <summary>启发式提取最低熵值阈值</summary>
    public double HeuristicEntropyThreshold { get; set; } = 4.5;

    // ── 新增：仿真配置 ────────────────────────────────
    /// <summary>TLS 指纹模板名称（为空则使用系统默认）</summary>
    public string? TlsFingerprintProfile { get; set; }

    /// <summary>是否启用行为仿真</summary>
    public bool EnableBehaviorSimulation { get; set; }

    // ── 新增：调查引擎配置 ────────────────────────────
    /// <summary>最大通道异常重试次数</summary>
    public int MaxChannelRetries { get; set; } = 2;

    /// <summary>通道健康检查间隔（秒）</summary>
    public int HealthCheckIntervalSec { get; set; } = 30;

    // ── 路径辅助方法 ──────────────────────────────────

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
