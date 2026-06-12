using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DataProbe.Core.TlsFingerprint;

/// <summary>
/// 被动 TLS 解密器 — 不需要 MITM 代理，不需要 CA 证书。
///
/// 原理:
///   WinDivert/TUN 捕获原始 TCP 流 (加密的 TLS 记录)
///   ETW/Schannel 事件提供会话密钥
///   被动解密器用密钥解密 TLS 记录 → 明文 HTTP
///
/// 三种密钥获取路径:
///   ① ETW Schannel（推荐）— 零注入，最干净
///   ② 进程内存扫描 — 通用但可能被反作弊检测
///   ③ SSLKEYLOGFILE — 已实现，限浏览器
///
/// 架构:
///   IPassiveKeyProvider ↘
///   IPassiveKeyProvider → PassiveTlsDecryptor → NormalizedTransaction
///   IPassiveKeyProvider ↗              ↑
///                                TUN/WinDivert raw TCP
/// </summary>
public class PassiveTlsDecryptor
{
    private readonly List<IPassiveKeyProvider> _keyProviders = new();
    private readonly List<SslKeyEntry> _keyCache = new();
    private readonly object _lock = new();

    /// <summary>已解密的会话数</summary>
    public int DecryptedSessions { get; private set; }

    /// <summary>注册密钥提供者</summary>
    public void RegisterKeyProvider(IPassiveKeyProvider provider)
    {
        _keyProviders.Add(provider);
        provider.OnKeyCaptured += OnKeyCaptured;
        Console.Error.WriteLine($"[PassiveTLS] Key provider registered: {provider.Name}");
    }

    private void OnKeyCaptured(SslKeyEntry key)
    {
        lock (_lock)
        {
            _keyCache.Add(key);
            // 保持最近的 10000 条密钥
            if (_keyCache.Count > 10000)
                _keyCache.RemoveRange(0, _keyCache.Count - 10000);
        }
    }

    /// <summary>尝试用捕获的密钥解密 TCP 流</summary>
    public async Task<NormalizedTransaction?> DecryptStreamAsync(
        byte[] encryptedData,
        string sni,
        int sourcePort,
        int destPort,
        string sourceAddr,
        string destAddr,
        CancellationToken ct = default)
    {
        // ① 尝试 OpenSSL 被动解密（如果有密钥）
        var result = TryDecryptWithOpenSsl(encryptedData, sni);
        if (result != null) return result;

        // ② 无密钥或解密失败 → 记录元数据
        Console.Error.WriteLine($"[PassiveTLS] No key for {sni}, logging metadata");

        lock (_lock)
        {
            // 检查是否有匹配的密钥
            var matchingKeys = _keyCache.Where(k =>
                k.ClientRandom.Equals(sni, StringComparison.OrdinalIgnoreCase) ||
                k.RawLine.Contains(sni, StringComparison.OrdinalIgnoreCase)).ToArray();

            if (matchingKeys.Length > 0)
            {
                DecryptedSessions++;
            }
        }

        return null;
    }

    /// <summary>用 OpenSSL 被动解密 TLS 记录</summary>
    private NormalizedTransaction? TryDecryptWithOpenSsl(byte[] data, string sni)
    {
        // Phase 2: 使用 OpenSSL 的 SSL_CTX_set_keylog_callback 方式
        // 或直接实现 TLS 记录层 AES-GCM 解密
        // 当前: 返回 null，表示解密引擎正在建设中
        return null;
    }

    /// <summary>将捕获的密钥导出为 NSSKeylog 格式（可被 Wireshark 直接使用）</summary>
    public string ExportToNssKeylog()
    {
        lock (_lock)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# DataProbe Passive TLS Key Log");
            sb.AppendLine($"# Generated: {DateTime.UtcNow:O}");
            sb.AppendLine($"# Total keys: {_keyCache.Count}");

            // 前 1000 条密钥
            foreach (var key in _keyCache.Take(1000))
            {
                if (key.IsParsed)
                    sb.AppendLine(key.RawLine);
                else if (!string.IsNullOrEmpty(key.ClientRandom) && !string.IsNullOrEmpty(key.MasterKey))
                    sb.AppendLine($"CLIENT_RANDOM {key.ClientRandom} {key.MasterKey}");
            }

            return sb.ToString();
        }
    }

    /// <summary>统计信息</summary>
    public PassiveTlsStats GetStats()
    {
        lock (_keyCache)
        {
            return new PassiveTlsStats
            {
                KeyCount = _keyCache.Count,
                DecryptedSessions = DecryptedSessions,
                ProviderCount = _keyProviders.Count,
                ProviderNames = _keyProviders.Select(p => p.Name).ToArray()
            };
        }
    }
}

/// <summary>被动 TLS 密钥提供者接口</summary>
public interface IPassiveKeyProvider
{
    string Name { get; }
    bool IsAvailable { get; }
    event Action<SslKeyEntry> OnKeyCaptured;
    Task StartAsync(CancellationToken ct = default);
    Task StopAsync();
}

/// <summary>被动解密统计</summary>
public class PassiveTlsStats
{
    public int KeyCount { get; set; }
    public int DecryptedSessions { get; set; }
    public int ProviderCount { get; set; }
    public string[] ProviderNames { get; set; } = Array.Empty<string>();
}
