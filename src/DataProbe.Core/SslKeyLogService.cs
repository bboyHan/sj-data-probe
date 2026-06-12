namespace DataProbe.Core;

/// <summary>
/// SSLKEYLOGFILE 密钥注入器 — 针对浏览器/CEF 目标。
///
/// 原理：
///   设置 SSLKEYLOGFILE 环境变量 → 启动目标进程
///   → 浏览器/CEF/curl 自动将 TLS 会话密钥写入该文件
///   → DataProbe 监控文件变化，收集密钥
///   → 密钥可用于被动解密（不依赖 MITM 代理）
///
/// 适用目标：
///   ├─ Chrome/Chromium/Edge  (BoringSSL, 支持 keylog)
///   ├─ Firefox               (NSS, 支持 keylog)
///   ├─ curl/wget             (OpenSSL, 支持 keylog)
///   └─ Electron 应用          (Chromium 内核, 支持 keylog)
///
/// 不适用：
///   ├─ 原生 App（WinHTTP/SChannel 不支持 keylog）
///   ├─ 游戏（自定义 TLS 栈不支持 keylog）
///   └─ 移动端 App（不支持环境变量注入）
///
/// 使用方式：
///   var keylog = new SslKeyLogService();
///   keylog.EnableForProcess("chrome");
///   // 启动目标进程
///   // 读取 keylog.GetKeys() → 喂给 passive decryptor
/// </summary>
public class SslKeyLogService : IDisposable
{
    private string? _keyLogPath;
    private FileSystemWatcher? _watcher;
    private long _lastFilePosition;
    private readonly List<SslKeyEntry> _keys = new();
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>已收集的密钥条目</summary>
    public IReadOnlyList<SslKeyEntry> Keys
    {
        get { lock (_lock) return _keys.ToArray(); }
    }

    /// <summary>当前密钥文件路径</summary>
    public string? KeyLogPath => _keyLogPath;

    /// <summary>
    /// 为指定进程启用 SSLKEYLOGFILE
    /// </summary>
    /// <param name="processName">进程名（不含 .exe）</param>
    /// <returns>是否成功启用</returns>
    public bool EnableForProcess(string processName)
    {
        try
        {
            // 在临时目录创建密钥文件
            _keyLogPath = Path.Combine(Path.GetTempPath(), $"dataprobe_sslkeylog_{Guid.NewGuid():N}.log");

            // 设置环境变量
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", _keyLogPath, EnvironmentVariableTarget.Process);

            // 启动文件监控
            _watcher = new FileSystemWatcher(Path.GetTempPath(), Path.GetFileName(_keyLogPath))
            {
                NotifyFilter = NotifyFilters.Size | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            _watcher.Changed += OnKeyLogChanged;

            Console.Error.WriteLine($"[SSLKEYLOGFILE] Enabled for {processName} → {_keyLogPath}");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[SSLKEYLOGFILE] Failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 读取所有已收集的密钥
    /// </summary>
    public SslKeyEntry[] CollectKeys()
    {
        lock (_lock)
        {
            // 读取自上次检查后的新增密钥
            if (_keyLogPath != null && File.Exists(_keyLogPath))
            {
                try
                {
                    using var fs = new FileStream(_keyLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(fs);

                    if (_lastFilePosition > 0)
                        fs.Seek(_lastFilePosition, SeekOrigin.Begin);

                    string? line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        if (line.StartsWith("#")) continue;

                        var parts = line.Split(' ');
                        if (parts.Length >= 2)
                        {
                            var entry = new SslKeyEntry
                            {
                                RawLine = line,
                                CapturedAt = DateTime.UtcNow
                            };

                            if (parts[0] == "RSA" && parts.Length >= 4)
                            {
                                entry.Type = "RSA";
                                entry.ClientRandom = parts[1];
                                entry.MasterKey = parts[3];
                            }
                            else if (parts[0] == "CLIENT_RANDOM" && parts.Length >= 3)
                            {
                                entry.Type = "TLS12";
                                entry.ClientRandom = parts[1];
                                entry.MasterKey = parts[2];
                            }
                            else if (parts[0] == "EXPORTER_SECRET" && parts.Length >= 3)
                            {
                                entry.Type = "TLS13";
                                entry.ClientRandom = parts[1];
                                entry.MasterKey = parts[2];
                            }
                            else if (parts[0] == "SERVER_HANDSHAKE_TRAFFIC_SECRET" && parts.Length >= 3)
                            {
                                entry.Type = "TLS13_HS";
                                entry.ClientRandom = parts[1];
                                entry.MasterKey = parts[2];
                            }
                            else if (parts[0] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET" && parts.Length >= 3)
                            {
                                entry.Type = "TLS13_CHS";
                                entry.ClientRandom = parts[1];
                                entry.MasterKey = parts[2];
                            }

                            entry.IsParsed = !string.IsNullOrEmpty(entry.Type);
                            _keys.Add(entry);
                        }
                    }

                    _lastFilePosition = fs.Length;
                }
                catch { }
            }

            return _keys.ToArray();
        }
    }

    /// <summary>
    /// 将当前密钥导出为 NSS 格式文本（可直接供 Wireshark 使用）
    /// </summary>
    public string ExportToNssFormat()
    {
        lock (_lock)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("# DataProbe SSL Key Log");
            sb.AppendLine($"# Captured at {DateTime.UtcNow:O}");

            foreach (var key in _keys)
            {
                if (key.IsParsed)
                    sb.AppendLine(key.RawLine);
            }

            return sb.ToString();
        }
    }

    private void OnKeyLogChanged(object sender, FileSystemEventArgs e)
    {
        // 文件变化时自动收集密钥（线程安全）
        CollectKeys();
    }

    /// <summary>
    /// 清除所有收集的密钥并停止监控
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _keys.Clear();
            _lastFilePosition = 0;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher?.Dispose();

        // 清理环境变量
        try { Environment.SetEnvironmentVariable("SSLKEYLOGFILE", null, EnvironmentVariableTarget.Process); }
        catch { }

        // 清理临时文件
        try { if (_keyLogPath != null && File.Exists(_keyLogPath)) File.Delete(_keyLogPath); }
        catch { }
    }
}

/// <summary>TLS 会话密钥条目</summary>
public class SslKeyEntry
{
    public string Type { get; set; } = "";        // CLIENT_RANDOM / RSA / TLS13 / ...
    public string ClientRandom { get; set; } = "";
    public string MasterKey { get; set; } = "";
    public string RawLine { get; set; } = "";
    public bool IsParsed { get; set; }
    public DateTime CapturedAt { get; set; }
}
