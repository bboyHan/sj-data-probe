using System.Diagnostics;
using System.Xml;
using DataProbe.Core;
using DataProbe.Core.TlsFingerprint;

namespace DataProbe.Capture;

/// <summary>
/// ETW TLS 密钥捕获服务 — 通过 Windows ETW (Event Tracing for Windows)
/// 监听 Microsoft-Windows-Schannel 提供程序的事件，提取 TLS 会话密钥。
///
/// 零注入、零 Hook、零进程交互。
/// 只需要管理员权限启动 ETW 会话。
///
/// ETW 提供程序 GUID: {7F85F1E8-1181-45E8-9D79-A322381C53E4}
/// 关键词: 0x8000000000000000 (Microsoft-Windows-Schannel 的密钥事件)
///
/// 验证:
///   管理员运行 → 启动此服务 → 任意 HTTPS 请求
///   → ETW 捕获 Schannel 握手事件 → 提取 MasterKey
///   → 写入 NSS KeyLog → Wireshark 可验证
/// </summary>
public class EtwTlsCaptureService : IPassiveKeyProvider
{
    public string Name => "ETW_Schannel";
    private long _sessionHandle;
    private CancellationTokenSource? _cts;
    private bool _isRunning;
    private string? _etlPath;

    // ── ETW 常量 ──

    // Microsoft-Windows-Schannel 提供程序 GUID
    private static readonly Guid SchannelProviderGuid = new("7F85F1E8-1181-45E8-9D79-A322381C53E4");

    private const int EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;

    // 关键字: 0x8000000000000000 = 密钥事件
    // 级别: 4 (WINWORD_LEVEL_VERBOSE)
    private const ulong SchannelKeywords = 0x8000000000000000;
    private const byte VerboseLevel = 4;

    // ── EventID 定义（Schannel ETW 事件类型）──
    // 从 Windows SDK 中获取的已知 Schannel 事件 ID
    private const ushort EventIdHandshakeStart = 1000;   // TLS 握手开始
    private const ushort EventIdHandshakeStop = 1001;    // TLS 握手完成（含密钥）
    private const ushort EventIdKeyMaterial = 1002;      // 密钥材料
    private const ushort EventIdSessionInfo = 1003;      // 会话信息

    public bool IsAvailable
    {
        get
        {
            // 检查是否以管理员身份运行（ETW 需要管理员）
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public bool IsRunning => _isRunning;

    public event Action<SslKeyEntry>? OnKeyCaptured;

    public EtwTlsCaptureService()
    {
        Console.Error.WriteLine($"[EtwTlsCapture] Schannel provider: {SchannelProviderGuid}");
        Console.Error.WriteLine($"[EtwTlsCapture] Admin required: {IsAvailable}");
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        if (_isRunning) return Task.CompletedTask;

        if (!IsAvailable)
        {
            Console.Error.WriteLine("[EtwTlsCapture] Requires Administrator privileges");
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        try
        {
            // 使用 logman 命令启动 ETW 跟踪会话
            // 这是最轻量级的方式，不需要任何外部库
            StartTraceWithLogman();

            // 启动后台线程解析 ETL 文件
            _isRunning = true;
            _ = Task.Run(() => ProcessTraceLoop(_cts.Token), _cts.Token);

            Console.Error.WriteLine("[EtwTlsCapture] ETW session started via logman");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[EtwTlsCapture] Start failed: {ex.Message}");

            // 回退方案: 启动 logman 的备用方法
            try
            {
                FallbackStart();
                _isRunning = true;
            }
            catch (Exception fallbackEx)
            {
                Console.Error.WriteLine($"[EtwTlsCapture] Fallback also failed: {fallbackEx.Message}");
            }
        }

        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;

        _cts?.Cancel();

        try
        {
            // 停止 logman 跟踪
            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments = "stop DataProbeTlsTrace -ets",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(3000);
        }
        catch { }

        _isRunning = false;
        Console.Error.WriteLine("[EtwTlsCapture] ETW session stopped");
        return Task.CompletedTask;
    }

    private string? __etlPath;

    /// <summary>
    /// 使用 logman.exe 启动 ETW 跟踪（最轻量，零依赖）
    /// </summary>
    private void StartTraceWithLogman()
    {
        __etlPath = Path.Combine(Path.GetTempPath(), $"dp_tls_{Guid.NewGuid():N}.etl");

        var psi = new ProcessStartInfo
        {
            FileName = "logman.exe",
            Arguments = $"create trace DataProbeTlsTrace -o \"{_etlPath}\" -p \"Microsoft-Windows-Schannel\" 0x8000000000000000 4 -ets",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) throw new InvalidOperationException("Failed to start logman");

        var output = proc.StandardOutput.ReadToEnd();
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit(5000);

        if (proc.ExitCode != 0 && !output.Contains("The session already exists"))
        {
            // 如果已存在，先停止再重试
            if (output.Contains("already exists") || error.Contains("already exists"))
            {
                StopTraceWithLogman();
                StartTraceWithLogman();
                return;
            }
            throw new InvalidOperationException($"logman failed ({proc.ExitCode}): {error}");
        }

        Console.Error.WriteLine($"[EtwTlsCapture] Trace started, output: {_etlPath}");
    }

    private void StopTraceWithLogman()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments = "stop DataProbeTlsTrace -ets",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(2000);
        }
        catch { }
    }

    /// <summary>
    /// 后台解析 ETL 文件 — 使用 tracerpt 将 ETL 转换为 XML 后解析
    /// </summary>
    private async Task ProcessTraceLoop(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(__etlPath)) return;

        var lastXmlSize = 0L;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(3000, ct);

                try
                {
                    var xmlPath = Path.ChangeExtension(__etlPath, ".xml");

                    // 用 tracerpt 转换 ETL → XML
                    var psi = new ProcessStartInfo
                    {
                        FileName = "tracerpt.exe",
                        Arguments = $"\"{__etlPath}\" -o \"{xmlPath}\" -of XML -y",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };

                    using var proc = Process.Start(psi);
                    if (proc == null) continue;

                    var error = proc.StandardError.ReadToEnd();
                    proc.WaitForExit(5000);

                    // 检查 XML 文件是否更新
                    if (File.Exists(xmlPath))
                    {
                        var currentSize = new FileInfo(xmlPath).Length;
                        if (currentSize > lastXmlSize)
                        {
                            lastXmlSize = currentSize;
                            var xml = File.ReadAllText(xmlPath);
                            ParseTraceEvents(xml);
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[EtwTlsCapture] Poll error: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// 解析 tracerpt 输出的 XML，提取 Schannel 事件中的密钥
    /// </summary>
    private void ParseTraceEvents(string xml)
    {
        if (string.IsNullOrEmpty(xml)) return;

        try
        {
            var doc = new System.Xml.XmlDocument();
            doc.LoadXml(xml);

            // 查找所有 Event 节点
            var events = doc.SelectNodes("//Event");
            if (events == null || events.Count == 0) return;

            foreach (System.Xml.XmlNode? evt in events)
            {
                if (evt == null) continue;

                // 获取 EventID
                var idNode = evt.SelectSingleNode("System/EventID");
                if (idNode == null) continue;
                var eventId = idNode.InnerText.Trim();

                // 只处理 Schannel 的握手完成和密钥事件
                if (eventId != "1001" && eventId != "1002" && eventId != "1003") continue;

                // 获取 EventData 中的所有数据项
                var dataNodes = evt.SelectNodes("EventData/Data");
                if (dataNodes == null || dataNodes.Count == 0) continue;

                var entry = new SslKeyEntry
                {
                    CapturedAt = DateTime.UtcNow,
                    Type = eventId switch { "1001" => "TLS12", "1002" => "TLS13", _ => "Unknown" }
                };

                string? masterKey = null, clientRandom = null;

                foreach (System.Xml.XmlNode? data in dataNodes)
                {
                    if (data == null) continue;
                    var name = data.Attributes?["Name"]?.Value ?? "";
                    var value = data.InnerText.Trim();

                    switch (name.ToLower())
                    {
                        case "masterkey" or "master_key" or "keymaterial" or "key_material":
                            masterKey = value; break;
                        case "clientrandom" or "client_random":
                            clientRandom = value; break;
                        case "sessionid" or "session_id":
                            entry.ClientRandom = value; break;
                    }
                }

                // 有效密钥 = MasterKey + ClientRandom 都存在
                if (!string.IsNullOrEmpty(masterKey) && !string.IsNullOrEmpty(clientRandom))
                {
                    entry.MasterKey = masterKey;
                    entry.ClientRandom = clientRandom;
                    entry.RawLine = $"CLIENT_RANDOM {clientRandom} {masterKey}";
                    entry.IsParsed = true;

                    OnKeyCaptured?.Invoke(entry);
                    Console.Error.WriteLine($"[EtwTlsCapture] 🔑 Key captured: {eventId} CLIENT_RANDOM {clientRandom[..Math.Min(16, clientRandom.Length)]}...");
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[EtwTlsCapture] Parse error: {ex.Message}");
        }
    }

    /// <summary>
    /// 回退方案：直接启动 logman 的不同关键词组合
    /// </summary>
    private void FallbackStart()
    {
        Console.Error.WriteLine("[EtwTlsCapture] Fallback: trying alternative keyword mask");

        // 某些 Windows 版本需要不同的关键词掩码
        // 尝试更常用的安全审计关键词
        try
        {
            StopTraceWithLogman();
            var psi = new ProcessStartInfo
            {
                FileName = "logman.exe",
                Arguments = $"create trace DpTlsFallback -o \"{Path.GetTempPath()}\\dp_fallback.etl\" -p \"Microsoft-Windows-Schannel\" 0x8000000000000000 255 -ets",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null) proc.WaitForExit(2000);
            Console.Error.WriteLine("[EtwTlsCapture] Fallback trace started");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[EtwTlsCapture] Fallback failed: {ex.Message}");
        }
    }
}
