using System.Diagnostics;
using System.Xml;
using DataProbe.Core;
using DataProbe.Core.TlsFingerprint;

namespace DataProbe.Capture;

public class EtwTlsCaptureService : IPassiveKeyProvider
{
    public string Name => "ETW_Schannel";
    private CancellationTokenSource? _cts;
    private bool _isRunning;
    private string? _etlPath;

    // Windows 11 25H2 已知的 Schannel 相关 ETW 提供程序
    private static readonly (string Name, string Guid, ulong Keywords)[] SchannelProviders = {
        ("Microsoft-Windows-Schannel-Events", "{91CC1150-71AA-47E2-AE18-C96E61736B6F}", 0xFFFFFFFFFFFFFFFF),
        ("Schannel",                         "{1F678132-5938-4686-9FDC-C8FF68F15C85}", 0xFFFFFFFFFFFFFFFF),
        ("Security: SChannel",               "{37D2C3CD-C5D4-4587-8531-4696C44244C8}", 0xFFFFFFFFFFFFFFFF),
    };

    public bool IsAvailable
    {
        get
        {
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

    public Task StartAsync(CancellationToken ct = default)
    {
        if (_isRunning) return Task.CompletedTask;
        if (!IsAvailable) { Console.Error.WriteLine("[EtwTlsCapture] Requires Admin"); return Task.CompletedTask; }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        // 尝试每个提供程序
        foreach (var (name, guid, keywords) in SchannelProviders)
        {
            try
            {
                _etlPath = Path.Combine(Path.GetTempPath(), $"dp_tls_{Guid.NewGuid():N}.etl");
                var xmlPath = Path.ChangeExtension(_etlPath, ".xml");

                // 清理可能残留的会话
                ExecLogman($"stop DataProbeTlsTrace -ets");

                var output = ExecLogman($"create trace DataProbeTlsTrace -o \"{_etlPath}\" -p \"{name}\" {keywords} 255 -ets");
                if (output.Contains("failed", StringComparison.OrdinalIgnoreCase)) continue;

                Console.Error.WriteLine($"[EtwTlsCapture] ✅ Trace started with: {name}");

                _isRunning = true;
                _ = Task.Run(() => PollTraceLoop(xmlPath, _cts.Token), _cts.Token);
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[EtwTlsCapture] Provider '{name}' failed: {ex.Message}");
                Cleanup();
            }
        }

        Console.Error.WriteLine("[EtwTlsCapture] All providers failed");
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;
        _cts?.Cancel();
        ExecLogman("stop DataProbeTlsTrace -ets");
        Cleanup();
        _isRunning = false;
        return Task.CompletedTask;
    }

    private void Cleanup()
    {
        try { if (_etlPath != null && File.Exists(_etlPath)) File.Delete(_etlPath); } catch { }
        try { if (_etlPath != null) { var x = Path.ChangeExtension(_etlPath, ".xml"); if (File.Exists(x)) File.Delete(x); } } catch { }
    }

    private static string ExecLogman(string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "logman.exe", Arguments = args,
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        });
        if (proc == null) return "failed";
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(5000);
        return output + proc.StandardError.ReadToEnd();
    }

    private async Task PollTraceLoop(string xmlPath, CancellationToken ct)
    {
        var lastSize = 0L;

        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(3000, ct);
            if (_etlPath == null || !File.Exists(_etlPath)) continue;

            try
            {
                using var tp = Process.Start(new ProcessStartInfo
                {
                    FileName = "tracerpt.exe",
                    Arguments = $"\"{_etlPath}\" -o \"{xmlPath}\" -of XML -y",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                });
                if (tp == null) continue;
                tp.WaitForExit(5000);

                if (!File.Exists(xmlPath)) continue;
                var size = new FileInfo(xmlPath).Length;
                if (size <= lastSize) continue;
                lastSize = size;

                var xml = File.ReadAllText(xmlPath);
                ParseTraceXml(xml);
            }
            catch (Exception ex) { Debug.WriteLine($"[EtwTlsCapture] Poll: {ex.Message}"); }
        }
    }

    private void ParseTraceXml(string xml)
    {
        if (string.IsNullOrEmpty(xml)) return;

        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var events = doc.SelectNodes("//Event");
            if (events == null || events.Count == 0) return;

            foreach (System.Xml.XmlNode? evt in events)
            {
                if (evt == null) continue;
                var idNode = evt.SelectSingleNode("System/EventID");
                if (idNode == null) continue;

                // 只处理握手完成/密钥事件
                var eventId = idNode.InnerText.Trim();
                if (eventId != "1001" && eventId != "1002" && eventId != "1003" && eventId != "1004") continue;

                var dataNodes = evt.SelectNodes("EventData/Data");
                if (dataNodes == null) continue;

                string? masterKey = null, clientRandom = null;
                foreach (System.Xml.XmlNode? data in dataNodes)
                {
                    if (data == null) continue;
                    var name = data.Attributes?["Name"]?.Value ?? "";
                    var value = data.InnerText.Trim();
                    var lower = name.ToLower();

                    if (lower.Contains("master") || lower.Contains("keymaterial") || lower.Contains("secret"))
                        masterKey = value;
                    else if (lower.Contains("clientrandom") || lower.Contains("client_random"))
                        clientRandom = value;
                }

                if (!string.IsNullOrEmpty(masterKey) && !string.IsNullOrEmpty(clientRandom))
                {
                    OnKeyCaptured?.Invoke(new SslKeyEntry
                    {
                        Type = "TLS12",
                        MasterKey = masterKey,
                        ClientRandom = clientRandom,
                        RawLine = $"CLIENT_RANDOM {clientRandom} {masterKey}",
                        IsParsed = true,
                        CapturedAt = DateTime.UtcNow
                    });
                    Console.Error.WriteLine($"[EtwTlsCapture] 🔑 Key: {clientRandom[..Math.Min(16, clientRandom.Length)]}...");
                }
            }
        }
        catch (Exception ex) { Debug.WriteLine($"[EtwTlsCapture] XML parse: {ex.Message}"); }
    }
}
