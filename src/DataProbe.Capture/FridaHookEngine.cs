using System.Diagnostics;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// Frida Hook 引擎 — 调用外部 Python 脚本 (frida_hook.py)
/// 通过 Frida 注入目标进程，Hook SSL 函数，回传明文数据。
///
/// 不需要任何 C++ 编译器。依赖 Python + frida 包。
/// </summary>
public class FridaHookEngine
{
    private Process? _pythonProcess;
    private bool _isRunning;
    private string? _scriptPath;

    /// <summary>Hook 数据接收事件</summary>
    public event Action<NormalizedTransaction>? OnTransactionCaptured;

    public bool IsRunning => _isRunning;

    /// <summary>Python 路径</summary>
    public string PythonPath { get; set; } = "python";

    /// <summary>
    /// 注入目标进程
    /// </summary>
    public async Task<bool> InjectAsync(string processName, string pipeName = "DataProbeHookPipe")
    {
        if (_isRunning) return true;

        try
        {
            // 定位 frida_hook.py
            _scriptPath = FindScript();
            if (_scriptPath == null)
            {
                Console.Error.WriteLine("[FridaHook] frida_hook.py not found");
                return false;
            }

            var psi = new ProcessStartInfo
            {
                FileName = PythonPath,
                Arguments = $"\"{_scriptPath}\" {processName}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                EnvironmentVariables = { ["PYTHONUNBUFFERED"] = "1" }
            };

            _pythonProcess = new Process { StartInfo = psi };
            _pythonProcess.Start();

            // 异步读取输出
            _ = Task.Run(() => ReadOutputAsync(_pythonProcess));

            // 等待 attach 确认
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 5000 && !_pythonProcess.HasExited)
            {
                await Task.Delay(100);
            }

            _isRunning = !_pythonProcess.HasExited;
            if (_isRunning)
                Console.Error.WriteLine($"[FridaHook] Attached to {processName}");
            else
                Console.Error.WriteLine("[FridaHook] Process exited early");

            return _isRunning;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FridaHook] Inject failed: {ex.Message}");
            return false;
        }
    }

    public async Task StopAsync()
    {
        if (!_isRunning) return;
        try
        {
            if (_pythonProcess != null && !_pythonProcess.HasExited)
            {
                _pythonProcess.Kill();
                await _pythonProcess.WaitForExitAsync();
            }
        }
        catch { }
        _isRunning = false;
        Console.Error.WriteLine("[FridaHook] Stopped");
    }

    private static string? FindScript()
    {
        // 搜索可能的路径
        var candidates = new[]
        {
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "frida_hook.py"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..",
                         "DataProbe.Capture", "frida_hook.py"),
            Path.Combine(Directory.GetCurrentDirectory(), "frida_hook.py"),
            "frida_hook.py"
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private async Task ReadOutputAsync(Process process)
    {
        try
        {
            while (!process.HasExited)
            {
                var line = await process.StandardOutput.ReadLineAsync();
                if (line == null) break;

                if (line.Contains("\"status\":\"attached\""))
                    Console.Error.WriteLine("[FridaHook] ✅ Attached");
                else if (line.Contains("\"status\":\"error\""))
                    Console.Error.WriteLine($"[FridaHook] ❌ {line}");
                else
                    Console.Error.WriteLine($"[FridaHook] {line}");
            }

            var error = await process.StandardError.ReadToEndAsync();
            if (!string.IsNullOrEmpty(error))
                Console.Error.WriteLine($"[FridaHook] Stderr: {error}");
        }
        catch { }
    }

    public void Dispose() => StopAsync().GetAwaiter().GetResult();
}
