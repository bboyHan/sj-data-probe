using System.Diagnostics;
using System.Runtime.InteropServices;
using DataProbe.Core;
using DataProbe.Core.TlsFingerprint;

namespace DataProbe.Capture;

/// <summary>
/// 进程内存 TLS 密钥扫描器 — 路径二。
///
/// 原理:
///   OpenSSL 1.1.x / 3.x 的 SSL_SESSION 结构体在进程内存中包含 master_key。
///   通过 ReadProcessMemory 扫描目标进程堆，搜索 SSL_SESSION 特征。
///
/// 特征:
///   OpenSSL SSL_SESSION 结构有固定的 layout:
///   - session_id (32 bytes)
///   - master_key (48 bytes for TLS 1.2)
///   - session_id_length (int)
///   - master_key_length (int)
///
/// 不注入、不 Hook、不改目标进程内存。
/// 只读扫描，对被扫描进程零影响。
/// </summary>
public class MemoryKeyScanner : IPassiveKeyProvider
{
    public string Name => "MemoryScanner";

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

    public bool IsRunning => _scanCts != null && !_scanCts.IsCancellationRequested;

    public event Action<SslKeyEntry>? OnKeyCaptured;

    private CancellationTokenSource? _scanCts;
    private readonly List<string> _targetProcesses = new() { "chrome", "msedge", "firefox", "explorer" };

    /// <summary>添加要扫描的目标进程</summary>
    public void AddTarget(string processName) => _targetProcesses.Add(processName);

    public Task StartAsync(CancellationToken ct = default)
    {
        if (!IsAvailable) { Console.Error.WriteLine("[MemoryScan] Requires Admin"); return Task.CompletedTask; }

        _scanCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _ = Task.Run(() => ScanLoop(_scanCts.Token), _scanCts.Token);
        Console.Error.WriteLine("[MemoryScan] Started");
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _scanCts?.Cancel();
        _scanCts = null;
        Console.Error.WriteLine("[MemoryScan] Stopped");
        return Task.CompletedTask;
    }

    private async Task ScanLoop(CancellationToken ct)
    {
        var skipCache = new HashSet<string>(); // 已提取过的 key 不做第二次

        while (!ct.IsCancellationRequested)
        {
            try
            {
                foreach (var processName in _targetProcesses)
                {
                    if (ct.IsCancellationRequested) break;

                    var processes = Process.GetProcessesByName(processName);
                    foreach (var proc in processes.Take(3)) // 最多扫 3 个同进程
                    {
                        if (ct.IsCancellationRequested) break;
                        try
                        {
                            var keys = ScanProcessMemory(proc);
                            foreach (var key in keys)
                            {
                                if (skipCache.Add($"{key.ClientRandom}:{key.MasterKey}"))
                                {
                                    OnKeyCaptured?.Invoke(key);
                                    Console.Error.WriteLine($"[MemoryScan] 🔑 Key from {processName}: {key.ClientRandom[..Math.Min(16, key.ClientRandom.Length)]}...");
                                }
                            }
                        }
                        catch { } // 跳过无权访问的进程
                        finally { proc.Dispose(); }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[MemoryScan] Loop error: {ex.Message}");
            }

            await Task.Delay(5000, ct); // 每 5 秒扫一次
        }
    }

    /// <summary>
    /// 扫描目标进程内存中的 TLS 会话密钥
    /// </summary>
    private static List<SslKeyEntry> ScanProcessMemory(Process proc)
    {
        var keys = new List<SslKeyEntry>();
        var handle = proc.Handle;

        // 查询进程内存信息
        nint address = nint.Zero;
        while (WinApi.VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<WinApi.MEMORY_BASIC_INFORMATION>()) != 0)
        {
            if ((uint)mbi.State != 0x1000 /* MEM_COMMIT */ || (uint)mbi.Protect == 0x01 /* NOACCESS */)
            {
                address = mbi.BaseAddress + (nint)mbi.RegionSize;
                continue;
            }

            // 读取可读内存页
            var buffer = new byte[(int)Math.Min(mbi.RegionSize, 1024 * 1024)]; // 每页最多 1MB
            if (!WinApi.ReadProcessMemory(handle, mbi.BaseAddress, buffer, buffer.Length, out var bytesRead))
            {
                address = mbi.BaseAddress + (nint)mbi.RegionSize;
                continue;
            }

            // 搜索 SSL_SESSION.master_key 特征
            keys.AddRange(ScanBufferForMasterKeys(buffer, (long)mbi.BaseAddress));

            address = mbi.BaseAddress + (nint)mbi.RegionSize;
        }

        return keys;
    }

    /// <summary>
    /// 在内存缓冲区中搜索 OpenSSL master_key 模式
    /// TLS 1.2 master_key: 48 字节随机数，通常在 SSL_SESSION 结构偏移 0x48-0x78
    /// Client Random: 32 字节，在 SSL 结构体中
    /// </summary>
    private static IEnumerable<SslKeyEntry> ScanBufferForMasterKeys(byte[] buffer, long baseAddr)
    {
        // 搜索 OpenSSL 的 SSL_SESSION_MAGIC 或其他标识
        // 这是一个简化的 PoC 实现
        // Phase 2 完整实现: 解析 SSL_SESSION 结构体的已知偏移
        yield break; // PoC 阶段：返回空，等待实际调试验证
    }
}

internal static class WinApi
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(nint hProcess, nint lpAddress,
        out WinApi.MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
