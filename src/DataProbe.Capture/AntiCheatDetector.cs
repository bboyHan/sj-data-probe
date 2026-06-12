using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 反作弊检测器（增强版）— 扫描系统进程、驱动、内核模块，
/// 检测已知反作弊系统。结果影响 ADE 的通道选择策略。
/// </summary>
public class AntiCheatDetector
{
    private readonly HashSet<string> _knownAntiCheatProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "ace", "ace-core", "aceguard", "ace-sys", "aceservice",
        "tensafe", "tenprotect", "tp3", "tp3helper",
        "eac", "easyanticheat", "eac_service", "eac_launcher",
        "battleye", "beservice", "belauncher", "beyondeyechina",
        "nprotect", "npgg", "npggnt", "gameguard", "gamemons",
        "mhyprot", "mhyp", "mhyprot2", "mhyprot3",
        "xigncode", "x3", "xcorona",
        "facehugger", "fhservice",
        "denuvo", "denuvoservice",
        "vmprotect", "vmp"
    };

    private readonly HashSet<string> _knownAntiCheatDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        "ace.sys", "acedrv.sys", "acedrv64.sys",
        "tpd.sys", "tensafe.sys",
        "eac.sys", "easyanticheat.sys",
        "battleye.sys", "bedaisy.sys",
        "npgg.sys", "npggnt.sys", "gameguard.sys",
        "mhyprot.sys", "mhyprot2.sys", "mhyprot3.sys",
        "xigncode.sys", "x3.sys",
        "vmprot.sys", "vmprot64.sys"
    };

    private AntiCheatLevel? _cachedLevel;
    private string[]? _cachedDetections;

    /// <summary>检测所有正在运行的反作弊</summary>
    public AntiCheatInfo Scan(int targetProcessId = 0)
    {
        var detected = new List<string>();
        var level = AntiCheatLevel.None;

        try
        {
            // 1) 扫描进程列表
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLower();
                    if (_knownAntiCheatProcesses.Contains(name))
                    {
                        detected.Add($"process:{name} (PID {proc.Id})");
                        level = MaxLevel(level, GetLevelForProcess(name));
                    }
                }
                catch { }
            }

            // 2) 扫描目标进程的模块（如果有）
            if (targetProcessId > 0)
            {
                try
                {
                    var target = System.Diagnostics.Process.GetProcessById(targetProcessId);
                    foreach (System.Diagnostics.ProcessModule module in target.Modules)
                    {
                        var modName = module.ModuleName?.ToLower() ?? "";
                        if (_knownAntiCheatDrivers.Contains(modName))
                        {
                            detected.Add($"module:{modName}");
                            level = MaxLevel(level, AntiCheatLevel.Kernel);
                        }
                    }
                }
                catch { }
            }

            // 3) 扫描常见驱动文件路径
            var driverPaths = new[]
            {
                @"C:\Windows\System32\drivers", @"C:\Windows\SysWOW64\drivers"
            };
            foreach (var dir in driverPaths.Where(Directory.Exists))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.sys"))
                    {
                        var name = Path.GetFileName(file).ToLower();
                        if (_knownAntiCheatDrivers.Contains(name))
                        {
                            detected.Add($"driver:{name}");
                            level = MaxLevel(level, AntiCheatLevel.Kernel);
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        _cachedLevel = level;
        _cachedDetections = detected.ToArray();

        Console.Error.WriteLine($"[AntiCheat] Level: {level}, Detected: {detected.Count}");
        return new AntiCheatInfo { Level = level, Detections = detected.ToArray() };
    }

    /// <summary>清除缓存，下次 Scan 重新检测</summary>
    public void ResetCache()
    {
        _cachedLevel = null;
        _cachedDetections = null;
    }

    private static AntiCheatLevel GetLevelForProcess(string name) => name switch
    {
        "ace" or "aceguard" or "aceservice" => AntiCheatLevel.Kernel,
        "tensafe" or "tenprotect" => AntiCheatLevel.Kernel,
        "eac" or "easyanticheat" => AntiCheatLevel.Kernel,
        "battleye" or "beservice" => AntiCheatLevel.Kernel,
        "mhyprot" or "mhyprot2" => AntiCheatLevel.Kernel,
        "nprotect" or "npgg" => AntiCheatLevel.Kernel,
        _ => AntiCheatLevel.User
    };

    private static AntiCheatLevel MaxLevel(AntiCheatLevel a, AntiCheatLevel b) =>
        a > b ? a : b;
}

public class AntiCheatInfo
{
    public AntiCheatLevel Level { get; set; } = AntiCheatLevel.None;
    public string[] Detections { get; set; } = Array.Empty<string>();
}

public enum AntiCheatLevel
{
    None,       // 无反作弊
    User,       // 用户态反作弊（有限检测）
    Kernel,     // 内核态反作弊（驱动级别）
    Hypervisor  // 硬件级反作弊（极少见）
}
