using System.Text;
using DataProbe.Core;
using DataProbe.Core.Plugin;

namespace DataProbe.Extractor.ReverseEngineering;

/// <summary>
/// PE 导入表扫描器 — 解析 Windows PE (Portable Executable) 文件，
/// 提取 DLL 依赖、导入函数、检测反作弊驱动和 SSL 库。
///
/// PE 结构:
///   DOS 头 (64 bytes) → e_lfanew → NT 头 → 节表 → 导入表
///
/// 检测目标:
///   - SSL 库: libssl-*.dll, ssleay32.dll, libcurl.dll
///   - 反作弊: ace.dll, tensafe.dll, eac.dll, battleye.dll
///   - 网络库: winhttp.dll, wininet.dll, libcurl.dll, websocket.dll
///   - 运行时: mscoree.dll (.NET), mono-2.0-sgen.dll (Unity)
/// </summary>
public class PeImportScanner : IReScanner
{
    public string Name => "PeImportScanner";

    // 已知反作弊 DLL 特征
    private static readonly HashSet<string> AntiCheatDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "ace.dll", "ace_core.dll", "aceguard.dll",
        "tensafe.dll", "tenprotect.dll", "tpshield.dll",
        "eac.dll", "easyanticheat.dll", "eac_service.dll",
        "battleye.dll", "beservice.dll", "belauncher.dll",
        "mhyprot.dll", "mhyp.dll", "mhyprot2.sys",
        "npggNT.dll", "nprotect.dll", "gameguard.dll",
        "xigncode.dll", "x3.xem", "xcorona.xem",
        "hlguard.dll", "cheatingdead.dll"
    };

    // SSL/TLS 库特征
    private static readonly HashSet<string> SslDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "libssl-1_1.dll", "libssl-1_1-x64.dll", "libssl-3.dll", "libssl-3-x64.dll",
        "ssleay32.dll", "libeay32.dll",
        "libcurl.dll", "curl.dll",
        "winhttp.dll", "wininet.dll"
    };

    // 运行时特征
    private static readonly HashSet<string> RuntimeDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "mscoree.dll", "clr.dll",          // .NET Framework
        "mono-2.0-sgen.dll", "mono.dll",   // Mono / Unity
        "coreclr.dll",                     // .NET Core
        "v8.dll", "libcef.dll",            // Chromium/CEF
        "node.dll",                        // Node.js
        "python3.dll", "python39.dll"       // Python embedded
    };

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        if (fileType != "pe" && fileType != "dll" && fileType != "exe") return [];
        if (fileData.Length < 64) return [];

        var findings = new List<ReFinding>();

        try
        {
            // 1) 校验 DOS 头
            if (fileData[0] != 0x4D || fileData[1] != 0x5A) return []; // "MZ"

            // 2) 定位 NT 头
            int e_lfanew = BitConverter.ToInt32(fileData, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 4 >= fileData.Length) return [];

            // 3) 校验 NT 头签名
            if (fileData[e_lfanew] != 0x50 || fileData[e_lfanew + 1] != 0x45) return []; // "PE\0\0"

            // 4) 解析架构
            var machine = BitConverter.ToUInt16(fileData, e_lfanew + 4);
            var is64Bit = machine == 0x8664; // AMD64
            findings.Add(new ReFinding
            {
                Category = FindingCategory.Custom,
                Value = is64Bit ? "x64" : "x86",
                Detail = "PE architecture",
                Confidence = 1.0f
            });

            // 5) 解析导入表
            int importOffset = is64Bit
                ? BitConverter.ToInt32(fileData, e_lfanew + 0x90) // IMAGE_DIRECTORY_ENTRY_IMPORT
                : BitConverter.ToInt32(fileData, e_lfanew + 0x80);
            int importSize = is64Bit
                ? BitConverter.ToInt32(fileData, e_lfanew + 0x94)
                : BitConverter.ToInt32(fileData, e_lfanew + 0x84);

            if (importOffset > 0 && importOffset < fileData.Length)
            {
                var imports = ParseImportTable(fileData, importOffset, importSize);
                findings.AddRange(AnalyzeImports(imports));
            }

            // 6) 可打印字符串扫描（补充导入表中没有的信息）
            findings.AddRange(ScanStrings(fileData));

            // 7) 检测 .NET 特征
            var text = Encoding.ASCII.GetString(fileData);
            if (text.Contains("mscorlib") || text.Contains("System.Windows.Forms"))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.SdkDetected,
                    Value = ".NET Framework",
                    Detail = ".NET application detected",
                    Confidence = 0.9f
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.Custom,
                Value = $"pe_parse_error: {ex.Message}",
                Detail = "Failed to parse PE",
                Confidence = 0.3f
            });
        }

        return [.. findings];
    }

    /// <summary>解析导入表</summary>
    private static List<(string DllName, string FunctionName)> ParseImportTable(
        byte[] data, int offset, int size)
    {
        var imports = new List<(string, string)>();

        int entry = offset;
        while (entry + 20 <= data.Length)
        {
            // 导入描述符: OriginalFirstThunk(8) + TimeDateStamp(4) + ForwarderChain(4)
            //             + Name(8) + FirstThunk(8)
            int nameRva = BitConverter.ToInt32(data, entry + 12);
            int firstThunk = BitConverter.ToInt32(data, entry + 16);

            if (nameRva == 0 && firstThunk == 0) break; // 结束标志

            // 获取 DLL 名称
            var dllName = ReadRvaString(data, nameRva);
            if (string.IsNullOrEmpty(dllName)) { entry += 20; continue; }

            // 遍历 INT (Import Name Table)
            if (firstThunk > 0 && firstThunk < data.Length)
            {
                int thunkEntry = firstThunk;
                while (thunkEntry + 8 <= data.Length)
                {
                    ulong thunk = BitConverter.ToUInt64(data, thunkEntry);
                    if (thunk == 0) break;
                    thunkEntry += 8;

                    // 检查是否按序号导入 (高位为1)
                    if ((thunk & 0x8000000000000000) != 0) continue;

                    int funcNameRva = (int)(thunk & 0x7FFFFFFF);
                    if (funcNameRva > 0 && funcNameRva < data.Length)
                    {
                        var funcName = ReadRvaString(data, funcNameRva);
                        if (!string.IsNullOrEmpty(funcName))
                            imports.Add((dllName, funcName));
                    }
                }
            }

            entry += 20;
        }

        return imports;
    }

    /// <summary>分析导入表，检测安全相关 DLL</summary>
    private static List<ReFinding> AnalyzeImports(List<(string DllName, string FunctionName)> imports)
    {
        var findings = new List<ReFinding>();
        var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (dll, func) in imports)
        {
            var dllLower = dll.ToLower();
            dlls.Add(dllLower);

            // 反作弊 DLL 检测
            if (AntiCheatDlls.Contains(dllLower))
            {
                if (!findings.Any(f => f.Value.Contains(dll)))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.AntiCheat,
                        Value = $"anti_cheat: {dll}",
                        Detail = $"Anti-cheat DLL detected: {dll}",
                        Confidence = 0.95f
                    });
                }
            }

            // SSL 库检测
            if (SslDlls.Contains(dllLower))
            {
                if (!findings.Any(f => f.Value.Contains(dll)))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.CustomEncryption,
                        Value = $"ssl_lib: {dll}",
                        Detail = $"SSL/TLS library: {dll}",
                        Confidence = 0.9f
                    });
                }
            }

            // 运行时检测
            if (RuntimeDlls.Contains(dllLower))
            {
                if (!findings.Any(f => f.Value.Contains(dll)))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.SdkDetected,
                        Value = $"runtime: {dll}",
                        Detail = $"Runtime detected: {dll}",
                        Confidence = 0.9f
                    });
                }
            }
        }

        // WinDivert 检测
        if (dlls.Contains("windivert.dll"))
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.Custom,
                Value = "windivert detected",
                Detail = "Target uses WinDivert (packet capture)",
                Confidence = 0.8f
            });
        }

        return findings;
    }

    /// <summary>从 PE 文件中提取有用的字符串</summary>
    private static List<ReFinding> ScanStrings(byte[] data)
    {
        var findings = new List<ReFinding>();
        var sb = new StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            var c = (char)data[i];
            if (char.IsLetterOrDigit(c) || c is '/' or ':' or '.' or '_' or '-' or '=' or '@')
            {
                sb.Append(c);
            }
            else
            {
                var str = sb.ToString();
                if (str.Length >= 10)
                {
                    if (str.StartsWith("https://") || str.StartsWith("http://"))
                    {
                        findings.Add(new ReFinding
                        {
                            Category = FindingCategory.ApiEndpoint,
                            Value = str.Length > 250 ? str[..250] : str,
                            Detail = "URL from PE string table",
                            Confidence = 0.9f
                        });
                    }
                }
                sb.Clear();
            }
        }

        return findings;
    }

    /// <summary>从 RVA (Relative Virtual Address) 读取字符串</summary>
    private static string ReadRvaString(byte[] data, int rva)
    {
        if (rva <= 0 || rva >= data.Length) return "";
        int end = rva;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data[rva..end]);
    }
}
