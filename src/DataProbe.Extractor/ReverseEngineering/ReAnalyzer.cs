using System.Text;
using DataProbe.Core;
using DataProbe.Core.Plugin;

namespace DataProbe.Extractor.ReverseEngineering;

/// <summary>
/// 逆向分析引擎 — 对目标文件（APK/IPA/DLL/EXE）自动执行静态分析，
/// 提取 API 端点、检测安全防护、识别加密算法。
///
/// 支持插件扩展：PluginManager 中注册的 IReScannerPlugin 自动参与分析。
///
/// 分析流水线：
///   输入文件 → 类型检测 → 并行扫描器（内置 + 插件）→ 聚合报告
/// </summary>
public class ReAnalyzer
{
    private readonly List<IReScanner> _scanners = new();
    private readonly PluginManager? _pluginManager;

    public ReAnalyzer(PluginManager? pluginManager = null)
    {
        _pluginManager = pluginManager;

        // 注册内置扫描器
        _scanners.Add(new StringScanner());
        _scanners.Add(new CertPinningDetector());
        _scanners.Add(new AntiEmulatorDetector());
    }

    /// <summary>
    /// 分析目标文件并增强 TargetProfile
    /// </summary>
    public void Analyze(byte[] fileData, TargetProfile profile)
    {
        if (fileData == null || fileData.Length < 4) return;

        var fileType = DetectFileType(fileData);
        Console.Error.WriteLine($"[RE] File type: {fileType}, size: {fileData.Length} bytes");

        // 1) 运行内置扫描器
        foreach (var scanner in _scanners)
        {
            var findings = scanner.Scan(fileData, fileType);
            ApplyFindings(findings, profile);
        }

        // 2) 运行插件扫描器（按目标筛选）
        if (_pluginManager != null)
        {
            var pluginScanners = _pluginManager.GetPlugins<IReScannerPlugin>()
                .Where(s => s.CanAnalyze(fileType, fileData)).ToArray();
            foreach (var plugin in pluginScanners)
            {
                try
                {
                    var findings = plugin.Scan(fileData, fileType);
                    Console.Error.WriteLine($"[RE] Plugin scanner '{plugin.Name}' found {findings.Length} items");
                    ApplyFindings(findings, profile);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[RE] Plugin scanner '{plugin.Name}' error: {ex.Message}");
                }
            }
        }
    }

    /// <summary>注册自定义扫描器</summary>
    public void RegisterScanner(IReScanner scanner)
    {
        _scanners.Add(scanner);
    }

    private void ApplyFindings(ReFinding[] findings, TargetProfile profile)
    {
        foreach (var finding in findings)
        {
            switch (finding.Category)
            {
                case FindingCategory.CertPinning:
                    profile.HasCertPinning = true;
                    profile.PinningLibrary = finding.Detail;
                    break;
                case FindingCategory.AntiEmulator:
                    profile.HasAntiEmulator = true;
                    profile.AntiEmulatorMethods = finding.Detail;
                    break;
                case FindingCategory.ApiEndpoint:
                    profile.APIEndpoints = profile.APIEndpoints.Append(finding.Value).ToArray();
                    break;
                case FindingCategory.HardcodedToken:
                    profile.HardcodedTokens = profile.HardcodedTokens.Append(finding.Value).ToArray();
                    break;
                case FindingCategory.SdkDetected:
                    profile.DetectedSDKs = profile.DetectedSDKs.Append(finding.Value).ToArray();
                    break;
                case FindingCategory.UrlScheme:
                    profile.URLSchemes = profile.URLSchemes.Append(finding.Value).ToArray();
                    break;
            }
        }
    }

    /// <summary>检测文件类型（基于魔数）</summary>
    public static string DetectFileType(byte[] data)
    {
        if (data.Length < 4) return "unknown";

        // ZIP/APK (PK\x03\x04)
        if (data[0] == 0x50 && data[1] == 0x4B)
        {
            // 检查是否有 AndroidManifest.xml → APK
            var text = Encoding.ASCII.GetString(data);
            if (text.Contains("AndroidManifest"))
                return "apk";
            if (text.Contains("classes.dex"))
                return "apk";
            return "zip";
        }

        // PE (MZ)
        if (data[0] == 0x4D && data[1] == 0x5A)
            return "pe";

        // ELF (\x7FELF)
        if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46)
            return "elf";

        // IPA (ZIP with Payload)
        if (data[0] == 0x50 && data[1] == 0x4B)
        {
            var text = Encoding.ASCII.GetString(data);
            if (text.Contains("Payload") || text.Contains("Info.plist"))
                return "ipa";
        }

        return "unknown";
    }
}

/// <summary>扫描器接口</summary>
public interface IReScanner
{
    string Name { get; }
    ReFinding[] Scan(byte[] fileData, string fileType);
}

/// <summary>字符串扫描器 — 提取 URL/Token/Key</summary>
public class StringScanner : IReScanner
{
    public string Name => "StringScanner";

    private static readonly string[] UrlPatterns = {
        "https://", "http://", "wss://", "ws://"
    };

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        var findings = new List<ReFinding>();

        try
        {
            // 提取可打印字符串（长度 >= 6）
            var sb = new StringBuilder();
            for (int i = 0; i < fileData.Length; i++)
            {
                char c = (char)fileData[i];
                if (char.IsLetterOrDigit(c) || c == '/' || c == ':' || c == '.' ||
                    c == '_' || c == '-' || c == '=' || c == '@' || c == '&' || c == '?' ||
                    c == '#' || c == '%')
                {
                    sb.Append(c);
                }
                else
                {
                    if (sb.Length >= 6)
                        CheckString(sb.ToString(), findings);
                    sb.Clear();
                }
            }
        }
        catch { }

        return [.. findings];
    }

    private static void CheckString(string text, List<ReFinding> findings)
    {
        // URL 检测
        foreach (var prefix in UrlPatterns)
        {
            if (text.StartsWith(prefix))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.ApiEndpoint,
                    Value = text,
                    Detail = "URL endpoint",
                    Confidence = 0.9f
                });
                break;
            }
        }

        // JWT 检测
        if (text.StartsWith("eyJ") && text.Contains('.') && text.Length > 30)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.HardcodedToken,
                Value = Truncate(text, 80),
                Detail = "JWT token"
            });
        }

        // URL scheme 检测 (xxx://)
        var schemeIdx = text.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx > 0 && schemeIdx < 20 && text.Length < 200)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.UrlScheme,
                Value = text,
                Detail = "URL scheme"
            });
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}

/// <summary>证书锁定检测器</summary>
public class CertPinningDetector : IReScanner
{
    public string Name => "CertPinningDetector";

    private static readonly string[] PinningPatterns = {
        "CertificatePinner", "certificatePinner", "CERTIFICATE_PINNER",
        "TrustManager", "checkServerTrusted",
        "NSURLSession", "didReceiveChallenge",
        "ServerCertificateValidationCallback",
        "SslPolicyErrors", "ServicePointManager.ServerCertificateValidationCallback",
        "X509Certificate", "ca-cert", "cert_hash",
        "pinSha256", "publicKeyHash"
    };

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        var findings = new List<ReFinding>();
        var text = Encoding.ASCII.GetString(fileData);

        foreach (var pattern in PinningPatterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.CertPinning,
                    Value = pattern,
                    Detail = pattern,
                    Offset = idx,
                    Confidence = 0.8f
                });
            }
        }

        return findings.ToArray();
    }
}

/// <summary>反模拟器检测器</summary>
public class AntiEmulatorDetector : IReScanner
{
    public string Name => "AntiEmulatorDetector";

    private static readonly string[] AntiEmulatorPatterns = {
        "generic", "Build.FINGERPRINT", "TracerPid",
        "isDebuggerConnected", "getDeviceId",
        "ro.kernel.qemu", "ro.product.cpu.abi",
        "iMX6Q", "goldfish", "ranchu",
        "/system/bin/su", "Superuser.apk"
    };

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        var findings = new List<ReFinding>();
        if (fileType != "apk") return Array.Empty<ReFinding>();

        var text = Encoding.ASCII.GetString(fileData);
        var matchedMethods = new List<string>();

        foreach (var pattern in AntiEmulatorPatterns)
        {
            if (text.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                matchedMethods.Add(pattern);
        }

        if (matchedMethods.Count > 0)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.AntiEmulator,
                Value = string.Join(", ", matchedMethods),
                Detail = $"Detected {matchedMethods.Count} anti-emulator checks",
                Confidence = Math.Min(1.0f, matchedMethods.Count * 0.2f)
            });
        }

        return [.. findings];
    }
}
