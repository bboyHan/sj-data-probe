using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using DataProbe.Core;
using DataProbe.Core.Plugin;

namespace DataProbe.Extractor.ReverseEngineering;

/// <summary>
/// APK Manifest 扫描器 — 解包 APK，解析 AndroidManifest.xml，
/// 提取包名、Activity、Service、权限、Intent Filter、API 端点。
///
/// APK = ZIP 文件，内含:
///   AndroidManifest.xml — 二进制 XML (AXML)，描述 App 结构
///   classes.dex         — DEX 字节码（可反编译为字符串池）
///   res/                — 资源文件
///   lib/                — 原生库 (.so)
///   assets/             — 资产文件（可能有 JS bundle）
///
/// Phase 5 V2 实现:
///   V1: ZIP 解包 + 文件名扫描 (当前 ✅)
///   V2: AndroidManifest AXML 解析 (本文件)
///   V3: DEX 字符串池提取 (待实现)
/// </summary>
public class ApkManifestScanner : IReScanner
{
    public string Name => "ApkManifestScanner";

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        if (fileType != "apk") return [];
        if (fileData.Length < 4) return [];

        var findings = new List<ReFinding>();

        try
        {
            using var ms = new MemoryStream(fileData);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            // 1) 列出 APK 结构
            var entries = archive.Entries.Select(e => e.FullName).ToArray();

            // 2) 解压并解析 AndroidManifest.xml（二进制 AXML）
            var manifestEntry = archive.GetEntry("AndroidManifest.xml");
            if (manifestEntry != null)
            {
                using var manifestStream = manifestEntry.Open();
                var manifestBytes = new byte[manifestEntry.Length];
                manifestStream.Read(manifestBytes, 0, (int)manifestEntry.Length);

                var manifestText = ParseBinaryXml(manifestBytes);
                findings.AddRange(AnalyzeManifest(manifestText));
            }

            // 3) 从 DEX 中提取字符串常量
            var dexEntries = archive.Entries.Where(e => e.Name.EndsWith(".dex")).ToArray();
            foreach (var dexEntry in dexEntries)
            {
                using var dexStream = dexEntry.Open();
                var dexBytes = new byte[dexEntry.Length];
                dexStream.Read(dexBytes, 0, (int)dexEntry.Length);

                findings.AddRange(ExtractDexStrings(dexBytes));
            }

            // 4) 扫描 lib/ 下的原生库
            var libs = entries.Where(e => e.StartsWith("lib/") && e.EndsWith(".so"))
                .Select(e => Path.GetFileName(e))
                .Distinct()
                .ToArray();
            if (libs.Length > 0)
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.SdkDetected,
                    Value = $"native_libs: {string.Join(", ", libs)}",
                    Detail = "Native libraries detected",
                    Confidence = 0.9f
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.Custom,
                Value = $"apk_parse_error: {ex.Message}",
                Detail = "Failed to parse APK",
                Confidence = 0.3f
            });
        }

        return [.. findings];
    }

    /// <summary>解析二进制 AndroidManifest.xml（AXML）为纯文本</summary>
    private static string ParseBinaryXml(byte[] data)
    {
        if (data.Length < 8) return "";

        // AXML 格式: 头部 + 字符串池 + XML 节点树
        // 简化解法：从二进制中提取所有可打印字符串
        // 完整 AXML 解析器需专门实现（复杂，涉及 chunk 类型和资源引用）
        var sb = new StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            // 跳过头部的 0x00080003 magic
            if (i + 1 < data.Length && data[i] == 0x00 && data[i + 1] == 0x08)
                continue;

            // 提取 UTF-16 字符串（Android 使用 UTF-16LE 编码）
            if (i + 1 < data.Length && data[i] != 0 && data[i + 1] == 0)
            {
                var text = ReadUtf16String(data, i, out var consumed);
                if (text.Length >= 3)
                {
                    sb.AppendLine(text);
                    i += consumed;
                }
            }
        }

        return sb.ToString();
    }

    private static string ReadUtf16String(byte[] data, int start, out int consumed)
    {
        var chars = new List<byte>();
        int i = start;
        while (i + 1 < data.Length)
        {
            if (data[i] == 0 && data[i + 1] == 0) break;
            if (data[i + 1] == 0 && data[i] >= 0x20 && data[i] <= 0x7E)
                chars.Add(data[i]);
            i += 2;
        }
        consumed = i - start + 2;
        return Encoding.ASCII.GetString(chars.ToArray());
    }

    /// <summary>分析 AndroidManifest 文本内容</summary>
    private static List<ReFinding> AnalyzeManifest(string manifestText)
    {
        var findings = new List<ReFinding>();

        // 包名
        var pkg = Regex.Match(manifestText, @"package\s*=\s*""([^""]+)""");
        if (pkg.Success)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.ApiEndpoint,
                Value = pkg.Groups[1].Value,
                Detail = "APK package name",
                Confidence = 1.0f
            });
        }

        // Activity / Service / Receiver
        foreach (Match m in Regex.Matches(manifestText, @"(activity|service|receiver|provider)\s*=\s*""([^""]+)"""))
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.ApiEndpoint,
                Value = m.Groups[2].Value,
                Detail = $"Android component: {m.Groups[1].Value}",
                Confidence = 0.9f
            });
        }

        // Intent-filter action
        foreach (Match m in Regex.Matches(manifestText, @"action\s*=\s*""([^""]+)"""))
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.UrlScheme,
                Value = m.Groups[1].Value,
                Detail = "Intent action",
                Confidence = 0.8f
            });
        }

        // 自定义 URL Scheme (android:scheme)
        foreach (Match m in Regex.Matches(manifestText, @"scheme\s*=\s*""([a-zA-Z][a-zA-Z0-9.+-]+)"""))
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.UrlScheme,
                Value = $"{m.Groups[1].Value}://",
                Detail = "URL scheme",
                Confidence = 0.9f
            });
        }

        // 权限
        foreach (Match m in Regex.Matches(manifestText, @"permission\s*=\s*""([^""]+)"""))
        {
            var perm = m.Groups[1].Value;
            if (perm.Contains("INTERNET") || perm.Contains("NETWORK") || perm.Contains("CAMERA") ||
                perm.Contains("RECORD_AUDIO") || perm.Contains("ACCESS_FINE_LOCATION"))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.Custom,
                    Value = perm,
                    Detail = "Sensitive permission",
                    Confidence = 0.8f
                });
            }
        }

        return findings;
    }

    /// <summary>从 DEX 文件中提取可打印字符串</summary>
    private static List<ReFinding> ExtractDexStrings(byte[] dexData)
    {
        var findings = new List<ReFinding>();

        // DEX 文件: header(112 bytes) + string_ids + ...
        // string_ids 区域包含所有字符串常量的偏移
        if (dexData.Length < 112) return [];
        if (dexData[0] != 0x64 || dexData[1] != 0x65 || dexData[2] != 0x79) return []; // "dex\0"

        int stringIdsOffset = BitConverter.ToInt32(dexData, 0x20); // string_ids_off
        int stringIdsCount = BitConverter.ToInt32(dexData, 0x38); // string_ids_size

        if (stringIdsOffset <= 0 || stringIdsCount <= 0 || stringIdsOffset > dexData.Length - 4)
            return [];

        var urls = new HashSet<string>();

        for (int i = 0; i < Math.Min(stringIdsCount, 5000); i++)
        {
            int offset = stringIdsOffset + i * 4;
            if (offset + 4 > dexData.Length) break;

            int strOffset = BitConverter.ToInt32(dexData, offset);
            if (strOffset <= 0 || strOffset >= dexData.Length) continue;

            // 读取 UTF-8/UTF-16 字符串
            var str = ReadDexString(dexData, strOffset);
            if (string.IsNullOrEmpty(str) || str.Length < 8) continue;

            // 检测 URL
            if (str.StartsWith("https://") || str.StartsWith("http://") || str.StartsWith("wss://"))
            {
                if (urls.Add(str))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.ApiEndpoint,
                        Value = str.Length > 200 ? str[..200] : str,
                        Detail = "API endpoint from DEX",
                        Confidence = 0.95f
                    });
                }
            }

            // 检测证书锁定
            if (str.Contains("CertificatePinner", StringComparison.Ordinal) ||
                str.Contains("sha256/", StringComparison.Ordinal))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.CertPinning,
                    Value = str,
                    Detail = "Certificate pinning from DEX"
                });
            }
        }

        return findings;
    }

    private static string ReadDexString(byte[] data, int offset)
    {
        try
        {
            // ULEB128 编码的字符串长度
            int pos = offset;
            int len = 0;
            int shift = 0;
            while (pos < data.Length)
            {
                len |= (data[pos] & 0x7F) << shift;
                if ((data[pos] & 0x80) == 0) { pos++; break; }
                shift += 7;
                pos++;
            }

            if (pos + len > data.Length) return "";
            return Encoding.UTF8.GetString(data, pos, len);
        }
        catch { return ""; }
    }
}
