using System.Text;
using System.Text.RegularExpressions;
using DataProbe.Core;
using DataProbe.Core.Plugin;

namespace DataProbe.Extractor.ReverseEngineering;

/// <summary>
/// WebAssembly 分析器 — 从目标文件（APK/JS/WASM）中检测并分析
/// WebAssembly 模块，提取导入导出、字符串常量、加密函数特征。
///
/// WASM 模块特征:
///   - 魔数: 0x00 0x61 0x73 0x6D (\0asm)
///   - 版本: 0x01 0x00 0x00 0x00
///   - 段类型: Type(1) / Import(2) / Function(3) / Memory(5) / Export(7)
///             Start(8) / Element(9) / Code(10) / Data(11)
///
/// 为什么 WASM 分析对数据提取重要:
///   - 越来越多的 App 将核心加密/解密逻辑编译到 WASM 中运行
///   - 传统字符串扫描 + Hook 对 WASM 内部逻辑无效
///   - 分析 WASM 可以找到加密函数、解密密钥、API 签名算法
/// </summary>
public class WasmAnalyzer : IReScanner
{
    public string Name => "WasmAnalyzer";

    // WASM 魔数 \0asm + 版本
    private static readonly byte[] WasmMagic = { 0x00, 0x61, 0x73, 0x6D };

    // WASM 段类型名称
    private static readonly Dictionary<byte, string> SectionNames = new()
    {
        [1] = "Type", [2] = "Import", [3] = "Function", [4] = "Table",
        [5] = "Memory", [6] = "Global", [7] = "Export",
        [8] = "Start", [9] = "Element", [10] = "Code", [11] = "Data",
        [12] = "DataCount", [0] = "Custom"
    };

    public ReFinding[] Scan(byte[] fileData, string fileType)
    {
        var findings = new List<ReFinding>();

        // 1) 直接检测 WASM 文件
        if (IsWasmFile(fileData))
        {
            findings.AddRange(AnalyzeWasm(fileData));
        }

        // 2) 在 APK/JS/ZIP 中查找内嵌的 WASM
        if (fileType is "apk" or "zip" or "js")
        {
            findings.AddRange(DetectEmbeddedWasm(fileData, fileType));
        }

        return [.. findings];
    }

    /// <summary>检测文件是否为 WASM</summary>
    private static bool IsWasmFile(byte[] data)
    {
        if (data.Length < 8) return false;
        return data[0] == WasmMagic[0] && data[1] == WasmMagic[1]
            && data[2] == WasmMagic[2] && data[3] == WasmMagic[3];
    }

    /// <summary>分析 WASM 模块结构</summary>
    private static List<ReFinding> AnalyzeWasm(byte[] wasmData)
    {
        var findings = new List<ReFinding>();
        findings.Add(new ReFinding
        {
            Category = FindingCategory.Custom,
            Value = "wasm_module",
            Detail = $"WASM module, {wasmData.Length} bytes",
            Confidence = 1.0f
        });

        int pos = 8; // 跳过魔数 + 版本

        // 解析各段
        while (pos < wasmData.Length)
        {
            if (pos + 1 > wasmData.Length) break;
            byte sectionId = wasmData[pos]; pos++;

            // LEB128 解码段长度
            if (!TryDecodeLeb128(wasmData, ref pos, out var sectionLen))
                break;

            var sectionName = SectionNames.GetValueOrDefault(sectionId, $"Section_{sectionId}");
            int sectionEnd = pos + sectionLen;
            if (sectionEnd > wasmData.Length) sectionEnd = wasmData.Length;

            switch (sectionId)
            {
                case 2: // Import 段 — 导入函数（外部依赖的关键信息）
                    findings.AddRange(ParseImportSection(wasmData, pos, sectionEnd));
                    break;

                case 7: // Export 段 — 导出函数（暴露给 JS 调用的接口）
                    findings.AddRange(ParseExportSection(wasmData, pos, sectionEnd));
                    break;

                case 11: // Data 段 — 内嵌数据（可能包含字符串常量）
                    findings.AddRange(ParseDataSection(wasmData, pos, sectionEnd));
                    break;

                case 0: // Custom 段 — 自定义元数据（可能是 source map）
                    // 跳过，不产生 findings
                    break;
            }

            pos = sectionEnd;
        }

        return findings;
    }

    /// <summary>解析 Import 段 — 检测导入的加密/SSL 相关函数</summary>
    private static List<ReFinding> ParseImportSection(byte[] data, int start, int end)
    {
        var findings = new List<ReFinding>();
        int pos = start;

        if (!TryDecodeLeb128(data, ref pos, out var count) || count == 0)
            return findings;

        for (int i = 0; i < count && pos < end; i++)
        {
            // module_len(LEB128) + module_str + name_len(LEB128) + name_str + import_kind(1)
            if (!TryDecodeLeb128(data, ref pos, out var modLen) || pos + modLen > end) break;
            var module = Encoding.UTF8.GetString(data, pos, modLen);
            pos += modLen;

            if (!TryDecodeLeb128(data, ref pos, out var nameLen) || pos + nameLen > end) break;
            var name = Encoding.UTF8.GetString(data, pos, nameLen);
            pos += nameLen;

            if (pos >= end) break;
            byte kind = data[pos]; pos++; // 0=function, 1=table, 2=mem, 3=global

            // 跳过 type_idx / table/mem/global 类型信息
            if (kind == 0 && pos + 1 <= end) { pos++; } // type_idx

            // 检测加密相关的导入
            if (name.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("decrypt", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("crypto", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("hash", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.CustomEncryption,
                    Value = $"{module}.{name}",
                    Detail = $"WASM import: {module}.{name}",
                    Confidence = 0.9f
                });
            }
        }

        return findings;
    }

    /// <summary>解析 Export 段 — 检测暴露给 JS 的 API</summary>
    private static List<ReFinding> ParseExportSection(byte[] data, int start, int end)
    {
        var findings = new List<ReFinding>();
        int pos = start;

        if (!TryDecodeLeb128(data, ref pos, out var count) || count == 0)
            return findings;

        for (int i = 0; i < count && pos < end; i++)
        {
            if (!TryDecodeLeb128(data, ref pos, out var nameLen) || pos + nameLen > end) break;
            var name = Encoding.UTF8.GetString(data, pos, nameLen);
            pos += nameLen;

            if (pos >= end) break;
            byte kind = data[pos]; pos++; // 0=func, 1=table, 2=mem, 3=global

            // index (LEB128)
            TryDecodeLeb128(data, ref pos, out _);

            // 检测敏感导出函数
            if (name.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("decrypt", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("sign", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("token", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.CustomEncryption,
                    Value = $"export:{name}",
                    Detail = $"WASM export: {name} (potential crypto function)",
                    Confidence = 0.85f
                });
            }
        }

        return findings;
    }

    /// <summary>解析 Data 段 — 提取字符串常量</summary>
    private static List<ReFinding> ParseDataSection(byte[] data, int start, int end)
    {
        var findings = new List<ReFinding>();
        int pos = start;

        if (!TryDecodeLeb128(data, ref pos, out var count) || count == 0)
            return findings;

        for (int i = 0; i < count && pos + 4 < end; i++)
        {
            // memory_index(LEB128) + offset_expr + data_len(LEB128) + data_bytes
            TryDecodeLeb128(data, ref pos, out _); // memory idx
            // skip init_expr (通常是一个 end 0x0B)
            while (pos < end && data[pos] != 0x0B) pos++;
            if (pos < end) pos++; // skip 0x0B

            if (!TryDecodeLeb128(data, ref pos, out var dataLen) || pos + dataLen > end)
                break;

            // 从 data bytes 中提取可读字符串
            var strings = ExtractReadableStrings(data, pos, dataLen);
            foreach (var str in strings.Where(s => s.Length >= 6))
            {
                // 检测 URL
                if (str.StartsWith("https://") || str.StartsWith("http://") || str.StartsWith("wss://"))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.ApiEndpoint,
                        Value = str.Length > 250 ? str[..250] : str,
                        Detail = "URL from WASM data section",
                        Confidence = 0.9f
                    });
                }

                // 检测可能的密钥/Token
                if (str.Length >= 20 && str.Any(c => !char.IsLetterOrDigit(c)))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.HardcodedToken,
                        Value = str.Length > 100 ? str[..100] : str,
                        Detail = "Potential key/token from WASM data",
                        Confidence = 0.7f
                    });
                }

                // API Key 前缀检测
                if (str.StartsWith("sk-") || str.StartsWith("pk-") || str.StartsWith("ak-"))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.HardcodedToken,
                        Value = str,
                        Detail = "API key from WASM",
                        Confidence = 0.9f
                    });
                }
            }

            pos += dataLen;
        }

        return findings;
    }

    /// <summary>在 APK/JS 中检测内嵌的 WASM 模块</summary>
    private static List<ReFinding> DetectEmbeddedWasm(byte[] data, string fileType)
    {
        var findings = new List<ReFinding>();

        // 搜索 \0asm 魔数
        var wasmStarts = new List<int>();
        for (int i = 0; i < data.Length - 4; i++)
        {
            if (data[i] == 0x00 && data[i + 1] == 0x61 && data[i + 2] == 0x73 && data[i + 3] == 0x6D)
            {
                wasmStarts.Add(i);
            }
        }

        // 搜索 'wasm' 字符串引用
        var text = Encoding.ASCII.GetString(data);
        var wasmRefs = new List<string>();
        foreach (Match m in System.Text.RegularExpressions.Regex.Matches(
            text, @"['""]([^'""]+\.wasm)['""]", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {
            wasmRefs.Add(m.Groups[1].Value);
        }

        if (wasmStarts.Count > 0 || wasmRefs.Count > 0)
        {
            findings.Add(new ReFinding
            {
                Category = FindingCategory.Custom,
                Value = $"wasm_detected",
                Detail = $"Found {wasmStarts.Count} embedded WASM modules, {wasmRefs.Count} WASM references",
                Confidence = 0.95f
            });

            foreach (var refName in wasmRefs.Take(10))
            {
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.Custom,
                    Value = $"wasm_ref:{refName}",
                    Detail = $"WASM file reference: {refName}",
                    Confidence = 0.9f
                });
            }

            // 分析第一个嵌入的 WASM 模块
            if (wasmStarts.Count > 0)
            {
                var firstWasm = data.Skip(wasmStarts[0]).Take(Math.Min(data.Length - wasmStarts[0], 200000)).ToArray();
                findings.AddRange(AnalyzeWasm(firstWasm));
            }
        }

        return findings;
    }

    /// <summary>从字节范围中提取可读字符串</summary>
    private static List<string> ExtractReadableStrings(byte[] data, int offset, int length)
    {
        var strings = new List<string>();
        var sb = new StringBuilder();
        int end = offset + length;

        for (int i = offset; i < end; i++)
        {
            char c = (char)data[i];
            if (char.IsLetterOrDigit(c) || c is '/' or ':' or '.' or '_' or '-'
                or '=' or '@' or '&' or '?' or '#' or '%' or '+' or '~')
            {
                sb.Append(c);
            }
            else
            {
                if (sb.Length >= 4)
                    strings.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= 4)
            strings.Add(sb.ToString());

        return strings;
    }

    /// <summary>LEB128 解码（WASM 使用的可变长整数编码）</summary>
    private static bool TryDecodeLeb128(byte[] data, ref int pos, out int value)
    {
        value = 0;
        int shift = 0;
        int start = pos;

        while (pos < data.Length)
        {
            byte b = data[pos];
            value |= (b & 0x7F) << shift;
            shift += 7;
            pos++;

            if ((b & 0x80) == 0) return true;
            if (shift >= 35) break; // 安全限制
        }

        pos = start;
        return false;
    }
}
