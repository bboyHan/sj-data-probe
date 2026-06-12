using DataProbe.Core;
using DataProbe.Core.Plugin;

namespace ExamplePlugin;

/// <summary>
/// DataProbe 示例插件 — 演示完整的插件生命周期。
///
/// 此插件功能：扫描 APK/DLL 中特定目标的 URL，
/// 当目标检测到 "example.com" 或 "target-app" 时，
/// 增强目标情报报告。
///
/// 编译:
///   dotnet build plugins/example/ExampleScanner.csproj
///
/// 部署:
///   cp plugins/example/bin/Debug/net8.0/ExampleScanner.dll \
///     src/DataProbe.Api/bin/Debug/net8.0/plugins/scanners/
///
/// 验证:
///   启动 DataProbe → 日志显示 [Plugin] Loaded plugin: example.scanner
///
/// 插件开发规范:
///   - 实现 IReScannerPlugin 或任意 IDataProbePlugin 子接口
///   - 引用 DataProbe.Core.dll, DataProbe.Extractor.dll
///   - 编译为 .dll，放到 plugins/{type}/ 下
///   - PluginManager 自动发现 + 热加载
/// </summary>
public class ExampleTargetScanner : IReScannerPlugin
{
    // ── IDataProbePlugin ──

    public string Id => "example.target_scanner";
    public string Name => "Example Target Scanner";
    public string Version => "1.0.0";
    public string Description => "识别特定目标 App 的特征并增强情报";

    public string[] SupportedTargets => new[]
    {
        "com.example.shop",       // 电商 App
        "com.example.game",       // 游戏 App
        "*.example.com"           // 所有 example.com 子域名
    };

    public PluginType Type => PluginType.ReScanner;

    public Task<bool> InitializeAsync(CancellationToken ct = default)
    {
        // 插件初始化逻辑：加载配置文件、连接外部服务等
        Console.Error.WriteLine("[ExamplePlugin] Initialized");
        return Task.FromResult(true);
    }

    // ── IReScannerPlugin ──

    public bool CanAnalyze(string fileType, byte[] fileData)
    {
        // 此插件处理 APK 和 PE 文件
        return fileType is "apk" or "pe" or "dll";
    }

    public ReFinding[] Scan(byte[] fileData, string fileType, CancellationToken ct = default)
    {
        var findings = new List<ReFinding>();

        try
        {
            // 1) 从二进制中提取可打印字符串
            var strings = ExtractStrings(fileData);

            // 2) 检查是否为目标 App
            bool isTargetApp = false;
            foreach (var s in strings)
            {
                if (s.Contains("com.example.shop"))
                {
                    isTargetApp = true;

                    // 提取 API 端点
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.ApiEndpoint,
                        Value = s,
                        Detail = "ExampleShop API endpoint",
                        Confidence = 0.9f
                    });
                }

                // 检测加密函数
                if (s.Contains("ExampleCrypto") || s.Contains("encryptPayload"))
                {
                    findings.Add(new ReFinding
                    {
                        Category = FindingCategory.CustomEncryption,
                        Value = s,
                        Detail = "Custom encryption function detected",
                        Confidence = 0.85f
                    });
                }
            }

            if (isTargetApp)
            {
                Console.Error.WriteLine($"[ExamplePlugin] Target identified: com.example.shop");

                // 3) 添加自定义情报
                findings.Add(new ReFinding
                {
                    Category = FindingCategory.Custom,
                    Value = "example_shop_detected",
                    Detail = "ExampleShop specific analysis",
                    Confidence = 1.0f
                });
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ExamplePlugin] Scan error: {ex.Message}");
        }

        return [.. findings];
    }

    /// <summary>从二进制中提取可打印字符串</summary>
    private static List<string> ExtractStrings(byte[] data)
    {
        var strings = new List<string>();
        var current = new System.Text.StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            char c = (char)data[i];
            if (char.IsLetterOrDigit(c) || c == '/' || c == ':' || c == '.' ||
                c == '_' || c == '-' || c == '=' || c == '@')
            {
                current.Append(c);
            }
            else
            {
                if (current.Length >= 8)
                    strings.Add(current.ToString());
                current.Clear();
            }
        }

        return strings;
    }
}

/// <summary>
/// 示例解密器插件 — 退掉 App 的自定义加密层
/// 演示 IDecryptionPlugin 的使用方式。
/// </summary>
public class ExampleCryptoDecoder : IDecryptionPlugin
{
    public string Id => "example.crypto_decoder";
    public string Name => "ExampleShop Crypto Decoder";
    public string Version => "1.0.0";
    public string Description => "解码 ExampleShop 的自定义 AES 加密";

    public string[] SupportedTargets => new[] { "com.example.shop" };
    public PluginType Type => PluginType.Decryption;

    public Task<bool> InitializeAsync(CancellationToken ct = default)
    {
        Console.Error.WriteLine("[ExamplePlugin:Crypto] Initialized");
        return Task.FromResult(true);
    }

    public bool CanDecrypt(NormalizedTransaction tx)
    {
        // 检测是否为加密响应（响应体以 "ENC:" 开头）
        return tx.ResponseBody.StartsWith("ENC:");
    }

    public Task<NormalizedTransaction?> DecryptAsync(NormalizedTransaction tx, CancellationToken ct = default)
    {
        // 此处演示解码逻辑，真实插件需要实现实际解密
        try
        {
            var encrypted = tx.ResponseBody;
            if (encrypted.StartsWith("ENC:"))
            {
                // 模拟解码：移除 "ENC:" 前缀并 Base64 解码
                var b64 = encrypted[4..];
                var decoded = System.Text.Encoding.UTF8
                    .GetString(Convert.FromBase64String(b64));

                tx.ResponseBody = decoded;
                Console.Error.WriteLine($"[ExamplePlugin:Crypto] Decoded response: {decoded[..Math.Min(100, decoded.Length)]}");
            }
        }
        catch { }

        return Task.FromResult<NormalizedTransaction?>(tx);
    }
}
