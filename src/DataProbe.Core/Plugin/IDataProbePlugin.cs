namespace DataProbe.Core.Plugin;

/// <summary>
/// 所有 DataProbe 插件的根接口。每种插件类型继承此接口并扩展。
/// 插件 = 针对特定目标/场景的自定义能力包，以 .dll 形式分发。
/// </summary>
public interface IDataProbePlugin
{
    /// <summary>插件唯一标识，如 "com.example.shop.decrypt"</summary>
    string Id { get; }

    /// <summary>人类可读名称</summary>
    string Name { get; }

    /// <summary>版本号，语义化版本</summary>
    string Version { get; }

    /// <summary>插件描述</summary>
    string Description { get; }

    /// <summary>插件类型</summary>
    PluginType Type { get; }

    /// <summary>此插件适用的目标标识列表，如 ["com.example.shop", "*.taobao.com"]</summary>
    /// <remarks>空列表 = 适用于所有目标</remarks>
    string[] SupportedTargets { get; }

    /// <summary>初始化插件</summary>
    Task<bool> InitializeAsync(CancellationToken ct = default);
}

/// <summary>
/// 插件类型
/// </summary>
public enum PluginType
{
    /// <summary>逆向扫描器 — 从 APK/DLL/JS 中提取情报</summary>
    ReScanner,

    /// <summary>应用层解密器 — 自定义加密/编码的解码</summary>
    Decryption,

    /// <summary>高级提取器 — 超越正则的复杂数据提取逻辑</summary>
    Extractor,

    /// <summary>协议解析器 — 自定义二进制协议解析</summary>
    Protocol,

    /// <summary>验证码/挑战处理器 — 定制验证码求解</summary>
    Challenge
}

// ═══════════════════════════════════════════════════════════
// 反 向 扫 描 器 插 件
// ═══════════════════════════════════════════════════════════

/// <summary>
/// 逆向扫描器插件 — 对目标文件进行静态分析，提取情报。
/// 每个插件针对特定 App 或特定类型的分析。
/// 示例: "抖音 APK 扫描器"、"微信小程序解包器"
/// </summary>
public interface IReScannerPlugin : IDataProbePlugin
{
    /// <summary>判断此扫描器能否分析该文件</summary>
    bool CanAnalyze(string fileType, byte[] fileData);

    /// <summary>执行分析，返回发现项</summary>
    ReFinding[] Scan(byte[] fileData, string fileType, CancellationToken ct = default);
}

/// <summary>扫描发现项（与 ReAnalyzer.cs 共享的模型）</summary>
public class ReFinding
{
    public FindingCategory Category { get; set; }
    public string Value { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Offset { get; set; }
    public float Confidence { get; set; } = 1.0f;
}

public enum FindingCategory
{
    CertPinning,
    AntiEmulator,
    AntiDebug,
    ApiEndpoint,
    HardcodedToken,
    SdkDetected,
    UrlScheme,
    CustomEncryption,
    AntiCheat,
    /// <summary>由插件自定义的扩展类别，字符串标识</summary>
    Custom
}

// ═══════════════════════════════════════════════════════════
// 应 用 层 解 密 器 插 件
// ═══════════════════════════════════════════════════════════

/// <summary>
/// 解密器插件 — 在 TLS 解密之后、数据到达规则引擎之前，
/// 对应用层自定义加密/编码的数据进行解码。
///
/// 典型场景:
///   App A 把响应体做 Base64(AES(data)) → 此插件负责退掉这两层
///   App B 把 JSON 做自定义 XOR → 此插件负责 XOR 回明文
/// </summary>
public interface IDecryptionPlugin : IDataProbePlugin
{
    /// <summary>判断此解密器能否处理该事务</summary>
    bool CanDecrypt(NormalizedTransaction tx);

    /// <summary>执行解密，返回解密后的事务</summary>
    Task<NormalizedTransaction?> DecryptAsync(NormalizedTransaction tx, CancellationToken ct = default);
}

/// <summary>解密结果</summary>
public class DecryptionResult
{
    public bool Success { get; set; }
    public string? DecryptedBody { get; set; }
    public string? DecryptionMethod { get; set; }
    public Dictionary<string, string>? ExtractedMetadata { get; set; }
}

// ═══════════════════════════════════════════════════════════
// 高 级 提 取 器 插 件
// ═══════════════════════════════════════════════════════════

/// <summary>
/// 提取器插件 — 当正则/JSONPath 不足以提取复杂结构时使用。
/// 例如: Protobuf 解码后提取、HTML 表格解析、分页数据合并。
/// </summary>
public interface IExtractorPlugin : IDataProbePlugin
{
    /// <summary>判断此提取器能否处理该事务</summary>
    bool CanExtract(NormalizedTransaction tx);

    /// <summary>执行提取，返回证据列表</summary>
    Task<List<DataEvidence>> ExtractAsync(NormalizedTransaction tx, CancellationToken ct = default);
}

// ═══════════════════════════════════════════════════════════
// 协 议 解 析 器 插 件
// ═══════════════════════════════════════════════════════════

/// <summary>
/// 协议解析器插件 — 解析非 HTTP 的二进制协议。
/// 数据流 → 此插件 → NormalizedTransaction
/// </summary>
public interface IProtocolPlugin : IDataProbePlugin
{
    /// <summary>协议名称，如 "MQTT"、"WebRTC"</summary>
    string ProtocolName { get; }

    /// <summary>判断原始字节是否匹配此协议</summary>
    bool CanParse(ReadOnlySpan<byte> data);

    /// <summary>解析请求，返回 JSON 格式字符串</summary>
    string? ParseRequest(ReadOnlySpan<byte> data);

    /// <summary>解析响应</summary>
    string? ParseResponse(ReadOnlySpan<byte> data);
}
