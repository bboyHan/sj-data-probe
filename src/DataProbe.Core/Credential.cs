using System.Text.Json.Serialization;

namespace DataProbe.Core;

/// <summary>
/// 数据捕获结果 — 引擎产出的统一结构化数据单元。
/// 不限定业务含义，由调用方按需使用。
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CapturedDataType
{
    Url,            // URL 链接
    Params,         // 结构化参数
    Token,          // 访问令牌
    Image,          // 图片数据 (Base64)
    Key,            // 密钥/卡密
    Account,        // 账号信息
    Payment,        // 支付数据
    RawData,        // 未识别的原始数据
}

public class Credential
{
    public string Id { get; set; } = $"cred_{Guid.NewGuid():N}";
    public CapturedDataType Type { get; set; } = CapturedDataType.RawData;
    public string Value { get; set; } = "";
    public string Platform { get; set; } = "";
    public string ProductId { get; set; } = "";
    public string Source { get; set; } = "dataprobe";
    public string AccountName { get; set; } = "";
    public string IdentityToken { get; set; } = "";
    public string Method { get; set; } = "";
    public Dictionary<string, string> Metadata { get; set; } = new();
    public DateTime CapturedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 序列化为输出负载（适配后端 API 格式）。
    /// </summary>
    public object ToPayload() => new
    {
        id = Id,
        type = Type switch
        {
            CapturedDataType.Url => "url",
            CapturedDataType.Params => "params",
            CapturedDataType.Token => "token",
            CapturedDataType.Image => "image",
            CapturedDataType.Key => "key",
            CapturedDataType.Account => "account",
            CapturedDataType.Payment => "payment",
            _ => "raw"
        },
        value = Value,
        platform = Platform,
        product_id = ProductId,
        source = Source,
        identity = IdentityToken,
        method = Method,
        metadata = new Dictionary<string, string>(Metadata),
        captured_at = CapturedAt.ToString("O"),
    };
}
