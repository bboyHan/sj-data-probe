using DataProbe.Core;

namespace DataProbe.Http;

/// <summary>
/// 协议解析器接口 — 每种协议实现一个。
/// 职责：检测协议 → 解析请求/响应 → 产出 NormalizedTransaction
/// </summary>
public interface IProtocolParser
{
    /// <summary>协议名称，如 "HTTP/1.1"、"HTTP/2"、"WebSocket"</summary>
    string ProtocolName { get; }

    /// <summary>判断原始字节是否匹配此协议</summary>
    bool CanParse(ReadOnlySpan<byte> data);

    /// <summary>尝试从原始字节中解析出 HTTP 风格的事务（方法、路径、请求体）</summary>
    ParseResult? ParseRequest(ReadOnlySpan<byte> data);

    /// <summary>尝试从原始字节中解析出 HTTP 风格的事务（状态码、响应体、响应头）</summary>
    ParseResult? ParseResponse(ReadOnlySpan<byte> data);
}

/// <summary>
/// 解析结果 — 统一的中间表示
/// </summary>
public class ParseResult
{
    public string Method { get; set; } = "";
    public string Path { get; set; } = "";
    public string QueryString { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new();
    public byte[] Body { get; set; } = Array.Empty<byte>();
    public int StatusCode { get; set; }
    public string BodyString => System.Text.Encoding.UTF8.GetString(Body);
}
