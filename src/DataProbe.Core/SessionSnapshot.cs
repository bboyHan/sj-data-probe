using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProbe.Core;

/// <summary>
/// 操作流快照 — 一次"完整数字操作"的全部数据痕迹。
/// 所有通道、协议、注入方式捕获的数据最终聚合为此结构。
/// 这是规则引擎的唯一输入格式。
/// </summary>
public class SessionSnapshot
{
    public string SessionId { get; init; } = $"sess_{Guid.NewGuid():N}";
    public string TargetName { get; set; } = "";
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }

    /// <summary>操作步骤，按时间排序</summary>
    public List<OperationStep> Steps { get; set; } = new();

    /// <summary>本次调查使用的通道方案</summary>
    public string? CaptureMethod { get; set; }

    /// <summary>目标防护评级</summary>
    public ProtectionLevel TargetRating { get; set; } = ProtectionLevel.Unknown;

    /// <summary>此快照中所有文本的全文索引（用于全局规则扫描加速）</summary>
    [JsonIgnore]
    public TextIndex AllText { get; } = new();

    /// <summary>构建完成后调用，填充索引</summary>
    public void BuildIndex()
    {
        AllText.Clear();
        foreach (var step in Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                AllText.Add(http.RequestUrl.LocationId, http.RequestUrl.RawText);
                AllText.Add(http.RequestHeaders.LocationId, http.RequestHeaders.RawText);
                AllText.Add(http.RequestBody.LocationId, http.RequestBody.RawText);
                AllText.Add(http.ResponseHeaders.LocationId, http.ResponseHeaders.RawText);
                AllText.Add(http.ResponseBody.LocationId, http.ResponseBody.RawText);
                AllText.Add(http.ResponseStatus.LocationId, http.ResponseStatus.RawText);
            }
            foreach (var ws in step.WebSocketMessages)
                AllText.Add(ws.LocationId, ws.Payload);
            foreach (var schema in step.UrlSchemes)
                AllText.Add(schema.LocationId, schema.Uri);
            foreach (var hook in step.HookData)
                AllText.Add(hook.LocationId, hook.Value);
        }
    }
}

/// <summary>
/// 操作流中的一个步骤，对应一次用户操作或自动触发的交互。
/// </summary>
public class OperationStep
{
    /// <summary>步序号，从 1 开始</summary>
    public int StepIndex { get; set; }

    /// <summary>人类可读的操作描述，如"点击购买按钮"</summary>
    public string UserAction { get; set; } = "";

    /// <summary>步骤发生时间</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>此步骤中所有的 HTTP 交互</summary>
    public List<HttpTransaction> HttpTransactions { get; set; } = new();

    /// <summary>此步骤中所有的 WebSocket 消息</summary>
    public List<WebSocketMessage> WebSocketMessages { get; set; } = new();

    /// <summary>此步骤中调起的 URL Scheme（如 weixin://, intent://）</summary>
    public List<SchemaInvocation> UrlSchemes { get; set; } = new();

    /// <summary>此步骤中通过进程 Hook 获取的数据</summary>
    public List<HookCapture> HookData { get; set; } = new();

    /// <summary>重定向链</summary>
    public List<RedirectChain> RedirectChains { get; set; } = new();
}

/// <summary>
/// HTTP 交互 — 一个完整的请求/响应周期。
/// 显式定义 6 个核心数据位置，每个位置独立存储。
/// </summary>
public class HttpTransaction
{
    /// <summary>所属步序号</summary>
    public int StepIndex { get; set; }

    /// <summary>HTTP 方法</summary>
    public string Method { get; set; } = "";

    /// <summary>完整 URL（含 query string）</summary>
    public string Url { get; set; } = "";

    /// <summary>HTTP 状态码</summary>
    public int StatusCode { get; set; }

    // ── 6 个核心数据位置 ──

    /// <summary>位置 1: 请求 URL（含 path + query）</summary>
    public DataFragment RequestUrl { get; set; } = new();

    /// <summary>位置 2: 请求头</summary>
    public DataFragment RequestHeaders { get; set; } = new();

    /// <summary>位置 3: 请求体</summary>
    public DataFragment RequestBody { get; set; } = new();

    /// <summary>位置 4: 响应头</summary>
    public DataFragment ResponseHeaders { get; set; } = new();

    /// <summary>位置 5: 响应体</summary>
    public DataFragment ResponseBody { get; set; } = new();

    /// <summary>位置 6: 响应状态行</summary>
    public DataFragment ResponseStatus { get; set; } = new();

    // ── 结构化解码（延迟初始化） ──

    private JsonDoc? _requestJson;
    private JsonDoc? _responseJson;

    /// <summary>请求体 JSON 解析结果（按需延迟解析）</summary>
    [JsonIgnore]
    public JsonDoc? RequestJson =>
        _requestJson ??= TryParseJson(RequestBody);

    /// <summary>响应体 JSON 解析结果（按需延迟解析）</summary>
    [JsonIgnore]
    public JsonDoc? ResponseJson =>
        _responseJson ??= TryParseJson(ResponseBody);

    private static JsonDoc? TryParseJson(DataFragment fragment)
    {
        if (fragment.Size == 0) return null;
        if (string.IsNullOrEmpty(fragment.RawText)) return null;
        try
        {
            using var doc = JsonDocument.Parse(fragment.RawText);
            return new JsonDoc(doc);
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// 数据片段 — 规则匹配的最小单元。
/// 统一所有数据位置的访问方式，支持多种内容类型的按需解析。
/// </summary>
public class DataFragment
{
    /// <summary>位置标识，如 "step.3.request.body"</summary>
    public string LocationId { get; set; } = "";

    /// <summary>内容类型提示：json / html / form / plain / binary</summary>
    public string ContentType { get; set; } = "plain";

    /// <summary>数据大小（字节数）</summary>
    public long Size { get; set; }

    /// <summary>纯文本表示（所有类型都有，二进制转 Base64）</summary>
    public string RawText { get; set; } = "";

    /// <summary>原始字节（仅对 Header/Status 以外的位置可用）</summary>
    [JsonIgnore]
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();

    /// <summary>键值对表示（适用于 Headers、Form、Query）</summary>
    public Dictionary<string, string> AsPairs { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>构造 HTTP 请求头片段</summary>
    public static DataFragment FromHeaders(Dictionary<string, string> headers)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var (k, v) in headers)
            sb.AppendLine($"{k}: {v}");

        return new DataFragment
        {
            ContentType = "headers",
            Size = sb.Length,
            RawText = sb.ToString(),
            AsPairs = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
        };
    }

    /// <summary>构造请求/响应体片段</summary>
    public static DataFragment FromBody(string body, string contentType = "plain")
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        return new DataFragment
        {
            ContentType = contentType,
            Size = bytes.Length,
            RawText = body,
            RawBytes = bytes
        };
    }

    /// <summary>构造 URL 片段</summary>
    public static DataFragment FromUrl(string url)
    {
        return new DataFragment
        {
            ContentType = "url",
            Size = url.Length,
            RawText = url
        };
    }

    /// <summary>构造状态行片段</summary>
    public static DataFragment FromStatus(int statusCode, string reason = "")
    {
        var text = $"{statusCode}{(string.IsNullOrEmpty(reason) ? "" : $" {reason}")}";
        return new DataFragment
        {
            ContentType = "status",
            Size = text.Length,
            RawText = text,
            AsPairs = new Dictionary<string, string> { ["code"] = statusCode.ToString(), ["reason"] = reason }
        };
    }
}

/// <summary>
/// WebSocket 消息
/// </summary>
public class WebSocketMessage
{
    public int StepIndex { get; set; }
    public string LocationId => $"step.{StepIndex}.websocket.{Direction}.{Index}";
    public int Index { get; set; }
    public string Direction { get; set; } = "send";  // send / receive
    public int OpCode { get; set; }                   // 1=Text, 2=Binary, 8=Close, 9=Ping, 10=Pong
    public string Payload { get; set; } = "";
    public bool IsText => OpCode == 1;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// URL Scheme 调用（如 weixin://pay, intent://, alipay://）
/// </summary>
public class SchemaInvocation
{
    public int StepIndex { get; set; }
    public string LocationId => $"step.{StepIndex}.schema";
    public string Uri { get; set; } = "";
    public string Scheme => Uri.Contains("://") ? Uri[..Uri.IndexOf("://")] : "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// 重定向链
/// </summary>
public class RedirectChain
{
    public int StepIndex { get; set; }
    public string InitialUrl { get; set; } = "";
    public List<string> RedirectUrls { get; set; } = new();
    public string FinalUrl => RedirectUrls.Count > 0 ? RedirectUrls[^1] : InitialUrl;
}

/// <summary>
/// 进程 Hook 捕获的数据
/// </summary>
public class HookCapture
{
    public int StepIndex { get; set; }
    public string LocationId => $"step.{StepIndex}.hook.{FunctionName}";
    public string FunctionName { get; set; } = "";
    public string Direction { get; set; } = "";  // call / return
    public string Value { get; set; } = "";
    public string? ArgJson { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// 全局文本索引 — 用于快速全位置规则扫描
/// </summary>
public class TextIndex
{
    private readonly List<(string LocationId, string Text)> _entries = new();

    public void Add(string locationId, string text)
    {
        if (!string.IsNullOrEmpty(text))
            _entries.Add((locationId, text));
    }

    public void Clear() => _entries.Clear();
    public int Count => _entries.Count;

    /// <summary>在所有文本中搜索正则匹配</summary>
    public IEnumerable<(string LocationId, string Text, System.Text.RegularExpressions.Match Match)>
        Search(System.Text.RegularExpressions.Regex regex)
    {
        foreach (var (loc, text) in _entries)
        {
            var match = regex.Match(text);
            if (match.Success)
                yield return (loc, text, match);
        }
    }

    /// <summary>在所有文本中搜索子串</summary>
    public IEnumerable<(string LocationId, string Text)> SearchContains(string pattern, StringComparison comp = StringComparison.OrdinalIgnoreCase)
    {
        foreach (var (loc, text) in _entries)
        {
            if (text.Contains(pattern, comp))
                yield return (loc, text);
        }
    }

    /// <summary>在所有 JSON 中搜索 JSONPath</summary>
    public IEnumerable<(string LocationId, JsonDoc Doc)> SearchJson(string jsonPath)
    {
        // 简化版：仅遍历标记为 json 的条目
        // 完整 JSONPath 实现后续扩展
        yield break;
    }
}

/// <summary>
/// JSON 文档的轻量包装（避免将整个 JsonDocument 暴露给外部）
/// </summary>
public class JsonDoc
{
    private readonly JsonDocument _doc;

    internal JsonDoc(JsonDocument doc) => _doc = doc;

    /// <summary>按 JSONPath 查找值（简化版，仅支持点号路径如 "data.user.token"）</summary>
    public string? SelectValue(string path)
    {
        var parts = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
        JsonElement element = _doc.RootElement;

        foreach (var part in parts)
        {
            if (element.ValueKind != JsonValueKind.Object) return null;
            if (!element.TryGetProperty(part, out element)) return null;
        }

        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => element.GetRawText()
        };
    }

    /// <summary>遍历所有字段名</summary>
    public IEnumerable<string> FieldNames()
    {
        return FlattenFieldNames(_doc.RootElement, "");
    }

    private static IEnumerable<string> FlattenFieldNames(JsonElement element, string prefix)
    {
        if (element.ValueKind != JsonValueKind.Object) yield break;

        foreach (var prop in element.EnumerateObject())
        {
            var name = string.IsNullOrEmpty(prefix) ? prop.Name : $"{prefix}.{prop.Name}";
            yield return name;
            foreach (var child in FlattenFieldNames(prop.Value, name))
                yield return child;
        }
    }
}

/// <summary>
/// 目标防护等级
/// </summary>
public enum ProtectionLevel
{
    Unknown = 0,
    None,       // 无防护，浏览器目标
    Low,        // 基本 HTTPS，无锁定
    Medium,     // 证书锁定，无反作弊
    High,       // 证书锁定 + 反作弊
    Extreme     // 硬件级防护 + 实时风控
}
