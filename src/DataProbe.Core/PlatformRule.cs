using System.Text.RegularExpressions;

namespace DataProbe.Core;

/// <summary>
/// 提取规则 — 纯数据，定义如何匹配和提取目标数据。
/// 从 JSON 文件加载，支持运行时热更新。
/// </summary>
public class PlatformRule
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public int Priority { get; set; } = 100;
    public string? Id { get; set; }

    /// <summary>匹配条件列表，全部满足才算命中</summary>
    public List<MatcherRule> Matchers { get; set; } = new();

    /// <summary>提取器列表</summary>
    public List<ExtractorRule> Extractors { get; set; } = new();

    // ── 运行时统计 ──
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastMatchedAt { get; set; }
    public long TotalCaptured { get; set; }
}

public class MatcherRule
{
    /// <summary>匹配字段: domain | path | method | status | header.xxx</summary>
    public string Field { get; set; } = "";

    /// <summary>匹配操作: equals | contains | regex | starts_with | not</summary>
    public string Operator { get; set; } = "contains";

    /// <summary>匹配值</summary>
    public string Value { get; set; } = "";

    public bool IsMatch(NormalizedTransaction tx)
    {
        var target = Field.ToLower() switch
        {
            "domain" => tx.Domain,
            "path" => tx.Path,
            "method" => tx.Method,
            "status" => tx.StatusCode.ToString(),
            "query" => tx.QueryString,
            "url" => tx.Url,
            var h when h.StartsWith("header.") => LookupHeader(h, tx),
            _ => ""
        };

        return Operator.ToLower() switch
        {
            "equals" => target.Equals(Value, StringComparison.OrdinalIgnoreCase),
            "contains" => target.Contains(Value, StringComparison.OrdinalIgnoreCase),
            "starts_with" => target.StartsWith(Value, StringComparison.OrdinalIgnoreCase),
            "regex" => Regex.IsMatch(target, Value, RegexOptions.IgnoreCase),
            "not" => !target.Contains(Value, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static string LookupHeader(string field, NormalizedTransaction tx)
    {
        var name = field["header.".Length..].Trim();
        if (tx.ResponseHeaders.TryGetValue(name, out var v)) return v;
        if (tx.RequestHeaders.TryGetValue(name, out var v2)) return v2;
        return "";
    }
}

public class ExtractorRule
{
    public string Name { get; set; } = "";
    public string Source { get; set; } = "response_body";
    public string OutputField { get; set; } = "value";
    public string DataType { get; set; } = "url";
    public string Pattern { get; set; } = "";

    private Regex? _compiled;

    public string? Extract(NormalizedTransaction tx)
    {
        if (Source.ToLower() == "response_body_raw")
        {
            var b64 = tx.ResponseBodyBase64;
            if (string.IsNullOrEmpty(b64)) return null;
            return b64;
        }

        var source = Source.ToLower() switch
        {
            "request_body" => tx.RequestBody,
            "response_body" => tx.ResponseBody,
            "path" => tx.Path,
            "query" => tx.QueryString,
            "domain" => tx.Domain,
            "method" => tx.Method,
            "url" => tx.Url,
            var h when h.StartsWith("header.") => LookupHeader(h, tx),
            _ => ""
        };

        if (string.IsNullOrEmpty(source)) return null;

        _compiled ??= new Regex(Pattern, RegexOptions.Compiled | RegexOptions.Multiline);

        var match = _compiled.Match(source);
        return match.Success
            ? (match.Groups.Count > 1 ? match.Groups[1].Value : match.Value)
            : null;
    }

    private static string LookupHeader(string field, NormalizedTransaction tx)
    {
        var name = field["header.".Length..].Trim();
        if (tx.ResponseHeaders.TryGetValue(name, out var v)) return v;
        if (tx.RequestHeaders.TryGetValue(name, out var v2)) return v2;
        return "";
    }
}
