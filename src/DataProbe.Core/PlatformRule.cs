using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProbe.Core;

/// <summary>
/// 提取规则 — 定义如何匹配和提取目标数据。
/// 核心升级：支持全位置扫描、上下文条件、多匹配器。
/// </summary>
public class PlatformRule
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public int Priority { get; set; } = 100;
    public string? Id { get; set; }

    /// <summary>匹配条件列表，全部满足才算命中（已有逻辑保留）</summary>
    public List<MatcherRule> Matchers { get; set; } = new();

    /// <summary>提取器列表（已有逻辑保留）</summary>
    public List<ExtractorRule> Extractors { get; set; } = new();

    // ── 新增：高级规则配置 ──

    /// <summary>
    /// 上下文条件 — 本规则只在满足此条件的操作流中启用。
    /// 例如：只在包含 "order" 路径的操作流中扫描支付链接。
    /// </summary>
    public ContextCondition? Context { get; set; }

    /// <summary>
    /// 扫描位置列表 — 指定在哪些数据位置执行匹配。
    /// 空列表 = 所有位置。
    /// 位置标识: request.url / request.headers / request.body /
    ///           response.headers / response.body / response.status /
    ///           websocket.message / url.scheme / dom.text / hook.function
    /// </summary>
    public List<string> ScanLocations { get; set; } = new()
    {
        "response.body",
        "request.body",
        "response.headers",
        "request.headers",
        "request.url",
        "response.status",
        "websocket.message",
        "url.scheme"
    };

    /// <summary>
    /// 提取目标字段映射 — 替代 Extractors 中的 OutputField
    /// </summary>
    public List<FieldExtractor> Fields { get; set; } = new();

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>最后匹配时间</summary>
    public DateTime? LastMatchedAt { get; set; }

    /// <summary>累计捕获数</summary>
    public long TotalCaptured { get; set; }

    /// <summary>从 Fields 编译为 Extractors（保持兼容）</summary>
    public List<ExtractorRule> CompileFields()
    {
        return Fields.Select(f => new ExtractorRule
        {
            Name = f.Name,
            Source = f.Source,
            OutputField = f.OutputField,
            DataType = f.DataType,
            Pattern = f.Pattern
        }).ToList();
    }
}

/// <summary>
/// 上下文条件 — 控制规则在什么操作流下激活。
/// </summary>
public class ContextCondition
{
    /// <summary>路径关键词：操作流中任意 URL 包含这些关键词时启用规则</summary>
    public string[]? RequiresOperation { get; set; }

    /// <summary>最低置信度：只有置信度 >= 此值时输出</summary>
    public double MinConfidence { get; set; } = 0.7;

    /// <summary>检查此规则是否应在当前 SessionSnapshot 中激活</summary>
    public bool IsActive(SessionSnapshot session)
    {
        if (RequiresOperation != null && RequiresOperation.Length > 0)
        {
            // 在 Session 的所有 URL 中搜索关键词
            foreach (var step in session.Steps)
            {
                foreach (var http in step.HttpTransactions)
                {
                    var url = http.Url;
                    foreach (var kw in RequiresOperation)
                    {
                        if (url.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
            return false;
        }
        return true;
    }
}

/// <summary>
/// 字段提取器 — 定义从哪个数据源用哪种方式提取
/// </summary>
public class FieldExtractor
{
    public string Name { get; set; } = "";

    /// <summary>数据源: response_body / request_body / response_header.xxx / etc</summary>
    public string Source { get; set; } = "response_body";

    /// <summary>输出字段名</summary>
    public string OutputField { get; set; } = "value";

    /// <summary>数据类型: url / token / key / image / params / raw</summary>
    public string DataType { get; set; } = "raw";

    /// <summary>提取模式（正则表达式或 JSONPath）</summary>
    public string Pattern { get; set; } = "";

    [JsonIgnore]
    private Regex? _compiled;

    /// <summary>编译后的正则（延迟初始化）</summary>
    [JsonIgnore]
    public Regex? CompiledRegex
    {
        get
        {
            if (_compiled == null && !string.IsNullOrEmpty(Pattern))
            {
                try { _compiled = new Regex(Pattern, RegexOptions.Compiled | RegexOptions.Multiline); }
                catch { }
            }
            return _compiled;
        }
    }
}

/// <summary>
/// 匹配规则 — 判断一个 NormalizedTransaction 是否满足条件
/// </summary>
public class MatcherRule
{
    /// <summary>匹配字段: domain | path | method | status | header.xxx</summary>
    public string Field { get; set; } = "";

    /// <summary>匹配操作: equals | contains | regex | starts_with | not</summary>
    public string Operator { get; set; } = "contains";

    /// <summary>匹配值</summary>
    public string Value { get; set; } = "";

    private Regex? _compiledRegex;

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
            "regex" => MatchRegex(target),
            "not" => !target.Contains(Value, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private bool MatchRegex(string target)
    {
        _compiledRegex ??= new Regex(Value, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        return _compiledRegex.IsMatch(target);
    }

    private static string LookupHeader(string field, NormalizedTransaction tx)
    {
        var name = field["header.".Length..].Trim();
        if (tx.ResponseHeaders.TryGetValue(name, out var v)) return v;
        if (tx.RequestHeaders.TryGetValue(name, out var v2)) return v2;
        return "";
    }
}

/// <summary>
/// 提取规则（保留兼容）
/// </summary>
public class ExtractorRule
{
    public string Name { get; set; } = "";
    public string Source { get; set; } = "response_body";
    public string OutputField { get; set; } = "value";
    public string DataType { get; set; } = "url";
    public string Pattern { get; set; } = "";

    private Regex? _compiled;

    [System.Text.Json.Serialization.JsonIgnore]
    public Regex? CompiledRegex
    {
        get
        {
            if (_compiled == null && !string.IsNullOrEmpty(Pattern))
            {
                try { _compiled = new Regex(Pattern, RegexOptions.Compiled | RegexOptions.Multiline); }
                catch { }
            }
            return _compiled;
        }
    }

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

/// <summary>
/// 预设规则包 — 一组相关规则的集合
/// </summary>
public class RulePack
{
    /// <summary>规则包名称，如 "支付数据提取包"</summary>
    public string Name { get; set; } = "";

    /// <summary>规则包描述</summary>
    public string Description { get; set; } = "";

    /// <summary>版本号</summary>
    public string Version { get; set; } = "1.0";

    /// <summary>包含的规则</summary>
    public List<PlatformRule> Rules { get; set; } = new();

    /// <summary>适用目标类型</summary>
    public string[] TargetTypes { get; set; } = Array.Empty<string>();
}
