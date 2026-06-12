namespace DataProbe.Core;

/// <summary>
/// 数据证据 — 规则引擎产出的最小单元。
/// 每个证据包含：提取的值、在操作流中的精确位置、匹配方式、置信度。
/// 所有证据均可溯源到原始数据片段。
/// </summary>
public class DataEvidence
{
    /// <summary>证据唯一标识</summary>
    public string EvidenceId { get; init; } = $"ev_{Guid.NewGuid():N}";

    /// <summary>匹配的规则名称</summary>
    public string RuleName { get; set; } = "";

    /// <summary>提取到的值</summary>
    public string Value { get; set; } = "";

    /// <summary>数据类型（使用 Credential.cs 中的 CapturedDataType）</summary>
    public CapturedDataType Type { get; set; } = CapturedDataType.RawData;

    // ── 溯源信息 ──

    /// <summary>位置标识，如 "step.3.response.body"</summary>
    public string LocationId { get; set; } = "";

    /// <summary>所属请求 URL</summary>
    public string RequestUrl { get; set; } = "";

    /// <summary>操作流中的步骤序号</summary>
    public int StepIndex { get; set; }

    /// <summary>原始数据片段（上下文，用于验证）</summary>
    public string RawSnippet { get; set; } = "";

    // ── 匹配方式 ──

    /// <summary>匹配类型</summary>
    public MatchType MatchType { get; set; } = MatchType.Regex;

    /// <summary>置信度：1.0 = 精确匹配，0.7 = 启发式推断</summary>
    public float Confidence { get; set; } = 1.0f;

    // ── 关联 ──

    /// <summary>关联的其他证据 ID（如跨步骤复用的同一个 Token）</summary>
    public string? RelatedTo { get; set; }

    /// <summary>额外元数据</summary>
    public Dictionary<string, string> Metadata { get; set; } = new();

    /// <summary>捕获时间</summary>
    public DateTime CapturedAt { get; set; } = DateTime.UtcNow;

    /// <summary>创建精确匹配的证据</summary>
    public static DataEvidence Exact(string ruleName, string value, CapturedDataType type,
        string locationId, int stepIndex, string requestUrl, string rawSnippet)
    {
        return new DataEvidence
        {
            RuleName = ruleName,
            Value = value,
            Type = type,
            LocationId = locationId,
            StepIndex = stepIndex,
            RequestUrl = requestUrl,
            RawSnippet = rawSnippet,
            MatchType = MatchType.Regex,
            Confidence = 1.0f
        };
    }

    /// <summary>创建启发式匹配的证据</summary>
    public static DataEvidence Heuristic(string ruleName, string value, CapturedDataType type,
        string locationId, float confidence)
    {
        return new DataEvidence
        {
            RuleName = ruleName,
            Value = value,
            Type = type,
            LocationId = locationId,
            MatchType = MatchType.Heuristic,
            Confidence = Math.Clamp(confidence, 0, 1)
        };
    }
}

/// <summary>
/// 匹配类型
/// </summary>
public enum MatchType
{
    Regex,       // 正则表达式匹配
    JsonPath,    // JSONPath 匹配
    Semantic,    // 语义检测（如 JWT 解码、Base64 解码）
    Heuristic,   // 启发式推断（高熵值、结构推断）
    Diff,        // 差异分析（带/不带认证的响应对比）
    Hook         // 进程 Hook 捕获
}
