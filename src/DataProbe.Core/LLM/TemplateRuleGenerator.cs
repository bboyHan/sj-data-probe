using System.Text.Json;
using System.Text.RegularExpressions;

namespace DataProbe.Core.LLM;

/// <summary>
/// 模板规则生成器 — 零 LLM 依赖的兜底方案。
/// 通过字段名、值模式、结构特征自动生成提取规则。
///
/// 策略:
///   ① 字段名匹配: token / sign / password / secret → 自动提取
///   ② 值模式匹配: JWT / Base64 / URL / 微信支付链接 → 自动识别
///   ③ JSON 结构推断: 高频字段、嵌套路径
///
/// 这是整个 AI-Native 系统的"最后防线"——
/// 当所有 LLM 都不可用时，至少模板引擎能生成基本规则。
/// </summary>
public class TemplateRuleGenerator : IRuleGeneratorPlugin
{
    public string Name => "template_engine";
    public string Version => "1.0.0";
    public int Priority => 0; // 最低优先级 — 作为兜底

    public bool IsAvailable => true; // 始终可用

    // 敏感字段名→数据类型映射
    private static readonly Dictionary<string, string> SensitiveFields = new(StringComparer.OrdinalIgnoreCase)
    {
        ["token"] = "token", ["access_token"] = "token", ["accessToken"] = "token",
        ["auth_token"] = "token", ["refresh_token"] = "token", ["id_token"] = "token",
        ["sign"] = "token", ["signature"] = "token",
        ["password"] = "key", ["passwd"] = "key", ["secret"] = "key",
        ["api_key"] = "key", ["apikey"] = "key", ["api_secret"] = "key",
        ["pay_url"] = "url", ["payUrl"] = "url", ["payment_url"] = "url",
        ["order_id"] = "params", ["orderId"] = "params", ["trade_no"] = "params",
        ["phone"] = "params", ["mobile"] = "params", ["email"] = "params",
        ["openid"] = "token", ["open_id"] = "token",
    };

    // 值模式→数据类型
    private static readonly (Regex Pattern, string Type, string Name)[] ValuePatterns =
    {
        (new Regex(@"^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"), "token", "jwt_token"),
        (new Regex(@"^weixin://"), "url", "wechat_pay_url"),
        (new Regex(@"^alipay://"), "url", "alipay_pay_url"),
        (new Regex(@"^https?://[^\s]+"), "url", "http_url"),
        (new Regex(@"^[a-fA-F0-9]{32,}$"), "token", "md5_hash"),
        (new Regex(@"^\d{4,8}$"), "params", "verification_code"),
    };

    public Task<RuleGenerationResult> GenerateFromDescriptionAsync(
        string description, string? sampleResponse = null, CancellationToken ct = default)
    {
        var result = new RuleGenerationResult { GeneratorName = Name };

        // 从描述中提取关键词
        var keywords = ExtractKeywords(description);

        // 如果有样本数据，优先从样本推断
        if (!string.IsNullOrEmpty(sampleResponse))
        {
            var fromSample = InferFromSample(sampleResponse, description, keywords);
            result.Rules.AddRange(fromSample);
        }

        // 根据关键词生成规则
        foreach (var kw in keywords)
        {
            if (SensitiveFields.TryGetValue(kw, out var dataType))
            {
                var rule = BuildFieldRule(kw, dataType, description);
                if (rule != null && !result.Rules.Any(r => r.Name == rule.Name))
                    result.Rules.Add(rule);
            }
        }

        // 如果没有生成任何规则，创建一个基于关键词的通配规则
        if (result.Rules.Count == 0 && keywords.Count > 0)
        {
            result.Rules.Add(BuildWildcardRule(keywords, description));
        }

        result.Success = result.Rules.Count > 0;
        result.Confidence = 0.6f;
        result.Explanation = result.Success
            ? $"Generated {result.Rules.Count} rules from description keywords"
            : "Could not infer rules from description";

        return Task.FromResult(result);
    }

    public Task<RuleGenerationResult> GenerateFromSampleAsync(
        string sampleData, string contentType, CancellationToken ct = default)
    {
        var result = new RuleGenerationResult { GeneratorName = Name };

        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            var rules = InferFromJsonSample(sampleData);
            result.Rules.AddRange(rules);
        }
        else
        {
            var rules = InferFromTextSample(sampleData);
            result.Rules.AddRange(rules);
        }

        result.Success = result.Rules.Count > 0;
        result.Confidence = 0.7f;
        return Task.FromResult(result);
    }

    // ── 私有方法 ──

    private static List<string> ExtractKeywords(string description)
    {
        var keywords = new List<string>();
        // 常见中文/英文数据描述词
        var patterns = new[] {
            @"sign|签名|signature",
            @"token|令牌|凭证",
            @"password|密码|passwd|secret|密钥",
            @"pay|支付|付款|order|订单|trade|交易",
            @"phone|手机|mobile|短信|验证码",
            @"url|链接|地址|二维码",
            @"user|用户|account|账号|member",
        };

        foreach (var p in patterns)
        {
            if (Regex.IsMatch(description, p, RegexOptions.IgnoreCase))
            {
                foreach (Match m in Regex.Matches(description, p, RegexOptions.IgnoreCase | RegexOptions.Compiled))
                    keywords.Add(m.Value.ToLower());
            }
        }

        return keywords.Distinct().ToList();
    }

    private static List<PlatformRule> InferFromSample(string sample, string description, List<string> keywords)
    {
        var rules = new List<PlatformRule>();

        if (string.IsNullOrEmpty(sample)) return rules;

        // 检测是否为 JSON
        var trimmed = sample.Trim();
        if (trimmed.StartsWith("{") || trimmed.StartsWith("["))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                rules.AddRange(InferFromJsonElement(doc.RootElement, "auto_inferred", ""));
            }
            catch { }
        }
        else
        {
            // 非 JSON → 按行扫描值模式
            foreach (var line in trimmed.Split('\n'))
            {
                foreach (var (pattern, type, name) in ValuePatterns)
                {
                    if (pattern.IsMatch(line.Trim()))
                    {
                        rules.Add(new PlatformRule
                        {
                            Name = $"{name}_auto",
                            Description = $"Auto-detected {type}: {name}",
                            Priority = 100,
                            Enabled = true,
                            ScanLocations = new List<string> { "response.body" },
                            Extractors = new List<ExtractorRule>
                            {
                                new()
                                {
                                    Name = name,
                                    Source = "response_body",
                                    OutputField = "value",
                                    DataType = type,
                                    Pattern = pattern.ToString()
                                }
                            }
                        });
                        break;
                    }
                }
            }
        }

        return rules;
    }

    private static List<PlatformRule> InferFromJsonSample(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return InferFromJsonElement(doc.RootElement, "json_sample", "").ToList();
        }
        catch { return new List<PlatformRule>(); }
    }

    private static List<PlatformRule> InferFromTextSample(string text)
    {
        var rules = new List<PlatformRule>();
        foreach (var (pattern, type, name) in ValuePatterns)
        {
            var match = pattern.Match(text);
            if (match.Success)
            {
                rules.Add(new PlatformRule
                {
                    Name = $"{name}_auto",
                    Priority = 100,
                    ScanLocations = new List<string> { "response.body" },
                    Extractors = new List<ExtractorRule>
                    {
                        new() { Name = name, Source = "response_body",
                                OutputField = "value", DataType = type,
                                Pattern = pattern.ToString() }
                    }
                });
            }
        }
        return rules;
    }

    private static IEnumerable<PlatformRule> InferFromJsonElement(JsonElement element, string prefix, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in element.EnumerateObject())
            {
                var fieldPath = string.IsNullOrEmpty(path) ? prop.Name : $"{path}.{prop.Name}";

                // 检查字段名是否敏感
                if (SensitiveFields.TryGetValue(prop.Name, out var dataType))
                {
                    var ruleName = $"{prop.Name}_auto";
                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        yield return new PlatformRule
                        {
                            Name = ruleName,
                            Description = $"Auto-detected from field name: {prop.Name}",
                            Priority = 100,
                            Enabled = true,
                            Context = new ContextCondition { MinConfidence = 0.6 },
                            Matchers = new List<MatcherRule>(),
                            ScanLocations = new List<string> { "response.body.json" },
                            Extractors = new List<ExtractorRule>
                            {
                                new()
                                {
                                    Name = $"{prop.Name}_value",
                                    Source = "response_body",
                                    OutputField = "value",
                                    DataType = dataType,
                                    Pattern = $"\"{prop.Name}\"\\s*:\\s*\"([^\"]+)\""
                                }
                            }
                        };
                    }
                }

                // 递归嵌套
                if (prop.Value.ValueKind == JsonValueKind.Object || prop.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var child in InferFromJsonElement(prop.Value, prefix, fieldPath))
                        yield return child;
                }
            }
        }
    }

    private static PlatformRule? BuildFieldRule(string fieldName, string dataType, string description)
    {
        return new PlatformRule
        {
            Name = $"{fieldName}_from_desc",
            Description = $"Generated from: {description}",
            Priority = 100,
            Enabled = true,
            ScanLocations = new List<string> { "response.body", "response.headers", "request.body" },
            Extractors = new List<ExtractorRule>
            {
                new()
                {
                    Name = $"{fieldName}_value",
                    Source = "response_body",
                    OutputField = "value",
                    DataType = dataType,
                    Pattern = $"\"{fieldName}\"\\s*:\\s*\"([^\"]+)\""
                }
            }
        };
    }

    private static PlatformRule BuildWildcardRule(List<string> keywords, string description)
    {
        // 为多个关键词生成一个组合规则
        var patterns = keywords.Select(k =>
            $"\"{k}\"\\s*:\\s*\"([^\"]+)\"");

        return new PlatformRule
        {
            Name = "auto_wildcard",
            Description = description,
            Priority = 90,
            Enabled = true,
            ScanLocations = new List<string> { "response.body", "request.body" },
            Extractors = patterns.Select((p, i) => new ExtractorRule
            {
                Name = $"field_{i}",
                Source = "response_body",
                OutputField = "value",
                DataType = "raw",
                Pattern = p
            }).ToList()
        };
    }
}
