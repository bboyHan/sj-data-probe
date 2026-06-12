using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataProbe.Core.LLM;

/// <summary>
/// Ollama 规则生成器 — 调用本地运行的 Ollama (qwen2.5 等模型)。
/// 纯本地，数据不出机器，零成本。
///
/// 当 Ollama 服务不可用时，IsAvailable 返回 false，
/// 编排器自动回退到 TemplateRuleGenerator。
/// </summary>
public class OllamaRuleGenerator : IRuleGeneratorPlugin, IDisposable
{
    public string Name => "ollama_local";
    public string Version => "1.0.0";
    public int Priority => 50;
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private string _model = "qwen2.5:3b";

    /// <summary>Ollama 服务地址</summary>
    public string BaseUrl
    {
        get => _baseUrl;
        init { }
    }

    /// <summary>使用的模型名称</summary>
    public string Model { get => _model; set => _model = value; }

    public OllamaRuleGenerator(string baseUrl = "http://localhost:11434")
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
    }

    /// <summary>检测 Ollama 是否可用</summary>
    public bool IsAvailable
    {
        get
        {
            try
            {
                var response = _http.GetAsync($"{_baseUrl}/api/tags")
                    .WaitAsync(TimeSpan.FromSeconds(2)).Result;
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }

    public async Task<RuleGenerationResult> GenerateFromDescriptionAsync(
        string description, string? sampleResponse = null, CancellationToken ct = default)
    {
        var result = new RuleGenerationResult { GeneratorName = Name };

        try
        {
            if (!IsAvailable)
            {
                result.Success = false;
                result.ErrorMessage = "Ollama not available";
                return result;
            }

            // 构造 prompt
            var prompt = BuildPrompt(description, sampleResponse);

            // 调用 Ollama
            var requestBody = new
            {
                model = _model,
                prompt = prompt,
                stream = false,
                options = new { temperature = 0.1, num_predict = 2048 }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _http.PostAsync($"{_baseUrl}/api/generate", content, ct);
            var responseJson = await response.Content.ReadAsStringAsync(ct);

            using var doc = JsonDocument.Parse(responseJson);
            var rawOutput = doc.RootElement.GetProperty("response").GetString() ?? "";

            // 从 LLM 输出中提取 JSON 规则
            result.Rules = ParseRulesFromLlmOutput(rawOutput).ToList();
            result.Success = result.Rules.Count > 0;
            result.Confidence = result.Rules.Count > 0 ? 0.85f : 0f;
            result.Explanation = result.Rules.Count > 0
                ? $"Ollama generated {result.Rules.Count} rules"
                : "Ollama response did not contain valid rules";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    public async Task<RuleGenerationResult> GenerateFromSampleAsync(
        string sampleData, string contentType, CancellationToken ct = default)
    {
        return await GenerateFromDescriptionAsync(
            $"Extract all valuable fields from this {contentType} response",
            sampleData, ct);
    }

    private static string BuildPrompt(string description, string? sample)
    {
        var prompt = "You are a data extraction rule generator. Convert the user's request into JSON extraction rules.\n\nFormat:\n{\n  \"name\": \"rule_name\",\n  \"description\": \"...\",\n  \"priority\": 100,\n  \"enabled\": true,\n  \"scan_locations\": [\"response.body\"],\n  \"extractors\": [\n    {\"name\": \"field\", \"source\": \"response_body\", \"output_field\": \"value\", \"data_type\": \"token\", \"pattern\": \"\\\"key\\\"\\\\s*:\\\\s*\\\"([^\\\"]+)\\\"\"}\n  ]\n}\n\nUser request: " + description;

        if (!string.IsNullOrEmpty(sample))
        {
            prompt += $"\n\nSample data to analyze:\n{sample[..Math.Min(sample.Length, 2000)]}\n";
        }

        prompt += "\n\nReturn ONLY a JSON array of rule objects, no explanation text.";

        return prompt;
    }

    private static List<PlatformRule> ParseRulesFromLlmOutput(string output)
    {
        var rules = new List<PlatformRule>();
        try
        {
            var start = output.IndexOf('[');
            if (start < 0) { start = output.IndexOf('{'); if (start < 0) return rules; }

            var end = output.LastIndexOf(']');
            if (end < 0) { end = output.LastIndexOf('}') + 1; return rules; }
            else { end += 1; }

            if (end <= start) return rules;
            var json = output[start..end];

            if (json.TrimStart().StartsWith("["))
            {
                using var doc = JsonDocument.Parse(json);
                foreach (var element in doc.RootElement.EnumerateArray())
                {
                    var rule = JsonSerializer.Deserialize<PlatformRule>(
                        element.GetRawText(),
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (rule != null && !string.IsNullOrEmpty(rule.Name))
                        rules.Add(rule);
                }
            }
            else
            {
                var rule = JsonSerializer.Deserialize<PlatformRule>(
                    json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (rule != null && !string.IsNullOrEmpty(rule.Name))
                    rules.Add(rule);
            }
        }
        catch { }
        return rules;
    }

    public void Dispose() => _http.Dispose();
}
