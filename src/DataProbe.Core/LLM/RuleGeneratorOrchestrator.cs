namespace DataProbe.Core.LLM;

/// <summary>
/// 规则生成编排器 — 按优先级试所有生成器，LLM 失败时回退到模板引擎。
///
/// 策略:
///   ① Ollama 可用 → 用 Ollama（高精度）
///   ② 模板引擎（兜底，始终可用）
///   ③ 合并结果，去重
/// </summary>
public class RuleGeneratorOrchestrator
{
    private readonly List<IRuleGeneratorPlugin> _generators = new();

    public RuleGeneratorOrchestrator()
    {
        // 先注册 LLM 生成器（高优先级）
        try
        {
            var ollama = new OllamaRuleGenerator();
            if (ollama.IsAvailable)
            {
                _generators.Add(ollama);
                Console.Error.WriteLine("[RuleGenerator] Ollama available");
            }
        }
        catch { }

        // 模板引擎始终作为兜底
        _generators.Add(new TemplateRuleGenerator());
    }

    /// <summary>注册自定义生成器插件</summary>
    public void Register(IRuleGeneratorPlugin generator)
    {
        _generators.Insert(0, generator); // 插到最前面（最高优先级）
    }

    /// <summary>从描述生成规则</summary>
    public async Task<RuleGenerationResult> GenerateAsync(
        string description,
        string? sampleData = null,
        CancellationToken ct = default)
    {
        var allRules = new List<PlatformRule>();
        var usedGenerator = "";

        foreach (var gen in _generators.OrderByDescending(g => g.Priority))
        {
            if (!gen.IsAvailable) continue;

            var result = await gen.GenerateFromDescriptionAsync(description, sampleData, ct);
            if (result.Success && result.Rules.Count > 0)
            {
                allRules.AddRange(result.Rules);
                usedGenerator = gen.Name;
                break; // 第一个成功的生成器优先
            }
        }

        return new RuleGenerationResult
        {
            Success = allRules.Count > 0,
            GeneratorName = usedGenerator,
            Rules = allRules,
            Confidence = usedGenerator == "ollama_local" ? 0.85f : 0.6f,
            Explanation = allRules.Count > 0
                ? $"Generated {allRules.Count} rules via {usedGenerator}"
                : "No rules could be generated"
        };
    }

    /// <summary>从样本数据推断规则</summary>
    public async Task<RuleGenerationResult> InferFromSampleAsync(
        string sampleData, string contentType, CancellationToken ct = default)
    {
        var allRules = new List<PlatformRule>();
        var usedGenerator = "";

        foreach (var gen in _generators.OrderByDescending(g => g.Priority))
        {
            if (!gen.IsAvailable) continue;

            var result = await gen.GenerateFromSampleAsync(sampleData, contentType, ct);
            if (result.Success && result.Rules.Count > 0)
            {
                allRules.AddRange(result.Rules);
                usedGenerator = gen.Name;
                break;
            }
        }

        return new RuleGenerationResult
        {
            Success = allRules.Count > 0,
            GeneratorName = usedGenerator,
            Rules = allRules,
            Confidence = 0.7f,
        };
    }
}
