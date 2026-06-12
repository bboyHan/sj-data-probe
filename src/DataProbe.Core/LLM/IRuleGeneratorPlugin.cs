namespace DataProbe.Core.LLM;

/// <summary>
/// 规则生成器插件 — 将自然语言描述或样本数据转换为提取规则。
///
/// 不依赖任何特定 LLM。实现可以是:
///   - 本地 LLM (Ollama/Qwen)
///   - 云端 API (OpenAI/Claude)
///   - 零 LLM 模板引擎（兜底）
/// </summary>
public interface IRuleGeneratorPlugin
{
    string Name { get; }
    string Version { get; }
    int Priority { get; }  // 高优先级先生效

    /// <summary>判断此生成器是否可用（例如: LLM 是否在运行）</summary>
    bool IsAvailable { get; }

    /// <summary>从自然语言描述生成规则</summary>
    Task<RuleGenerationResult> GenerateFromDescriptionAsync(
        string description,
        string? sampleResponse = null,
        CancellationToken ct = default);

    /// <summary>从样本数据自动推断规则</summary>
    Task<RuleGenerationResult> GenerateFromSampleAsync(
        string sampleData,
        string contentType,
        CancellationToken ct = default);
}

public class RuleGenerationResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string GeneratorName { get; set; } = "";

    /// <summary>生成的规则列表</summary>
    public List<PlatformRule> Rules { get; set; } = new();

    /// <summary>人类可读的说明</summary>
    public string? Explanation { get; set; }

    /// <summary>置信度 (0-1)</summary>
    public float Confidence { get; set; }
}
