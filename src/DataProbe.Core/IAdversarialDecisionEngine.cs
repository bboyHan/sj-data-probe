namespace DataProbe.Core;

/// <summary>
/// 对抗决策引擎 (ADE) 接口。
/// ADE 是贯穿五阶段调查流水线的"大脑"：
///   阶段 I: 调用 AnalyzeTargetAsync() 获取目标情报
///   阶段 II: 调用 CreateExecutionPlan() 生成突破策略
///   阶段 III: 调用 OnChannelStatusChanged() 接收通道回调
///             遇阻时自动重新规划
///   阶段 IV: 无（数据分析由 RuleEngine 执行）
///   阶段 V: 无（报告生成由 ReportGenerator 执行）
/// </summary>
public interface IAdversarialDecisionEngine
{
    /// <summary>
    /// 阶段 I: 分析目标，生成情报报告。
    /// 并行执行网络侦察和（如果提供文件）逆向分析。
    /// </summary>
    /// <param name="target">目标标识：域名 / URL / App 包名 / 文件路径</param>
    /// <param name="targetFile">目标文件（可选）：APK/IPA/DLL/EXE</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>目标情报报告</returns>
    Task<TargetProfile> AnalyzeTargetAsync(
        string target,
        byte[]? targetFile = null,
        CancellationToken ct = default);

    /// <summary>
    /// 阶段 II: 根据目标情报生成执行计划。
    /// 选择通道、解密方案、仿真配置。
    /// </summary>
    ExecutionPlan CreateExecutionPlan(TargetProfile profile);

    /// <summary>
    /// 阶段 III 回调: 通道状态变更通知。
    /// ADE 根据此信息判断是否需要切换通道。
    /// </summary>
    /// <param name="channelName">通道名称</param>
    /// <param name="isHealthy">是否健康</param>
    /// <param name="error">错误信息（如果有）</param>
    /// <returns>如果返回新计划，表示需要切换通道</returns>
    ExecutionPlan? OnChannelStatusChanged(string channelName, bool isHealthy, string? error);
}

/// <summary>
/// 规则引擎接口 — 在 SessionSnapshot 上执行规则提取。
/// </summary>
public interface IRuleEngine
{
    /// <summary>规则数量</summary>
    int RuleCount { get; }

    /// <summary>
    /// 在完整的操作流快照上执行所有启用的规则。
    /// </summary>
    /// <param name="session">操作流快照</param>
    /// <returns>所有匹配到的证据</returns>
    Task<List<DataEvidence>> ProcessSessionAsync(SessionSnapshot session);

    /// <summary>获取所有规则</summary>
    List<PlatformRule> GetAllRules();

    /// <summary>保存规则（创建或更新）</summary>
    void SaveRule(PlatformRule rule);

    /// <summary>删除规则</summary>
    bool DeleteRule(string id);

    /// <summary>加载规则（从 platforms 目录）</summary>
    void LoadRules();
}

/// <summary>
/// 调查上下文 — 贯穿五阶段流水线的状态。
/// </summary>
public class InvestigationContext
{
    /// <summary>调查唯一标识</summary>
    public string InvestigationId { get; init; } = $"inv_{Guid.NewGuid():N}";

    /// <summary>目标输入（用户提供的原始输入）</summary>
    public string TargetInput { get; set; } = "";

    /// <summary>目标文件（用户提供的二进制文件）</summary>
    public byte[]? TargetFile { get; set; }

    /// <summary>启用的规则包名称列表</summary>
    public string[] EnabledRulePacks { get; set; } = Array.Empty<string>();

    // ── 阶段产出 ──

    /// <summary>阶段 I 产出</summary>
    public TargetProfile? TargetProfile { get; set; }

    /// <summary>阶段 II 产出</summary>
    public ExecutionPlan? ExecutionPlan { get; set; }

    /// <summary>阶段 III 产出</summary>
    public SessionSnapshot? Session { get; set; }

    /// <summary>阶段 IV 产出</summary>
    public List<DataEvidence>? Evidences { get; set; }

    // ── 状态 ──

    /// <summary>当前阶段</summary>
    public InvestigationPhase CurrentPhase { get; set; } = InvestigationPhase.TargetInsight;

    /// <summary>开始时间</summary>
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    /// <summary>完成时间</summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>是否遇阻降级</summary>
    public bool HasDegraded { get; set; }

    /// <summary>通道异常日志</summary>
    public List<ChannelEvent> ChannelEvents { get; set; } = new();
}

/// <summary>
/// 调查阶段
/// </summary>
public enum InvestigationPhase
{
    TargetInsight,   // 阶段 I: 目标洞察
    BreachPlanning,  // 阶段 II: 突破策略
    DataCapture,     // 阶段 III: 数据捕获
    Analysis,        // 阶段 IV: 数据分析
    Reporting,       // 阶段 V: 报告呈现
    Completed,
    Failed
}

/// <summary>
/// 通道事件（用于异常日志）
/// </summary>
public class ChannelEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string ChannelName { get; set; } = "";
    public ChannelEventType Type { get; set; }
    public string? Message { get; set; }
}

public enum ChannelEventType
{
    Started,
    Healthy,
    Unhealthy,
    Error,
    Restarted,
    Degraded,
    Switched
}
