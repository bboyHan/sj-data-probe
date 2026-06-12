namespace DataProbe.Core;

/// <summary>
/// 风控规避策略引擎 — 当检测到风控信号时自动切换出口、
/// 指纹、行为模式。避免被目标系统的风控模型持续跟踪。
///
/// 风控信号：
///   - 419/429/423 状态码
///   - 验证码突然出现
///   - 请求被静默丢弃
///   - 响应时间异常增加
///   - 设备指纹被拒绝
///
/// 规避策略：
///   - IP 轮换（代理切换）
///   - 设备指纹切换
///   - 请求速率限制
///   - 行为模式切换（normal → human）
/// </summary>
public class RiskControlEvasion
{
    private readonly Random _rng = new();

    /// <summary>当前 IP 地址</summary>
    public string? CurrentIp { get; set; }

    /// <summary>代理列表（用于 IP 轮换）</summary>
    public string[] ProxyList { get; set; } = Array.Empty<string>();

    /// <summary>连续请求计数（用于自动限速）</summary>
    public int RequestCount { get; private set; }

    /// <summary>风控触发次数</summary>
    public int RiskTriggeredCount { get; private set; }

    /// <summary>检测是否为风控响应</summary>
    public static bool IsRiskResponse(int statusCode, string responseBody)
    {
        if (statusCode is 419 or 429 or 423) return true;
        if (statusCode == 200 && string.IsNullOrWhiteSpace(responseBody)) return true;
        return false;
    }

    /// <summary>触发风控处理 — 限速 + 切换</summary>
    public RiskAction HandleRiskTriggered()
    {
        RiskTriggeredCount++;
        var action = new RiskAction();

        // 每次触发增加延迟
        action.DelayMs = Math.Min(5000, 1000 * RiskTriggeredCount);

        // 连续触发 3 次以上 → 换 IP
        if (RiskTriggeredCount >= 3 && ProxyList.Length > 0)
        {
            action.SwitchProxy = true;
            action.NewProxy = ProxyList[_rng.Next(ProxyList.Length)];
        }

        // 连续触发 5 次以上 → 切换行为模式到 human
        if (RiskTriggeredCount >= 5)
        {
            action.SwitchBehavior = true;
            action.NewBehaviorMode = "human";
        }

        Console.Error.WriteLine($"[RiskControl] Triggered #{RiskTriggeredCount}: {action}");
        return action;
    }

    /// <summary>请求速率限制 — 返回需要等待的毫秒数</summary>
    public int Throttle()
    {
        RequestCount++;

        if (RequestCount < 10) return 0;
        if (RequestCount < 30) return _rng.Next(100, 500);
        if (RequestCount < 100) return _rng.Next(500, 2000);
        return _rng.Next(2000, 5000);
    }

    /// <summary>重置计数器</summary>
    public void Reset()
    {
        RequestCount = 0;
        RiskTriggeredCount = 0;
    }
}

public class RiskAction
{
    public int DelayMs { get; set; }
    public bool SwitchProxy { get; set; }
    public string? NewProxy { get; set; }
    public bool SwitchBehavior { get; set; }
    public string? NewBehaviorMode { get; set; }

    public override string ToString()
    {
        var parts = new List<string> { $"delay={DelayMs}ms" };
        if (SwitchProxy) parts.Add($"proxy→{NewProxy}");
        if (SwitchBehavior) parts.Add($"mode→{NewBehaviorMode}");
        return string.Join(", ", parts);
    }
}
