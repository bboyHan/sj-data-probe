using System.Collections.Concurrent;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 默认对抗决策引擎 (ADE) 实现 — 五阶段调查流水线的"大脑"。
///
/// 职责：
///   阶段 I:  调用 TargetRecon 执行目标侦察 + 逆向分析 → TargetProfile
///   阶段 II: 根据 TargetProfile 选择通道组合 → ExecutionPlan
///   阶段 III: 监控通道健康，遇阻自动切换方案
///
/// 设计原则：
///   - 数据驱动：所有决策基于 TargetProfile 和通道 Capability
///   - 渐进降级：遇到防护自动降级方案，从最强方案逐步回退
///   - 可观测：所有决策日志对外暴露
/// </summary>
public class DefaultAdversarialDecisionEngine : IAdversarialDecisionEngine
{
    private readonly TargetRecon _recon;
    private readonly ChannelManager _channelManager;
    private readonly ConcurrentQueue<string> _decisionLog = new();

    /// <summary>最近一次决策日志</summary>
    public string[] RecentDecisionLog => _decisionLog.ToArray();

    public DefaultAdversarialDecisionEngine(ChannelManager channelManager)
    {
        _recon = new TargetRecon();
        _channelManager = channelManager ?? throw new ArgumentNullException(nameof(channelManager));
    }

    // ── 阶段 I: 目标洞察 ──

    public async Task<TargetProfile> AnalyzeTargetAsync(
        string target,
        byte[]? targetFile = null,
        CancellationToken ct = default)
    {
        Log($"=== 阶段 I: 目标洞察 ===");
        Log($"目标: {target}");

        // 执行网络侦察
        var profile = await _recon.ReconAsync(target, ct);

        Log($"  DNS: {profile.IPAddresses.Length} 个 IP");
        Log($"  TLS: {profile.TLSVersion ?? "N/A"}");
        Log($"  CDN: {profile.CDNProvider ?? "无"}");
        Log($"  防护评级: {profile.ProtectionRating}");

        // 如果有文件，执行逆向分析（骨架，具体由 RevEng 模块实现）
        if (targetFile != null && targetFile.Length > 0)
        {
            Log($"  逆向分析: 收到 {targetFile.Length} 字节的目标文件");
            // TODO: Phase 5 实现真正的逆向分析
            AnalyzeFile(targetFile, profile);
        }

        Log($"  推荐通道: {profile.RecommendedChannel}");
        return profile;
    }

    // ── 阶段 II: 突破策略 ──

    public ExecutionPlan CreateExecutionPlan(TargetProfile profile)
    {
        Log($"=== 阶段 II: 突破策略 ===");

        var plan = new ExecutionPlan
        {
            Summary = GeneratePlanSummary(profile),
            ExpectedCoverage = EstimateCoverage(profile),
            Limitations = GetLimitations(profile)
        };

        // 1. 通道选择
        var channels = SelectChannels(profile);
        plan.ChannelNames = channels;

        // 2. 解密方案选择
        plan.DecryptionMethods = SelectDecryptionMethods(profile);

        // 3. 仿真配置
        plan.TlsFingerprint = SelectTlsFingerprint(profile);

        // 4. SSLKEYLOGFILE（浏览器目标自动启用）
        plan.UseSslKeyLog = profile.Type == TargetType.Website;

        // 5. 验证码策略
        plan.CaptchaStrategy = profile.HasCaptcha ? CaptchaStrategyType.AutoOcr : CaptchaStrategyType.None;

        Log($"  方案: {plan.Summary}");
        Log($"  通道: {string.Join(", ", channels)}");
        Log($"  预期覆盖率: {plan.ExpectedCoverage}%");

        if (plan.Limitations.Length > 0)
        {
            Log($"  限制:");
            foreach (var limit in plan.Limitations)
                Log($"    - {limit}");
        }

        return plan;
    }

    // ── 阶段 III: 通道状态回调 ──

    public ExecutionPlan? OnChannelStatusChanged(string channelName, bool isHealthy, string? error)
    {
        if (isHealthy) return null;

        Log($"[ADE] 通道异常: {channelName} — {error}");

        // 检查可选备用通道
        var alternatives = _channelManager.SelectByCapability(c =>
            c.TargetScenarios.Contains("browser") && c.CanDecryptTls);

        var available = alternatives.FirstOrDefault(c =>
            !c.Name.Equals(channelName, StringComparison.OrdinalIgnoreCase));

        if (available != null)
        {
            Log($"[ADE] 自动切换: {channelName} → {available.Name}");
            return new ExecutionPlan
            {
                Summary = $"自动降级: {channelName} 异常，切换到 {available.Name}",
                ChannelNames = new[] { available.Name },
                DecryptionMethods = new[] { DecryptionMethod.CaMitm },
                ExpectedCoverage = 60,
                Limitations = new[] { $"因 {channelName} 异常自动降级" }
            };
        }

        Log($"[ADE] 无可用备用通道");
        return null;
    }

    // ── 通道选择逻辑 ──

    private string[] SelectChannels(TargetProfile profile)
    {
        var channels = new List<string>();
        var availableChannels = _channelManager.ChannelNames;

        switch (profile.ProtectionRating)
        {
            case ProtectionLevel.None:
                // 无防护 → 系统代理最简方案
                if (availableChannels.Contains("SystemProxy"))
                    channels.Add("SystemProxy");
                else if (availableChannels.Contains("TlsProxy"))
                    channels.Add("TlsProxy");
                break;

            case ProtectionLevel.Low:
                // 低防护 → 系统代理 + DNS
                if (availableChannels.Contains("SystemProxy"))
                    channels.Add("SystemProxy");
                if (availableChannels.Contains("DnsSpoof"))
                    channels.Add("DnsSpoof");
                if (availableChannels.Contains("WinDivert"))
                    channels.Add("WinDivert");
                break;

            case ProtectionLevel.Medium:
                // 中等防护 → 内核拦截 + DNS + TLS MITM
                if (availableChannels.Contains("WinDivert"))
                    channels.Add("WinDivert");
                if (availableChannels.Contains("DnsSpoof"))
                    channels.Add("DnsSpoof");
                if (availableChannels.Contains("TlsProxy"))
                    channels.Add("TlsProxy");
                break;

            case ProtectionLevel.High:
                // 高防护 → 进程 Hook（Phase 4 后实现）
                if (availableChannels.Contains("ProcessHook"))
                    channels.Add("ProcessHook");
                // 同时保留内核通道作为备选
                if (availableChannels.Contains("WinDivert"))
                    channels.Add("WinDivert");
                if (availableChannels.Contains("TlsProxy"))
                    channels.Add("TlsProxy");
                break;

            case ProtectionLevel.Extreme:
                // 极高防护 → 仅被动分析（不解密）
                channels.Add("Passive");
                break;

            default:
                channels.Add("SystemProxy");
                break;
        }

        return channels.ToArray();
    }

    private DecryptionMethod[] SelectDecryptionMethods(TargetProfile profile)
    {
        var methods = new List<DecryptionMethod>();

        switch (profile.ProtectionRating)
        {
            case ProtectionLevel.None:
            case ProtectionLevel.Low:
                methods.Add(DecryptionMethod.CaMitm);
                break;

            case ProtectionLevel.Medium:
                methods.Add(DecryptionMethod.CaMitm);
                if (profile.HasCertPinning)
                    methods.Add(DecryptionMethod.ProcessSslHook);
                break;

            case ProtectionLevel.High:
                methods.Add(DecryptionMethod.ProcessSslHook);
                methods.Add(DecryptionMethod.DotNetProfiler);
                break;

            case ProtectionLevel.Extreme:
                // 不解密
                break;
        }

        return methods.ToArray();
    }

    private static FingerprintConfig? SelectTlsFingerprint(TargetProfile profile)
    {
        return profile.Type switch
        {
            TargetType.Website => new FingerprintConfig { Profile = "chrome_122" },
            TargetType.MobileApp => new FingerprintConfig { Profile = "okhttp_4" },
            TargetType.PcGame => new FingerprintConfig { Profile = "chrome_122" },
            _ => null
        };
    }

    // ── 辅助方法 ──

    private static string GeneratePlanSummary(TargetProfile profile)
    {
        return profile.ProtectionRating switch
        {
            ProtectionLevel.None => "零配置方案：系统代理 + TLS MITM",
            ProtectionLevel.Low => "标准方案：系统代理/WinDivert + DNS + TLS MITM",
            ProtectionLevel.Medium => "增强方案：内核拦截 + DNS 劫持 + TLS 解密",
            ProtectionLevel.High => "深度方案：进程注入 + SSL Hook + TLS 解密",
            ProtectionLevel.Extreme => "极限方案：仅被动分析（不解密）",
            _ => "默认方案：系统代理"
        };
    }

    private static int EstimateCoverage(TargetProfile profile)
    {
        return profile.ProtectionRating switch
        {
            ProtectionLevel.None => 95,
            ProtectionLevel.Low => 85,
            ProtectionLevel.Medium => 70,
            ProtectionLevel.High => 50,
            ProtectionLevel.Extreme => 20,
            _ => 80
        };
    }

    private static string[] GetLimitations(TargetProfile profile)
    {
        var limitations = new List<string>();

        if (profile.HasCertPinning)
            limitations.Add("目标可能使用了证书锁定，标准 MITM 不可用");

        if (!string.IsNullOrEmpty(profile.CDNProvider))
            limitations.Add($"目标使用了 {profile.CDNProvider} CDN，可能包含 WAF 防护");

        if (profile.ProtectionRating >= ProtectionLevel.High)
            limitations.Add("高防护目标可能需要进程注入，操作员权限要求较高");

        return limitations.ToArray();
    }

    /// <summary>
    /// 文件分析骨架（Phase 5 完整实现）
    /// </summary>
    private static void AnalyzeFile(byte[] fileData, TargetProfile profile)
    {
        // 检查文件魔数判断类型
        if (fileData.Length > 4)
        {
            if (fileData[0] == 0x50 && fileData[1] == 0x4B) // ZIP/APK
                profile.Type = TargetType.MobileApp;
            else if (fileData[0] == 0x4D && fileData[1] == 0x5A) // MZ/PE
                profile.Type = TargetType.PcGame;
        }
    }

    private void Log(string message)
    {
        _decisionLog.Enqueue($"[{DateTime.UtcNow:HH:mm:ss}] {message}");
        if (_decisionLog.Count > 100)
            _decisionLog.TryDequeue(out _);
        Console.Error.WriteLine(message);
    }
}
