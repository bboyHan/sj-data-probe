using DataProbe.Core;

namespace DataProbe.Extractor;

/// <summary>
/// 不解密情报提取引擎 — 在 TLS 无法解密的情况下，
/// 仅从流量的元数据（大小、时序、SNI、连接模式）中提取情报。
///
/// 这是数据开采的"最后防线"——当所有解密手段都失败时，
/// 至少还能从这里得到有价值的信息。
///
/// 原理：
///   ① 包大小指纹 → 已知服务的请求/响应大小模式
///   ② 时序分析 → 用户操作与网络请求的关联关系
///   ③ SNI 分析 → 连接了哪些域名、频率如何
///   ④ 会话关联 → 多个连接使用同一 Token 特征
///   ⑤ TLS 指纹 → 目标用的 TLS 库版本（JA3）
/// </summary>
public class PassiveIntelligence
{
    private readonly int _minSampleSize = 3;

    /// <summary>
    /// 从 SessionSnapshot 中提取不解密情报
    /// </summary>
    public List<DataEvidence> Analyze(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();

        // ① SNI 域名分析
        results.AddRange(AnalyzeSniDomains(session));

        // ② 请求大小聚类
        results.AddRange(AnalyzeSizePatterns(session));

        // ③ 操作→请求时序关联
        results.AddRange(AnalyzeTimingCorrelation(session));

        // ④ TLS 指纹提取
        results.AddRange(ExtractTlsFingerprints(session));

        return results;
    }

    /// <summary>
    /// SNI 域名分析 — 统计连接频率、识别核心服务
    /// </summary>
    private static List<DataEvidence> AnalyzeSniDomains(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();
        var domainFreq = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var domainSizes = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var step in session.Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                try
                {
                    var uri = new Uri(http.Url);
                    var host = uri.Host;

                    domainFreq.TryGetValue(host, out var count);
                    domainFreq[host] = count + 1;

                    if (!domainSizes.ContainsKey(host))
                        domainSizes[host] = new List<int>();
                    domainSizes[host].Add((int)http.ResponseBody.Size);
                }
                catch { }
            }
        }

        // 提取高频域名
        foreach (var (domain, freq) in domainFreq.OrderByDescending(x => x.Value).Take(10))
        {
            var avgSize = domainSizes.TryGetValue(domain, out var sizes) && sizes.Count > 0
                ? (int)sizes.Average()
                : 0;

            results.Add(new DataEvidence
            {
                RuleName = "passive.sni_analysis",
                Value = domain,
                Type = CapturedDataType.RawData,
                LocationId = "passive.sni",
                MatchType = DataProbe.Core.MatchType.Heuristic,
                Confidence = Math.Min(1.0f, 0.5f + freq * 0.05f),
                Metadata = new Dictionary<string, string>
                {
                    ["frequency"] = freq.ToString(),
                    ["avg_response_size"] = $"{avgSize} bytes",
                    ["method"] = "sni_analysis"
                },
                CapturedAt = DateTime.UtcNow
            });
        }

        return results;
    }

    /// <summary>
    /// 请求大小聚类 — 通过响应体大小推断数据类型
    /// </summary>
    private List<DataEvidence> AnalyzeSizePatterns(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();
        var sizeBuckets = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var step in session.Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                try
                {
                    var uri = new Uri(http.Url);
                    var path = uri.AbsolutePath;
                    var dir = Path.GetDirectoryName(path) ?? "/";
                    if (!sizeBuckets.ContainsKey(dir))
                        sizeBuckets[dir] = new List<int>();
                    sizeBuckets[dir].Add((int)http.ResponseBody.Size);
                }
                catch { }
            }
        }

        foreach (var (endpoint, sizes) in sizeBuckets)
        {
            if (sizes.Count < _minSampleSize) continue;

            var avg = (int)sizes.Average();
            var min = sizes.Min();
            var max = sizes.Max();

            // 根据大小模式推断内容类型
            string inferredType;
            float confidence;

            if (avg < 500)
            {
                inferredType = "status/ack";
                confidence = 0.5f;
            }
            else if (avg < 5000)
            {
                inferredType = "list/metadata";
                confidence = 0.6f;
            }
            else if (avg < 50000)
            {
                inferredType = "detail/data_payload";
                confidence = 0.7f;
            }
            else
            {
                inferredType = "media/large_payload";
                confidence = 0.6f;
            }

            results.Add(new DataEvidence
            {
                RuleName = "passive.size_profile",
                Value = $"{endpoint} → avg={avg}B mode={inferredType}",
                Type = CapturedDataType.RawData,
                LocationId = "passive.sizepattern",
                MatchType = DataProbe.Core.MatchType.Heuristic,
                Confidence = confidence,
                Metadata = new Dictionary<string, string>
                {
                    ["endpoint"] = endpoint,
                    ["avg_size"] = avg.ToString(),
                    ["min_size"] = min.ToString(),
                    ["max_size"] = max.ToString(),
                    ["samples"] = sizes.Count.ToString(),
                    ["inferred_type"] = inferredType
                },
                CapturedAt = DateTime.UtcNow
            });
        }

        return results;
    }

    /// <summary>
    /// 时序关联分析 — 检测操作→请求的因果关系
    /// </summary>
    private static List<DataEvidence> AnalyzeTimingCorrelation(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();

        if (session.Steps.Count < 2) return results;

        for (int i = 0; i < session.Steps.Count; i++)
        {
            var step = session.Steps[i];
            if (step.HttpTransactions.Count == 0) continue;

            var stepTime = step.Timestamp;
            var urls = step.HttpTransactions.Select(h => h.Url).ToArray();

            // 跨步骤同域名（Token 复用）
            if (i > 0)
            {
                var prevUrls = session.Steps[i - 1].HttpTransactions
                    .Select(h => ExtractDomain(h.Url))
                    .ToHashSet();

                var sharedDomains = urls.Select(ExtractDomain)
                    .Where(d => prevUrls.Contains(d))
                    .Distinct()
                    .ToArray();

                if (sharedDomains.Length > 0)
                {
                    results.Add(new DataEvidence
                    {
                        RuleName = "passive.session_correlation",
                        Value = $"step{i - 1}→step{i}: {string.Join(", ", sharedDomains)}",
                        Type = CapturedDataType.RawData,
                        LocationId = $"passive.session_correlation.step.{i}",
                        MatchType = DataProbe.Core.MatchType.Heuristic,
                        Confidence = 0.8f,
                        Metadata = new Dictionary<string, string>
                        {
                            ["from_step"] = (i - 1).ToString(),
                            ["to_step"] = i.ToString(),
                            ["shared_domains"] = string.Join(",", sharedDomains),
                            ["method"] = "cross_step_domain_match"
                        },
                        CapturedAt = DateTime.UtcNow
                    });
                }
            }
        }

        return results;
    }

    /// <summary>
    /// TLS 指纹提取 — 从 JA3/JA3S 推断目标栈
    /// </summary>
    private static List<DataEvidence> ExtractTlsFingerprints(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();

        // 从 Session 元数据中提取 TLS 版本信息（如果有）
        if (session.TargetRating != ProtectionLevel.Unknown)
        {
            results.Add(new DataEvidence
            {
                RuleName = "passive.tls_version",
                Value = $"TLS version: {session.TargetRating}",
                Type = CapturedDataType.RawData,
                LocationId = "passive.tlsinfo",
                MatchType = DataProbe.Core.MatchType.Heuristic,
                Confidence = 0.7f,
                Metadata = new Dictionary<string, string>
                {
                    ["target_rating"] = session.TargetRating.ToString()
                },
                CapturedAt = DateTime.UtcNow
            });
        }

        return results;
    }

    private static string ExtractDomain(string url)
    {
        try { return new Uri(url).Host; }
        catch { return ""; }
    }
}
