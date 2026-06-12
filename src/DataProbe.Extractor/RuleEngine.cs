using System.Text.Json;
using DataProbe.Core;

namespace DataProbe.Extractor;

/// <summary>
/// 规则引擎 — 加载 platforms/*.json 规则文件，
/// 对 SessionSnapshot 进行全位置匹配 → 提取 → 输出 DataEvidence。
///
/// 核心设计原则：
///   - 数据驱动：规则是 JSON，不是代码
///   - 零硬编码：不需要为任何平台写 C# 代码
///   - 热加载：修改 JSON 后自动生效（通过文件监视）
///   - 全位置：规则可指定扫描操作流中的任意数据位置
/// </summary>
public class RuleEngine : IRuleEngine, IDisposable
{
    private List<PlatformRule> _rules = new();
    private readonly string _rulesDir;
    private readonly FileSystemWatcher? _watcher;
    private readonly object _lock = new();
    private readonly DataProbeConfig? _config;

    public RuleEngine(DataProbeConfig? config = null, string? rulesDir = null)
    {
        _config = config;
        _rulesDir = rulesDir ?? Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "platforms");

        Directory.CreateDirectory(_rulesDir);
        LoadRules();

        // 文件监视（热更新）
        try
        {
            _watcher = new FileSystemWatcher(_rulesDir, "*.json")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };
            _watcher.Changed += (_, _) => LoadRules();
            _watcher.Created += (_, _) => LoadRules();
            _watcher.EnableRaisingEvents = true;
        }
        catch { /* 文件监视非必需 */ }
    }

    public int RuleCount
    {
        get { lock (_lock) return _rules.Count; }
    }

    /// <summary>
    /// 获取所有规则（带 ID 和统计）
    /// </summary>
    public List<PlatformRule> GetAllRules()
    {
        lock (_lock) return new List<PlatformRule>(_rules);
    }

    /// <summary>
    /// 保存规则（创建或更新）
    /// </summary>
    public void SaveRule(PlatformRule rule)
    {
        var id = rule.Id ?? rule.Name;
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Rule must have a Name or Id");

        rule.Id = id;
        var filePath = Path.Combine(_rulesDir, $"{id}.json");

        // 兼容处理：如果使用了 Fields 而不是 Extractors
        if (rule.Fields.Count > 0 && (rule.Extractors == null || rule.Extractors.Count == 0))
        {
            rule.Extractors = rule.CompileFields();
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        var json = JsonSerializer.Serialize(rule, options);
        File.WriteAllText(filePath, json);
        // LoadRules() 会通过 FileSystemWatcher 自动触发
    }

    /// <summary>
    /// 删除规则
    /// </summary>
    public bool DeleteRule(string id)
    {
        var filePath = Path.Combine(_rulesDir, $"{id}.json");
        if (!File.Exists(filePath)) return false;
        File.Delete(filePath);
        return true;
    }

    /// <summary>
    /// 在操作流快照上执行所有启用的规则（核心方法）。
    /// </summary>
    public async Task<List<DataEvidence>> ProcessSessionAsync(SessionSnapshot session)
    {
        List<PlatformRule> rules;
        lock (_lock) rules = _rules;

        var results = new List<DataEvidence>();

        foreach (var rule in rules)
        {
            if (!rule.Enabled) continue;

            // 检查上下文条件
            if (rule.Context != null && !rule.Context.IsActive(session))
                continue;

            // 检查旧版 Matcher（兼容）
            if (rule.Matchers.Count > 0)
            {
                // 旧版规则需要逐事务匹配
                foreach (var step in session.Steps)
                {
                    foreach (var http in step.HttpTransactions)
                    {
                        var tx = ToNormalizedTransaction(http);
                        var matched = rule.Matchers.All(m => m.IsMatch(tx));
                        if (!matched) continue;

                        var extras = RunExtractors(rule, tx, http);
                        results.AddRange(extras);
                    }
                }
            }

            // 新版全位置扫描
            if (rule.ScanLocations.Count > 0 && rule.Extractors.Count > 0)
            {
                var sessionEvidence = ScanSessionPositions(session, rule);
                results.AddRange(sessionEvidence);
            }
        }

        // 启发式提取（如果启用）
        if (_config?.EnableHeuristicExtraction != false)
        {
            try
            {
                var heuristic = new HeuristicExtractor(
                    _config?.HeuristicEntropyThreshold ?? 4.5);
                var heuristicResults = heuristic.Extract(session);
                results.AddRange(heuristicResults);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] Heuristic extraction error: {ex.Message}");
            }
        }

        // 不解密情报提取（始终运行—不需要解密）
        try
        {
            var passive = new PassiveIntelligence();
            var passiveResults = passive.Analyze(session);
            results.AddRange(passiveResults);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[RuleEngine] Passive intelligence error: {ex.Message}");
        }

        return await Task.FromResult(results);
    }

    /// <summary>
    /// 在 Session 的指定位置上执行规则扫描
    /// </summary>
    private List<DataEvidence> ScanSessionPositions(SessionSnapshot session, PlatformRule rule)
    {
        var results = new List<DataEvidence>();
        var locations = rule.ScanLocations;

        foreach (var step in session.Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                var fragments = GetLocationFragments(http, locations);
                foreach (var (locationId, fragment) in fragments)
                {
                    if (fragment.Size == 0) continue;

                    foreach (var ext in rule.Extractors)
                    {
                        var matched = TryExtractFromFragment(ext, fragment, locationId, out var value);
                        if (!matched || string.IsNullOrEmpty(value)) continue;

                        var evidence = new DataEvidence
                        {
                            RuleName = rule.Name,
                            Value = value,
                            Type = ParseCapturedDataType(ext.DataType),
                            LocationId = locationId,
                            StepIndex = step.StepIndex,
                            RequestUrl = http.Url,
                            RawSnippet = Truncate(fragment.RawText, 200),
                            MatchType = DataProbe.Core.MatchType.Regex,
                            Confidence = 1.0f,
                            CapturedAt = DateTime.UtcNow
                        };
                        evidence.Metadata["rule_name"] = rule.Name;
                        evidence.Metadata["domain"] = ExtractDomain(http.Url);
                        evidence.Metadata["path"] = ExtractPath(http.Url);

                        results.Add(evidence);
                        rule.TotalCaptured++;
                        rule.LastMatchedAt = DateTime.UtcNow;
                    }
                }
            }

            // WebSocket 消息
            foreach (var ws in step.WebSocketMessages)
            {
                if (!locations.Any(l => l.StartsWith("websocket"))) continue;

                foreach (var ext in rule.Extractors)
                {
                    var match = ext.CompiledRegex?.Match(ws.Payload);
                    if (match?.Success == true)
                    {
                        var value = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                        var evidence = new DataEvidence
                        {
                            RuleName = rule.Name,
                            Value = value,
                            Type = ParseCapturedDataType(ext.DataType),
                            LocationId = ws.LocationId,
                            StepIndex = step.StepIndex,
                            RawSnippet = Truncate(ws.Payload, 200),
                            MatchType = DataProbe.Core.MatchType.Regex,
                            Confidence = 1.0f,
                            CapturedAt = DateTime.UtcNow
                        };
                        results.Add(evidence);
                        rule.TotalCaptured++;
                        rule.LastMatchedAt = DateTime.UtcNow;
                    }
                }
            }

            // URL Schema
            foreach (var schema in step.UrlSchemes)
            {
                if (!locations.Any(l => l.StartsWith("url.schema"))) continue;

                foreach (var ext in rule.Extractors)
                {
                    var match = ext.CompiledRegex?.Match(schema.Uri);
                    if (match?.Success == true)
                    {
                        var value = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                        results.Add(new DataEvidence
                        {
                            RuleName = rule.Name,
                            Value = value,
                            Type = ParseCapturedDataType(ext.DataType),
                            LocationId = schema.LocationId,
                            StepIndex = step.StepIndex,
                            RawSnippet = Truncate(schema.Uri, 200),
                            Confidence = 1.0f,
                            CapturedAt = DateTime.UtcNow
                        });
                        rule.TotalCaptured++;
                        rule.LastMatchedAt = DateTime.UtcNow;
                    }
                }
            }
        }

        return results;
    }

    /// <summary>
    /// 根据位置标识列表获取对应的 DataFragment
    /// </summary>
    private static List<(string LocationId, DataFragment)> GetLocationFragments(HttpTransaction http, List<string> locations)
    {
        var result = new List<(string, DataFragment)>();

        foreach (var loc in locations)
        {
            switch (loc.ToLower())
            {
                case "request.url":
                    result.Add(($"step.{http.StepIndex}.request.url", http.RequestUrl));
                    break;
                case "request.headers":
                    result.Add(($"step.{http.StepIndex}.request.headers", http.RequestHeaders));
                    break;
                case "request.body":
                    result.Add(($"step.{http.StepIndex}.request.body", http.RequestBody));
                    break;
                case "response.headers":
                    result.Add(($"step.{http.StepIndex}.response.headers", http.ResponseHeaders));
                    break;
                case "response.body":
                    result.Add(($"step.{http.StepIndex}.response.body", http.ResponseBody));
                    break;
                case "response.status":
                    result.Add(($"step.{http.StepIndex}.response.status", http.ResponseStatus));
                    break;
                case "any":
                    // "any" = 所有位置
                    result.Add(($"step.{http.StepIndex}.request.url", http.RequestUrl));
                    result.Add(($"step.{http.StepIndex}.request.headers", http.RequestHeaders));
                    result.Add(($"step.{http.StepIndex}.request.body", http.RequestBody));
                    result.Add(($"step.{http.StepIndex}.response.headers", http.ResponseHeaders));
                    result.Add(($"step.{http.StepIndex}.response.body", http.ResponseBody));
                    result.Add(($"step.{http.StepIndex}.response.status", http.ResponseStatus));
                    break;
            }
        }

        return result;
    }

    /// <summary>
    /// 从 DataFragment 中提取匹配值
    /// </summary>
    private static bool TryExtractFromFragment(ExtractorRule ext, DataFragment fragment, string locationId, out string? value)
    {
        value = null;

        // 优先使用 AsPairs（适用于 Headers）
        if (fragment.AsPairs.Count > 0 && ext.Source.StartsWith("header."))
        {
            var headerName = ext.Source["header.".Length..].Trim();
            if (fragment.AsPairs.TryGetValue(headerName, out var v))
            {
                value = v;
                return true;
            }
            return false;
        }

        // 正则匹配 RawText
        if (ext.CompiledRegex != null && !string.IsNullOrEmpty(fragment.RawText))
        {
            var match = ext.CompiledRegex.Match(fragment.RawText);
            if (match.Success)
            {
                value = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 旧版提取器兼容
    /// </summary>
    private List<DataEvidence> RunExtractors(PlatformRule rule, NormalizedTransaction tx, HttpTransaction http)
    {
        var results = new List<DataEvidence>();
        var cred = new Credential
        {
            Type = CapturedDataType.RawData,
            Platform = rule.Name,
            Source = "rule_engine",
            Metadata = new Dictionary<string, string>
            {
                ["rule_name"] = rule.Name,
                ["domain"] = tx.Domain,
                ["path"] = tx.Path,
            }
        };

        var extractors = rule.Extractors;
        if ((extractors == null || extractors.Count == 0) && rule.Fields?.Count > 0)
            extractors = rule.CompileFields();
        if (extractors == null || extractors.Count == 0) return results;

        foreach (var ext in extractors)
        {
            var value = ext.Extract(tx);
            if (value == null) continue;

            switch (ext.OutputField.ToLower())
            {
                case "value":
                    cred.Value = value;
                    cred.Type = ParseCapturedDataType(ext.DataType);
                    break;
                case "product_id":
                    cred.ProductId = value;
                    break;
                case "platform":
                    cred.Platform = value;
                    break;
                case "account_name":
                    cred.AccountName = value;
                    break;
                default:
                    cred.Metadata[ext.OutputField] = value;
                    break;
            }
        }

        if (!string.IsNullOrEmpty(cred.Value))
        {
            results.Add(new DataEvidence
            {
                RuleName = rule.Name,
                Value = cred.Value,
                Type = cred.Type,
                LocationId = $"step.{http.StepIndex}.response.body",
                StepIndex = http.StepIndex,
                RequestUrl = http.Url,
                MatchType = DataProbe.Core.MatchType.Regex,
                Confidence = 1.0f,
                Metadata = cred.Metadata,
                CapturedAt = DateTime.UtcNow
            });
        }

        return results;
    }

    /// <summary>
    /// 旧版 Process 接口 — 兼容 TlsProxy 等旧调用方。
    /// 将单个 NormalizedTransaction 包装为 Session 后执行规则扫描，
    /// 然后转换为 Credential 列表（保持 API 兼容）。
    /// </summary>
    public List<Credential> Process(NormalizedTransaction tx)
    {
        var session = new SessionSnapshot { TargetName = tx.Domain };
        var builder = new SessionBuilder(session);
        builder.AddTransaction(tx);
        var evidences = ProcessSessionAsync(session).GetAwaiter().GetResult();

        // 转换为 Credential（旧格式）
        return evidences.Select(e => new Credential
        {
            Value = e.Value,
            Type = e.Type,
            Platform = e.RuleName,
            Source = "rule_engine",
            ProductId = e.Metadata.GetValueOrDefault("product_id", ""),
            AccountName = e.Metadata.GetValueOrDefault("account_name", ""),
            IdentityToken = e.Metadata.GetValueOrDefault("identity", ""),
            Method = e.Metadata.GetValueOrDefault("method", ""),
            Metadata = new Dictionary<string, string>(e.Metadata),
            CapturedAt = e.CapturedAt
        }).ToList();
    }

    /// <summary>
    /// 加载所有 platforms/*.json 规则文件
    /// </summary>
    public void LoadRules()
    {
        try
        {
            var files = Directory.GetFiles(_rulesDir, "*.json");
            var loaded = new List<PlatformRule>();

            foreach (var file in files)
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var rule = JsonSerializer.Deserialize<PlatformRule>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (rule != null && !string.IsNullOrEmpty(rule.Name))
                    {
                        if (rule.Id == null)
                            rule.Id = Path.GetFileNameWithoutExtension(file);
                        loaded.Add(rule);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[RuleEngine] Failed to load {file}: {ex.Message}");
                }
            }

            loaded.Sort((a, b) => a.Priority.CompareTo(b.Priority));

            lock (_lock) _rules = loaded;

            Console.Error.WriteLine($"[RuleEngine] Loaded {loaded.Count} rules from {_rulesDir}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[RuleEngine] Error loading rules: {ex.Message}");
        }
    }

    /// <summary>
    /// 加载预设规则包
    /// </summary>
    public int LoadRulePack(RulePack pack)
    {
        if (pack?.Rules == null) return 0;
        int count = 0;
        foreach (var rule in pack.Rules)
        {
            if (!string.IsNullOrEmpty(rule.Name))
            {
                SaveRule(rule);
                count++;
            }
        }
        LoadRules(); // 重新加载
        return count;
    }

    /// <summary>
    /// 将 HttpTransaction 转为 NormalizedTransaction（用于旧版兼容）
    /// </summary>
    private static NormalizedTransaction ToNormalizedTransaction(HttpTransaction http)
    {
        var uri = TryParseUri(http.Url);
        return new NormalizedTransaction
        {
            Domain = uri?.Host ?? "",
            Method = http.Method,
            Path = uri?.AbsolutePath ?? "",
            QueryString = uri?.Query ?? "",
            Url = http.Url,
            StatusCode = http.StatusCode,
            RequestBody = http.RequestBody.RawText,
            ResponseBody = http.ResponseBody.RawText,
            CapturedAt = DateTime.UtcNow
        };
    }

    private static Uri? TryParseUri(string url)
    {
        try { return new Uri(url); }
        catch { return null; }
    }

    private static string ExtractDomain(string url)
    {
        try { return new Uri(url).Host; }
        catch { return ""; }
    }

    private static string ExtractPath(string url)
    {
        try { return new Uri(url).AbsolutePath; }
        catch { return ""; }
    }

    private static string Truncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text[..maxLen] + "...";
    }

    private static CapturedDataType ParseCapturedDataType(string type) => type.ToLower() switch
    {
        "url" or "payment_url" => CapturedDataType.Url,
        "params" or "payment_params" => CapturedDataType.Params,
        "token" or "access_token" => CapturedDataType.Token,
        "image" or "qr_image" => CapturedDataType.Image,
        "key" or "card_key" => CapturedDataType.Key,
        "account" => CapturedDataType.Account,
        "payment" => CapturedDataType.Payment,
        _ => CapturedDataType.RawData
    };

    public void Dispose()
    {
        _watcher?.Dispose();
    }
}
