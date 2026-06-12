using System.Text.Json;
using DataProbe.Core;

namespace DataProbe.Extractor;

/// <summary>
/// 平台规则引擎 — 加载 platforms/*.json 规则文件，
/// 对 NormalizedTransaction 进行匹配 → 提取 → 输出 Credential。
///
/// 核心设计原则：
///   - 数据驱动：规则是 JSON，不是代码
///   - 零硬编码：不需要为任何平台写 C# 代码
///   - 热加载：修改 JSON 后自动生效（通过文件监视）
/// </summary>
public class RuleEngine : IDisposable
{
    private List<PlatformRule> _rules = new();
    private readonly string _rulesDir;
    private readonly FileSystemWatcher? _watcher;
    private readonly object _lock = new();

    public RuleEngine(string? rulesDir = null)
    {
        _rulesDir = rulesDir ?? Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "platforms");

        // 确保目录存在
        Directory.CreateDirectory(_rulesDir);

        // 加载规则
        LoadRules();

        // 设置文件监视（热更新）
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

        // 编译 Fields 到 Extractors（保持兼容）
        if (rule.Fields != null && rule.Fields.Count > 0)
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
    /// 处理一个标准化事务，返回匹配的凭证列表。
    /// </summary>
    public List<Credential> Process(NormalizedTransaction tx)
    {
        List<PlatformRule> rules;
        lock (_lock) rules = _rules;

        var results = new List<Credential>();

        foreach (var rule in rules)
        {
            if (!rule.Enabled) continue;

            // 1. 匹配：所有 matcher 都满足才算匹配
            var matched = rule.Matchers.Count == 0 ||
                          rule.Matchers.All(m => m.IsMatch(tx));

            if (!matched) continue;

            // 2. 确定使用的提取器（优先用编译后的 Fields）
            var extractors = rule.Extractors;
            if ((extractors == null || extractors.Count == 0) && rule.Fields?.Count > 0)
            {
                extractors = rule.CompileFields();
            }
            if (extractors == null || extractors.Count == 0) continue;

            // 3. 提取
            var cred = new Credential
            {
                Type = CapturedDataType.Url,
                Platform = rule.Name,
                Source = "oracle",
                Metadata = new Dictionary<string, string>
                {
                    ["rule_name"] = rule.Name,
                    ["domain"] = tx.Domain,
                    ["path"] = tx.Path,
                }
            };

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
                    case "openid":
                        cred.OpenId = value;
                        break;
                    case "pay_method":
                        cred.PayMethod = value;
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

            // 只有提取到 value 才算有效凭证
            if (!string.IsNullOrEmpty(cred.Value))
            {
                results.Add(cred);
            }

            // 优先级规则：只取第一个匹配的（优先级最高的）
            break;
        }

        return results;
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
                        // 设置 Id 为文件名（不含扩展名）
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

            // 按优先级排序
            loaded.Sort((a, b) => a.Priority.CompareTo(b.Priority));

            lock (_lock) _rules = loaded;

            Console.Error.WriteLine($"[RuleEngine] Loaded {loaded.Count} platform rules from {_rulesDir}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[RuleEngine] Error loading rules: {ex.Message}");
        }
    }

    private static CapturedDataType ParseCapturedDataType(string type) => type.ToLower() switch
    {
        "url" or "payment_url" => CapturedDataType.Url,
        "params" or "payment_params" => CapturedDataType.Params,
        "token" or "access_token" => CapturedDataType.Token,
        "image" or "qr_image" => CapturedDataType.Image,
        "key" or "card_key" => CapturedDataType.Key,
        _ => CapturedDataType.RawData
    };

    public void Dispose()
    {
        _watcher?.Dispose();
    }
}
