using System.Text.Json;

namespace DataProbe.Core;

/// <summary>
/// 规则包导入器 — 规则市场的核心引擎。
///
/// 支持:
///   - 从 JSON 文件/字符串导入规则包
///   - 导出规则包为分享格式
///   - 验证规则包兼容性
///   - 规则包去重/版本管理
/// </summary>
public class RulePackImporter
{
    private readonly string _rulesDir;

    public RulePackImporter(string? rulesDir = null)
    {
        _rulesDir = rulesDir ?? Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "platforms");
    }

    /// <summary>从 JSON 字符串导入规则包</summary>
    public RulePackImportResult ImportFromJson(string json)
    {
        try
        {
            var pack = JsonSerializer.Deserialize<RulePack>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (pack == null)
                return new RulePackImportResult { Success = false, Error = "Invalid rule pack format" };

            return ImportPack(pack);
        }
        catch (Exception ex)
        {
            return new RulePackImportResult { Success = false, Error = ex.Message };
        }
    }

    /// <summary>导入规则包对象</summary>
    public RulePackImportResult ImportPack(RulePack pack)
    {
        var result = new RulePackImportResult
        {
            Success = true,
            PackName = pack.Name,
            PackVersion = pack.Version
        };

        if (pack.Rules == null || pack.Rules.Count == 0)
        {
            result.Success = false;
            result.Error = "Rule pack contains no rules";
            return result;
        }

        // 验证每条规则
        foreach (var rule in pack.Rules)
        {
            if (string.IsNullOrEmpty(rule.Name))
            {
                result.Skipped++;
                continue;
            }

            // 检查是否已存在同名规则
            var existingPath = Path.Combine(_rulesDir, $"{rule.Name}.json");
            if (File.Exists(existingPath))
            {
                // 同名规则存在 → 跳过（除非 force 覆盖）
                if (!result.ForceOverwrite)
                {
                    result.Skipped++;
                    continue;
                }
            }

            // 写入规则文件
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                };
                var ruleJson = JsonSerializer.Serialize(rule, options);
                File.WriteAllText(existingPath, ruleJson);
                result.Imported++;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Failed to save rule '{rule.Name}': {ex.Message}");
            }
        }

        return result;
    }

    /// <summary>导出规则包为分享格式</summary>
    public string ExportToJson(string[] ruleNames)
    {
        var pack = new RulePack
        {
            Name = "exported_pack",
            Description = "Exported from DataProbe",
            Version = "1.0",
            TargetTypes = Array.Empty<string>(),
            Rules = new List<PlatformRule>()
        };

        foreach (var name in ruleNames)
        {
            var path = Path.Combine(_rulesDir, $"{name}.json");
            if (File.Exists(path))
            {
                try
                {
                    var json = File.ReadAllText(path);
                    var rule = JsonSerializer.Deserialize<PlatformRule>(json,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (rule != null) pack.Rules.Add(rule);
                }
                catch { }
            }
        }

        return JsonSerializer.Serialize(pack, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>扫描已安装的所有规则包</summary>
    public List<RulePackInfo> ScanInstalledPacks()
    {
        if (!Directory.Exists(_rulesDir))
            return new List<RulePackInfo>();

        var packs = new List<RulePackInfo>();
        var groupedRules = new Dictionary<string, List<(PlatformRule Rule, string FilePath)>>();

        foreach (var file in Directory.GetFiles(_rulesDir, "*.json"))
        {
            try
            {
                var json = File.ReadAllText(file);
                var rule = JsonSerializer.Deserialize<PlatformRule>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (rule == null || string.IsNullOrEmpty(rule.Name)) continue;

                // 按文件名（不含扩展名）分组 — 同文件 = 同包
                var packKey = Path.GetFileNameWithoutExtension(file);
                if (!groupedRules.ContainsKey(packKey))
                    groupedRules[packKey] = new List<(PlatformRule, string)>();
                groupedRules[packKey].Add((rule, file));
            }
            catch { }
        }

        foreach (var (key, rules) in groupedRules)
        {
            packs.Add(new RulePackInfo
            {
                Name = key,
                RuleCount = rules.Count,
                FilePath = rules.First().FilePath,
                LastModified = File.GetLastWriteTime(rules.First().FilePath),
                IsSingleRule = rules.Count == 1,
                Targets = rules.SelectMany(r => r.Rule.Matchers
                    .Where(m => m.Field == "domain")
                    .Select(m => m.Value)).Distinct().ToArray()
            });
        }

        return packs;
    }
}

public class RulePackImportResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? PackName { get; set; }
    public string? PackVersion { get; set; }
    public int Imported { get; set; }
    public int Skipped { get; set; }
    public bool ForceOverwrite { get; set; }
    public List<string> Errors { get; set; } = new();
}

public class RulePackInfo
{
    public string Name { get; set; } = "";
    public int RuleCount { get; set; }
    public string FilePath { get; set; } = "";
    public DateTime LastModified { get; set; }
    public bool IsSingleRule { get; set; }
    public string[] Targets { get; set; } = Array.Empty<string>();
}
