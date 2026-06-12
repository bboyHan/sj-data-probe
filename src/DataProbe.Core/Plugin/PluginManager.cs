using System.Reflection;
using System.Text.Json;

namespace DataProbe.Core.Plugin;

/// <summary>
/// 插件管理器 — 全产品的统一扩展加载入口。
///
/// 设计原则：DataProbe 的所有扩展点都通过 plugins/ 目录加载。
///   一个 .dll = 一个独立功能模块，负责一个具体目标的攻克。
///   一个 .json = 一个规则包/指纹模板/设备配置。
///
/// 支持发现的接口（不只是 IDataProbePlugin 子接口）：
///   - ICaptureChannel    → 自定义采集通道
///   - IProtocolParser    → 自定义协议解析器
///   - IReScannerPlugin   → 逆向扫描器
///   - IDecryptionPlugin  → 应用层解密器
///   - IExtractorPlugin   → 高级提取器
///   - IProtocolPlugin    → 二进制协议解析器
///   - 所有 IDataProbePlugin 子接口
///
/// 支持发现的 JSON 文件：
///   - rules/*.json            → 提取规则
///   - fingerprints/*.json     → TLS JA3 指纹模板
///   - devices/*.json          → 设备指纹配置
///
/// 发现方式：
///   - .dll → Assembly.LoadFrom → 反射扫描所有已知接口
///   - .json → 按目录规则解析
///
/// 目录结构：
///   plugins/
///   ├── channels/            ← ICaptureChannel (.dll)
///   ├── parsers/             ← IProtocolParser (.dll)
///   ├── scanners/            ← IReScannerPlugin (.dll)
///   ├── decryption/          ← IDecryptionPlugin (.dll)
///   ├── extractors/          ← IExtractorPlugin (.dll)
///   ├── challenges/          ← 验证码处理器 (.dll)
///   ├── rules/               ← 提取规则包 (.json)
///   ├── fingerprints/        ← TLS 指纹模板 (.json)
///   └── devices/             ← 设备指纹配置 (.json)
/// </summary>
public class PluginManager : IDisposable
{
    private readonly string _pluginsDir;
    private readonly Dictionary<string, object> _extensions = new();
    private FileSystemWatcher? _watcher;
    private readonly object _lock = new();
    private bool _disposed;

    // ── 注册回调 ──
    // 宿主应用（Program.cs）通过这些回调接收新发现的扩展

    /// <summary>通道发现回调：Action(channelName, ICaptureChannel)</summary>
    public event Action<string, ICaptureChannel>? OnChannelDiscovered;

    /// <summary>协议解析器发现回调</summary>
    public event Action<string, IProtocolParser>? OnParserDiscovered;

    /// <summary>规则包发现回调</summary>
    public event Action<string, PlatformRule>? OnRuleDiscovered;

    /// <summary>TLS 指纹发现回调</summary>
    public event Action<string, string>? OnFingerprintDiscovered;

    /// <summary>通用插件发现回调（IDataProbePlugin 子接口）</summary>
    public event Action<string, IDataProbePlugin>? OnPluginDiscovered;

    /// <summary>已发现的扩展数量</summary>
    public int Count { get { lock (_lock) return _extensions.Count; } }

    public PluginManager(string? pluginsDir = null)
    {
        _pluginsDir = pluginsDir ?? Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "plugins");

        Directory.CreateDirectory(_pluginsDir);

        // 创建子目录
        foreach (var sub in new[] { "channels", "parsers", "scanners", "decryption",
                                     "extractors", "challenges", "rules",
                                     "fingerprints", "devices" })
            Directory.CreateDirectory(Path.Combine(_pluginsDir, sub));

        // 文件监视（热更新）
        try
        {
            _watcher = new FileSystemWatcher(_pluginsDir, "*.*")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.FileName,
                IncludeSubdirectories = true
            };
            _watcher.Created += (_, e) => ScheduleReload(e.FullPath);
            _watcher.Changed += (_, e) => ScheduleReload(e.FullPath);
            _watcher.EnableRaisingEvents = true;
        }
        catch { }
    }

    /// <summary>增量加载（文件变更时调用）</summary>
    private void ScheduleReload(string path)
    {
        Task.Run(async () =>
        {
            await Task.Delay(500); // 等文件写入完成
            try { await LoadAllAsync(); }
            catch { }
        });
    }

    /// <summary>
    /// 全量加载 — 扫描 plugins/ 下所有扩展
    /// </summary>
    public async Task<int> LoadAllAsync(CancellationToken ct = default)
    {
        int count = 0;

        // 1) 加载所有 .dll 文件
        var dllFiles = Directory.GetFiles(_pluginsDir, "*.dll", SearchOption.AllDirectories);
        foreach (var dll in dllFiles)
        {
            try { if (await LoadAssemblyAsync(dll, ct)) count++; }
            catch (Exception ex) { Console.Error.WriteLine($"[Plugin] DLL load failed: {dll} — {ex.Message}"); }
        }

        // 2) 加载所有 .json 规则包
        var ruleFiles = Directory.GetFiles(Path.Combine(_pluginsDir, "rules"), "*.json");
        foreach (var file in ruleFiles)
        {
            try { if (LoadRulePack(file)) count++; }
            catch (Exception ex) { Console.Error.WriteLine($"[Plugin] Rule load failed: {file} — {ex.Message}"); }
        }

        // 3) 加载所有 .json 指纹模板
        var fpFiles = Directory.GetFiles(Path.Combine(_pluginsDir, "fingerprints"), "*.json");
        foreach (var file in fpFiles)
        {
            try { if (LoadFingerprint(file)) count++; }
            catch (Exception ex) { Console.Error.WriteLine($"[Plugin] Fingerprint load failed: {file} — {ex.Message}"); }
        }

        Console.Error.WriteLine($"[PluginManager] Loaded {count} extensions from {_pluginsDir}");
        return count;
    }

    /// <summary>
    /// 加载一个 .dll，发现其中的所有扩展接口实现
    /// </summary>
    private async Task<bool> LoadAssemblyAsync(string dllPath, CancellationToken ct)
    {
        if (!File.Exists(dllPath)) return false;

        var assembly = Assembly.LoadFrom(dllPath);
        var types = assembly.GetTypes()
            .Where(t => !t.IsAbstract && !t.IsInterface)
            .ToArray();

        int found = 0;

        foreach (var type in types)
        {
            // 1) ICaptureChannel
            if (typeof(ICaptureChannel).IsAssignableFrom(type))
            {
                if (Activator.CreateInstance(type) is ICaptureChannel ch)
                {
                    lock (_lock) _extensions[$"channel:{ch.Name}"] = ch;
                    OnChannelDiscovered?.Invoke(ch.Name, ch);
                    found++;
                }
            }

            // 2) IProtocolParser
            if (typeof(IProtocolParser).IsAssignableFrom(type))
            {
                if (Activator.CreateInstance(type) is IProtocolParser parser)
                {
                    lock (_lock) _extensions[$"parser:{parser.ProtocolName}"] = parser;
                    OnParserDiscovered?.Invoke(parser.ProtocolName, parser);
                    found++;
                }
            }

            // 3) IDataProbePlugin 及其子接口
            if (typeof(IDataProbePlugin).IsAssignableFrom(type))
            {
                if (Activator.CreateInstance(type) is IDataProbePlugin plugin)
                {
                    await plugin.InitializeAsync(ct);
                    lock (_lock) _extensions[$"plugin:{plugin.Id}"] = plugin;
                    OnPluginDiscovered?.Invoke(plugin.Id, plugin);
                    found++;
                    Console.Error.WriteLine($"[Plugin] Loaded plugin: {plugin.Id} v{plugin.Version} ({plugin.Name})");
                }
            }
        }

        return found > 0;
    }

    /// <summary>加载一个规则包 JSON</summary>
    private bool LoadRulePack(string jsonPath)
    {
        var json = File.ReadAllText(jsonPath);
        var rulePack = JsonSerializer.Deserialize<RulePack>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
        if (rulePack?.Rules == null || rulePack.Rules.Count == 0) return false;

        foreach (var rule in rulePack.Rules)
        {
            if (string.IsNullOrEmpty(rule.Name)) continue;
            OnRuleDiscovered?.Invoke(rule.Name, rule);
        }

        Console.Error.WriteLine($"[Plugin] Loaded rule pack: {rulePack.Name} ({rulePack.Rules.Count} rules)");
        return true;
    }

    /// <summary>加载一个 TLS 指纹模板 JSON</summary>
    private bool LoadFingerprint(string jsonPath)
    {
        var json = File.ReadAllText(jsonPath);
        var name = Path.GetFileNameWithoutExtension(jsonPath);

        lock (_lock) _extensions[$"fingerprint:{name}"] = json;
        OnFingerprintDiscovered?.Invoke(name, json);

        Console.Error.WriteLine($"[Plugin] Loaded fingerprint: {name}");
        return true;
    }

    // ── 查询 API ──

    /// <summary>获取所有指定类型的扩展</summary>
    public T[] GetExtensions<T>()
    {
        lock (_lock) return _extensions.Values.OfType<T>().ToArray();
    }

    /// <summary>获取能处理特定目标的插件</summary>
    public IDataProbePlugin[] GetPluginsForTarget(string targetId)
    {
        lock (_lock)
        {
            return _extensions.Values
                .OfType<IDataProbePlugin>()
                .Where(p => p.SupportedTargets.Length == 0 ||
                            p.SupportedTargets.Any(t =>
                                t == targetId ||
                                (t.StartsWith("*.") && targetId.EndsWith(t[1..]))))
                .ToArray();
        }
    }

    /// <summary>按类型获取插件</summary>
    public T[] GetPlugins<T>() where T : class, IDataProbePlugin
    {
        lock (_lock) return _extensions.Values.OfType<T>().ToArray();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher?.Dispose();
        lock (_lock) _extensions.Clear();
    }
}
