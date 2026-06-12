using System.Reflection;

namespace DataProbe.Core.Plugin;

/// <summary>
/// 插件管理器 — 从 plugins/ 目录自动发现、加载、管理所有插件。
///
/// 插件 = 一个 .dll 文件，放在 plugins/ 或其子目录下。
/// 插件项目引用 DataProbe.Core，实现 IDataProbePlugin 的子接口。
///
/// 目录结构:
///   plugins/
///   ├── scanners/              ← 逆向扫描器插件
///   │   ├── ShopAppScanner.dll   ← 某电商 App 的专项扫描
///   │   └── WeChatMiniProgram.dll
///   ├── decryption/            ← 应用层解密器插件
///   │   ├── ShopAppCrypto.dll
///   │   └── DouyinDecrypt.dll
///   ├── extractors/            ← 高级提取器插件
///   └── challenges/            ← 验证码处理器
///
/// 热加载：文件变更自动重新加载（通过 FileSystemWatcher）
/// </summary>
public class PluginManager : IDisposable
{
    private readonly string _pluginsDir;
    private readonly Dictionary<string, IDataProbePlugin> _plugins = new();
    private FileSystemWatcher? _watcher;
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>已加载的插件数量</summary>
    public int Count { get { lock (_lock) return _plugins.Count; } }

    /// <summary>所有已加载的插件</summary>
    public IDataProbePlugin[] AllPlugins
    {
        get { lock (_lock) return _plugins.Values.ToArray(); }
    }

    public PluginManager(string? pluginsDir = null)
    {
        _pluginsDir = pluginsDir ?? Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "plugins");

        Directory.CreateDirectory(_pluginsDir);

        // 文件监视（热更新）
        try
        {
            _watcher = new FileSystemWatcher(_pluginsDir, "*.dll")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.FileName,
                IncludeSubdirectories = true
            };
            _watcher.Created += (_, _) => { Task.Run(async () => await LoadAllPluginsAsync()); };
            _watcher.Changed += (_, _) => { Task.Run(async () => await LoadAllPluginsAsync()); };
            _watcher.EnableRaisingEvents = true;
        }
        catch { }
    }

    /// <summary>
    /// 扫描 plugins/ 目录，加载所有插件
    /// </summary>
    public async Task<int> LoadAllPluginsAsync(CancellationToken ct = default)
    {
        var count = 0;
        var dllFiles = Directory.GetFiles(_pluginsDir, "*.dll", SearchOption.AllDirectories);

        foreach (var dllPath in dllFiles)
        {
            try
            {
                var loaded = await LoadPluginAsync(dllPath, ct);
                if (loaded) count++;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PluginManager] Failed to load {dllPath}: {ex.Message}");
            }
        }

        Console.Error.WriteLine($"[PluginManager] Loaded {count} plugins from {_pluginsDir}");
        return count;
    }

    /// <summary>加载单个插件文件</summary>
    public async Task<bool> LoadPluginAsync(string dllPath, CancellationToken ct = default)
    {
        if (!File.Exists(dllPath)) return false;

        try
        {
            var assembly = Assembly.LoadFrom(dllPath);
            var pluginTypes = assembly.GetTypes()
                .Where(t => !t.IsAbstract && !t.IsInterface)
                .Where(t => typeof(IDataProbePlugin).IsAssignableFrom(t))
                .ToArray();

            foreach (var type in pluginTypes)
            {
                if (Activator.CreateInstance(type) is not IDataProbePlugin plugin) continue;

                // 初始化
                await plugin.InitializeAsync(ct);

                lock (_lock)
                {
                    _plugins[$"{plugin.Id}@{plugin.Version}"] = plugin;
                }

                Console.Error.WriteLine($"[PluginManager] Loaded plugin: {plugin.Id} v{plugin.Version} ({plugin.Name})");
            }

            return pluginTypes.Length > 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[PluginManager] Error loading {dllPath}: {ex.Message}");
            return false;
        }
    }

    // ── 按类型查询插件 ──

    /// <summary>获取所有指定类型的插件</summary>
    public T[] GetPlugins<T>() where T : class, IDataProbePlugin
    {
        lock (_lock) return _plugins.Values.OfType<T>().ToArray();
    }

    /// <summary>获取能处理特定目标的插件</summary>
    public IDataProbePlugin[] GetPluginsForTarget(string targetId)
    {
        lock (_lock)
        {
            return _plugins.Values
                .Where(p => p.SupportedTargets.Length == 0 ||
                            p.SupportedTargets.Any(t =>
                                t == targetId ||
                                (t.StartsWith("*.") && targetId.EndsWith(t[1..]))))
                .ToArray();
        }
    }

    // ── 逆向扫描器快捷查询 ──

    /// <summary>获取能分析指定文件类型的扫描器</summary>
    public IReScannerPlugin[] GetScannersFor(string fileType, byte[] fileData)
    {
        return GetPlugins<IReScannerPlugin>()
            .Where(s => s.CanAnalyze(fileType, fileData))
            .ToArray();
    }

    /// <summary>获取能解密指定事务的解密器</summary>
    public IDecryptionPlugin[] GetDecryptorsFor(NormalizedTransaction tx)
    {
        return GetPlugins<IDecryptionPlugin>()
            .Where(d => d.CanDecrypt(tx))
            .ToArray();
    }

    /// <summary>获取能提取指定事务的提取器</summary>
    public IExtractorPlugin[] GetExtractorsFor(NormalizedTransaction tx)
    {
        return GetPlugins<IExtractorPlugin>()
            .Where(e => e.CanExtract(tx))
            .ToArray();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher?.Dispose();
        lock (_lock) _plugins.Clear();
    }
}
