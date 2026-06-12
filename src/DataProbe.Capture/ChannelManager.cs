using System.Reflection;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 通道管理器 — 统一管理所有 ICaptureChannel 的注册、发现、启停、健康检查。
///
/// 重构目标：
///   - 自动发现：程序集扫描所有 ICaptureChannel 实现
///   - 可插拔：运行时注册/注销通道
///   - 健康自愈：自动重启异常通道
///   - 状态可观测：提供实时通道状态快照
/// </summary>
public class ChannelManager : IDisposable
{
    private readonly Dictionary<string, ICaptureChannel> _channels = new();
    private readonly List<ICaptureChannel> _channelList = new();
    private readonly object _lock = new();
    private Timer? _healthTimer;
    private bool _disposed;

    /// <summary>已注册的通道数量</summary>
    public int ChannelCount { get { lock (_lock) return _channelList.Count; } }

    /// <summary>所有通道名称</summary>
    public string[] ChannelNames { get { lock (_lock) return _channelList.Select(c => c.Name).ToArray(); } }

    /// <summary>所有通道的状态快照</summary>
    public ChannelStatus[] AllStatus
    {
        get
        {
            lock (_lock)
            {
                return _channelList.Select(c => new ChannelStatus
                {
                    Name = c.Name,
                    Description = c.Description,
                    IsHealthy = c.IsHealthy,
                    Layer = c.Capability.Layer,
                    CanDecryptTls = c.Capability.CanDecryptTls,
                    RequiresAdmin = c.Capability.RequiresAdmin,
                    SupportedProtocols = c.Capability.SupportedProtocols,
                    ScopeDescription = c.Capability.ScopeDescription
                }).ToArray();
            }
        }
    }

    // ── 注册 API ──

    /// <summary>
    /// 手动注册一个通道
    /// </summary>
    public void Register(ICaptureChannel channel)
    {
        if (channel == null) throw new ArgumentNullException(nameof(channel));

        lock (_lock)
        {
            if (_channels.ContainsKey(channel.Name))
                throw new InvalidOperationException($"Channel '{channel.Name}' is already registered.");

            _channels[channel.Name] = channel;
            _channelList.Add(channel);
            Console.Error.WriteLine($"[ChannelManager] Registered: {channel.Name}");
        }
    }

    /// <summary>
    /// 批量注册多个通道
    /// </summary>
    public void RegisterRange(IEnumerable<ICaptureChannel> channels)
    {
        foreach (var ch in channels)
            Register(ch);
    }

    /// <summary>
    /// 注销一个通道
    /// </summary>
    public bool Unregister(string name)
    {
        lock (_lock)
        {
            if (!_channels.TryGetValue(name, out var channel))
                return false;

            try { channel.StopAsync().GetAwaiter().GetResult(); } catch { }
            _channels.Remove(name);
            _channelList.Remove(channel);
            Console.Error.WriteLine($"[ChannelManager] Unregistered: {name}");
            return true;
        }
    }

    // ── 自动发现 ──

    /// <summary>
    /// 扫描指定程序集中所有 ICaptureChannel 的非抽象实现并注册。
    /// </summary>
    /// <param name="assembly">要扫描的程序集。null = 调用方程序集</param>
    /// <returns>发现的通道数量</returns>
    public int DiscoverAndRegister(Assembly? assembly = null)
    {
        assembly ??= Assembly.GetCallingAssembly();
        var count = 0;

        var channelTypes = assembly.GetTypes()
            .Where(t => !t.IsAbstract && !t.IsInterface)
            .Where(t => typeof(ICaptureChannel).IsAssignableFrom(t))
            .Where(t => t.GetConstructors().Any(c => c.GetParameters().Length == 0)); // 仅无参构造

        foreach (var type in channelTypes)
        {
            try
            {
                if (Activator.CreateInstance(type) is ICaptureChannel channel)
                {
                    Register(channel);
                    count++;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] Auto-register failed for {type.Name}: {ex.Message}");
            }
        }

        if (count > 0)
            Console.Error.WriteLine($"[ChannelManager] Auto-discovered {count} channels from {assembly.GetName().Name}");

        return count;
    }

    // ── 获取通道 ──

    /// <summary>获取指定名称的通道</summary>
    public ICaptureChannel? Get(string name)
    {
        lock (_lock) return _channels.GetValueOrDefault(name);
    }

    /// <summary>获取指定类型的通道</summary>
    public T? Get<T>() where T : class, ICaptureChannel
    {
        lock (_lock) return _channelList.FirstOrDefault(c => c is T) as T;
    }

    /// <summary>根据能力筛选通道</summary>
    public ICaptureChannel[] SelectByCapability(Func<ChannelCapability, bool> predicate)
    {
        lock (_lock) return _channelList.Where(c => predicate(c.Capability)).ToArray();
    }

    // ── 生命周期管理 ──

    /// <summary>初始化所有已注册通道</summary>
    public async Task InitializeAllAsync()
    {
        List<ICaptureChannel> channels;
        lock (_lock) channels = new List<ICaptureChannel>(_channelList);

        foreach (var ch in channels)
        {
            try
            {
                var ok = await ch.InitializeAsync();
                Console.Error.WriteLine(ok
                    ? $"[ChannelManager] {ch.Name} initialized"
                    : $"[ChannelManager] {ch.Name} init failed");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} init error: {ex.Message}");
            }
        }
    }

    /// <summary>启动所有通道</summary>
    public async Task StartAllAsync()
    {
        List<ICaptureChannel> channels;
        lock (_lock) channels = new List<ICaptureChannel>(_channelList);

        foreach (var ch in channels)
        {
            try
            {
                await ch.StartAsync();
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} started");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} start failed: {ex.Message}");
            }
        }

        StartHealthCheck();
    }

    /// <summary>停止所有通道</summary>
    public async Task StopAllAsync()
    {
        StopHealthCheck();

        List<ICaptureChannel> channels;
        lock (_lock) channels = new List<ICaptureChannel>(_channelList);
        channels.Reverse(); // 逆序停止

        foreach (var ch in channels)
        {
            try
            {
                await ch.StopAsync();
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} stopped");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} stop error: {ex.Message}");
            }
        }
    }

    /// <summary>重启指定通道</summary>
    public async Task<bool> RestartAsync(string name)
    {
        var channel = Get(name);
        if (channel == null) return false;

        try
        {
            Console.Error.WriteLine($"[ChannelManager] Restarting {name}...");
            await channel.StopAsync();
            await channel.InitializeAsync();
            await channel.StartAsync();
            Console.Error.WriteLine($"[ChannelManager] {name} restarted");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ChannelManager] {name} restart failed: {ex.Message}");
            return false;
        }
    }

    // ── 健康检查 ──

    private int _healthCheckIntervalSec = 30;

    public void SetHealthCheckInterval(int seconds)
    {
        _healthCheckIntervalSec = Math.Max(5, seconds);
        if (_healthTimer != null)
        {
            StopHealthCheck();
            StartHealthCheck();
        }
    }

    private void StartHealthCheck()
    {
        _healthTimer?.Dispose();
        _healthTimer = new Timer(_ => HealthCheckAsync().GetAwaiter().GetResult(), null,
            TimeSpan.FromSeconds(_healthCheckIntervalSec),
            TimeSpan.FromSeconds(_healthCheckIntervalSec));
    }

    private void StopHealthCheck()
    {
        _healthTimer?.Dispose();
        _healthTimer = null;
    }

    /// <summary>健康检查 — 自动重启异常通道</summary>
    public async Task HealthCheckAsync()
    {
        List<ICaptureChannel> channels;
        lock (_lock) channels = new List<ICaptureChannel>(_channelList);

        foreach (var ch in channels)
        {
            try
            {
                if (!ch.IsHealthy)
                {
                    Console.Error.WriteLine($"[ChannelManager] {ch.Name} unhealthy, restarting...");
                    await ch.StopAsync();
                    await ch.InitializeAsync();
                    await ch.StartAsync();
                    Console.Error.WriteLine($"[ChannelManager] {ch.Name} restarted");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} health check error: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopHealthCheck();
        StopAllAsync().GetAwaiter().GetResult();
    }
}

/// <summary>
/// 通道状态快照（用于 API 输出和 Dashboard 展示）
/// </summary>
public class ChannelStatus
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool IsHealthy { get; set; }
    public CaptureLayer Layer { get; set; }
    public bool CanDecryptTls { get; set; }
    public bool RequiresAdmin { get; set; }
    public string[] SupportedProtocols { get; set; } = Array.Empty<string>();
    public string ScopeDescription { get; set; } = "";
}
