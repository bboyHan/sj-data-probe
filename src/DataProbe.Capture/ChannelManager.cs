using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 通道管理器 — 统一管理所有 ICaptureChannel 的注册、启停、健康检查。
///
/// 职责：
///   - Register：注册通道
///   - StartAllAsync / StopAllAsync：统一启停
///   - HealthCheckAsync：定时健康检查，自动恢复异常通道
///   - SelectChannels：根据 Target 需求匹配最优通道
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

    /// <summary>
    /// 注册一个通道
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
    /// 获取指定名称的通道
    /// </summary>
    public ICaptureChannel? Get(string name)
    {
        lock (_lock) return _channels.GetValueOrDefault(name);
    }

    /// <summary>
    /// 初始化所有已注册通道
    /// </summary>
    public async Task InitializeAllAsync()
    {
        List<ICaptureChannel> channels;
        lock (_lock) channels = new List<ICaptureChannel>(_channelList);

        foreach (var ch in channels)
        {
            try
            {
                var ok = await ch.InitializeAsync();
                if (ok)
                    Console.Error.WriteLine($"[ChannelManager] {ch.Name} initialized");
                else
                    Console.Error.WriteLine($"[ChannelManager] {ch.Name} init failed (will skip on start)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ChannelManager] {ch.Name} init error: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// 启动所有通道
    /// </summary>
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

        // 启动健康检查定时器（每 30 秒）
        _healthTimer?.Dispose();
        _healthTimer = new Timer(_ => HealthCheckAsync().GetAwaiter().GetResult(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// 停止所有通道
    /// </summary>
    public async Task StopAllAsync()
    {
        _healthTimer?.Dispose();
        _healthTimer = null;

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

    /// <summary>
    /// 健康检查 — 自动重启异常通道
    /// </summary>
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
        _healthTimer?.Dispose();
        StopAllAsync().GetAwaiter().GetResult();
    }
}
