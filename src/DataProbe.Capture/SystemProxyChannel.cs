using System.Runtime.InteropServices;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 系统代理通道 — 自动配置 Windows 系统代理指向本地的 TlsProxy。
/// 不需要管理员权限，覆盖所有走系统代理的应用（浏览器、.NET 应用等）。
///
/// 原理：
///   通过 WinINet API 设置系统代理 → 应用流量走代理 → TlsProxy 接收并 MITM
///   停止时自动恢复原始代理设置。
///
/// 适用场景：浏览器、Electron 应用、.NET 应用、所有读系统代理的应用。
/// 不适用的场景：不读系统代理的原生应用、游戏、自定义网络库。
/// </summary>
public class SystemProxyChannel : ICaptureChannel
{
    private string? _originalProxyServer;
    private bool _originalProxyEnable;
    private bool _isInitialized;
    private bool _isRunning;

    public string Name => "SystemProxy";
    public string Description => "系统代理 — 自动配置浏览器流量指向 TLS 代理";

    public ChannelCapability Capability => new()
    {
        Layer = CaptureLayer.L7,
        RequiresAdmin = false,
        RequiresCertInstall = true,
        CanIntercept = true,
        CanDecryptTls = true,
        CanModify = false,
        CanInject = false,
        SupportedProtocols = new[] { "HTTP", "HTTPS" },
        SupportedPlatforms = new[] { "windows" },
        TargetScenarios = new[] { "browser", "electron", "dotnet" },
        AntiCheatConflicts = Array.Empty<string>(),
        Limitations = new[]
        {
            "仅覆盖读取系统代理设置的应用",
            "原生 App、游戏、自定义网络库不经过系统代理",
            "需要安装 CA 证书以解密 HTTPS"
        },
        ScopeDescription = "系统代理（WinINET）— 浏览器及 .NET 应用流量"
    };

    public bool IsHealthy => _isRunning;

    public event Action<RawPacket>? OnPacket;

    /// <summary>TlsProxy 的监听地址</summary>
    public string ProxyAddress { get; set; } = "127.0.0.1";

    /// <summary>TlsProxy 的监听端口</summary>
    public int ProxyPort { get; set; } = 18802;

    public Task<bool> InitializeAsync()
    {
        _isInitialized = true;
        Console.Error.WriteLine("[SystemProxyChannel] Ready");
        return Task.FromResult(true);
    }

    public Task StartAsync()
    {
        if (_isRunning) return Task.CompletedTask;

        try
        {
            // 1. 保存当前代理设置
            SaveCurrentProxy();

            // 2. 设置系统代理指向 TlsProxy
            SetSystemProxy($"{ProxyAddress}:{ProxyPort}");

            _isRunning = true;
            Console.Error.WriteLine($"[SystemProxyChannel] System proxy set to {ProxyAddress}:{ProxyPort}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[SystemProxyChannel] Failed to set proxy: {ex.Message}");
        }

        // 系统代理通道不产生 RawPacket，数据由 TlsProxy 捕获
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        if (!_isRunning) return Task.CompletedTask;

        try
        {
            RestoreProxy();
            _isRunning = false;
            Console.Error.WriteLine("[SystemProxyChannel] System proxy restored");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[SystemProxyChannel] Failed to restore proxy: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    // ── WinINet P/Invoke ──

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool InternetSetOption(nint hInternet, int dwOption, nint lpBuffer, int dwBufferLength);

    private const int INTERNET_OPTION_REFRESH = 37;
    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;

    // ── 注册表代理管理 ──

    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// <summary>保存当前代理设置</summary>
    private void SaveCurrentProxy()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
            if (key != null)
            {
                var enable = key.GetValue("ProxyEnable");
                _originalProxyEnable = enable != null && (int)enable == 1;
                _originalProxyServer = key.GetValue("ProxyServer") as string ?? "";
            }
        }
        catch
        {
            _originalProxyEnable = false;
            _originalProxyServer = null;
        }
    }

    /// <summary>设置系统代理</summary>
    private void SetSystemProxy(string proxyAddress)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
        if (key == null)
            throw new InvalidOperationException("Cannot open Internet Settings registry key");

        key.SetValue("ProxyEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
        key.SetValue("ProxyServer", proxyAddress, Microsoft.Win32.RegistryValueKind.String);

        // 通知 WinINet 设置已变更
        InternetSetOption(nint.Zero, INTERNET_OPTION_SETTINGS_CHANGED, nint.Zero, 0);
        InternetSetOption(nint.Zero, INTERNET_OPTION_REFRESH, nint.Zero, 0);
    }

    /// <summary>恢复原始代理设置</summary>
    private void RestoreProxy()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
        if (key == null) return;

        if (_originalProxyEnable)
        {
            key.SetValue("ProxyEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
            if (!string.IsNullOrEmpty(_originalProxyServer))
                key.SetValue("ProxyServer", _originalProxyServer, Microsoft.Win32.RegistryValueKind.String);
        }
        else
        {
            key.SetValue("ProxyEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
        }

        InternetSetOption(nint.Zero, INTERNET_OPTION_SETTINGS_CHANGED, nint.Zero, 0);
        InternetSetOption(nint.Zero, INTERNET_OPTION_REFRESH, nint.Zero, 0);
    }

    public void Dispose()
    {
        if (_isRunning)
            StopAsync().GetAwaiter().GetResult();
    }
}
