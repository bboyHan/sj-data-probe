namespace DataProbe.Core;

/// <summary>
/// 目标情报报告 — 阶段 I（目标洞察）的输出。
/// 包含目标的网络信息、防护评估、逆向分析结果。
/// </summary>
public class TargetProfile
{
    /// <summary>目标标识（域名 / 包名 / 文件 hash）</summary>
    public string TargetId { get; set; } = "";

    /// <summary>目标类型</summary>
    public TargetType Type { get; set; } = TargetType.Website;

    /// <summary>人类可读名称</summary>
    public string DisplayName { get; set; } = "";

    /// <summary>综合防护评级</summary>
    public ProtectionLevel ProtectionRating { get; set; } = ProtectionLevel.Unknown;

    // ── 防护详情 ──

    /// <summary>是否有证书锁定</summary>
    public bool HasCertPinning { get; set; }

    /// <summary>证书锁定实现库</summary>
    public string? PinningLibrary { get; set; }  // okhttp / trustmanager / nsurlsession / custom

    /// <summary>是否有反模拟器检测</summary>
    public bool HasAntiEmulator { get; set; }

    /// <summary>反模拟器检测方法（逗号分隔）</summary>
    public string? AntiEmulatorMethods { get; set; }

    /// <summary>是否有反作弊</summary>
    public bool HasAntiCheat { get; set; }

    /// <summary>反作弊类型</summary>
    public string? AntiCheatType { get; set; }  // ace / tensafe / eac / battleye / none

    /// <summary>是否有自定义应用层加密</summary>
    public bool HasCustomEncryption { get; set; }

    /// <summary>是否有验证码</summary>
    public bool HasCaptcha { get; set; }

    /// <summary>验证码类型</summary>
    public string? CaptchaType { get; set; }  // geetest / recaptcha / hcaptcha / custom

    // ── 网络信息 ──

    /// <summary>解析到的 IP 地址</summary>
    public string[] IPAddresses { get; set; } = Array.Empty<string>();

    /// <summary>发现的子域名</summary>
    public string[] Subdomains { get; set; } = Array.Empty<string>();

    /// <summary>CDN 提供商</summary>
    public string? CDNProvider { get; set; }

    /// <summary>TLS 版本</summary>
    public string? TLSVersion { get; set; }

    // ── 应用信息 ──

    /// <summary>从逆向分析提取的 API 端点</summary>
    public string[] APIEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>注册的 URL Scheme</summary>
    public string[] URLSchemes { get; set; } = Array.Empty<string>();

    /// <summary>硬编码的 Token 或密钥</summary>
    public string[] HardcodedTokens { get; set; } = Array.Empty<string>();

    /// <summary>检测到的第三方 SDK</summary>
    public string[] DetectedSDKs { get; set; } = Array.Empty<string>();

    // ── 建议 ──

    /// <summary>推荐的通道名称</summary>
    public string? RecommendedChannel { get; set; }

    /// <summary>推荐的绕过方案</summary>
    public string[] BypassSuggestions { get; set; } = Array.Empty<string>();

    /// <summary>预期可提取率 (0-100)</summary>
    public int ExpectedCoverage { get; set; } = 100;

    /// <summary>生成人类可读的防护摘要</summary>
    public string GetProtectionSummary()
    {
        var parts = new List<string>();
        if (HasCertPinning) parts.Add("证书锁定");
        if (HasAntiEmulator) parts.Add("反模拟器");
        if (HasAntiCheat) parts.Add($"反作弊({AntiCheatType})");
        if (HasCustomEncryption) parts.Add("自定义加密");
        if (HasCaptcha) parts.Add($"验证码({CaptchaType})");
        return parts.Count > 0 ? string.Join(" + ", parts) : "无已知防护";
    }
}

/// <summary>
/// 目标类型
/// </summary>
public enum TargetType
{
    Website,        // 浏览器访问的网站
    MobileApp,      // 移动端原生 App
    PcGame,         // PC 端游
    MiniProgram,    // 微信/抖音小程序
    WebApi,         // 纯 API 接口
    Other
}

/// <summary>
/// 执行计划 — 阶段 II（突破策略）的输出。
/// 指定使用哪些通道、解密方案、仿真配置。
/// </summary>
public class ExecutionPlan
{
    /// <summary>人类可读的方案描述</summary>
    public string Summary { get; set; } = "";

    /// <summary>选定的通道名称列表</summary>
    public string[] ChannelNames { get; set; } = Array.Empty<string>();

    /// <summary>选定的解密方案列表</summary>
    public DecryptionMethod[] DecryptionMethods { get; set; } = Array.Empty<DecryptionMethod>();

    /// <summary>TLS 指纹配置</summary>
    public FingerprintConfig? TlsFingerprint { get; set; }

    /// <summary>设备指纹配置</summary>
    public DeviceProfile? DeviceFingerprint { get; set; }

    /// <summary>行为仿真配置</summary>
    public BehaviorConfig? BehaviorProfile { get; set; }

    /// <summary>验证码策略</summary>
    public CaptchaStrategyType CaptchaStrategy { get; set; } = CaptchaStrategyType.None;

    /// <summary>是否启用 SSLKEYLOGFILE（浏览器/CEF 目标）</summary>
    public bool UseSslKeyLog { get; set; }

    /// <summary>预期可提取率 (0-100)</summary>
    public int ExpectedCoverage { get; set; }

    /// <summary>已知限制</summary>
    public string[] Limitations { get; set; } = Array.Empty<string>();
}

/// <summary>
/// TLS 指纹配置
/// </summary>
public class FingerprintConfig
{
    /// <summary>要模拟的客户端类型</summary>
    public string Profile { get; set; } = "chrome_122";  // chrome_122 / firefox_123 / safari_17 / okhttp_4 / unity

    /// <summary>自定义密码套件（覆盖模板）</summary>
    public string? CustomCiphers { get; set; }

    /// <summary>自定义扩展列表</summary>
    public string? CustomExtensions { get; set; }
}

/// <summary>
/// 设备指纹
/// </summary>
public class DeviceProfile
{
    public string ModelId { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Brand { get; set; } = "";
    public string OS { get; set; } = "";
    public string Release { get; set; } = "";
    public string Resolution { get; set; } = "";
    public int DensityDpi { get; set; }
    public int Ttl { get; set; } = 64;
    public string CpuArch { get; set; } = "arm64-v8a";
    public string[] Sensors { get; set; } = Array.Empty<string>();

    public DeviceProfile Clone() => new()
    {
        ModelId = ModelId, Manufacturer = Manufacturer, Brand = Brand,
        OS = OS, Release = Release, Resolution = Resolution,
        DensityDpi = DensityDpi, Ttl = Ttl, CpuArch = CpuArch,
        Sensors = (string[])Sensors.Clone()
    };
}

/// <summary>
/// 行为仿真配置
/// </summary>
public class BehaviorConfig
{
    /// <summary>操作速度模式: normal / fast</summary>
    public string SpeedMode { get; set; } = "normal";

    /// <summary>是否模拟鼠标轨迹</summary>
    public bool SimulateMouseTrails { get; set; } = true;

    /// <summary>是否生成背景噪音流量</summary>
    public bool GenerateBackgroundNoise { get; set; }
}

/// <summary>
/// 解密方案
/// </summary>
public enum DecryptionMethod
{
    CaMitm,             // CA 证书 MITM
    SslKeyLogFile,      // SSLKEYLOGFILE 注入
    ProcessSslHook,     // 进程内 SSL Hook
    DotNetProfiler,     // .NET Profiler
    JavaAgent,          // Java Agent
    FridaHook,          // Frida 移动端 Hook
    MemoryScan          // 内存扫描 Master Key
}

/// <summary>
/// 通道捕获层级
/// </summary>
public enum CaptureLayer
{
    L2,     // 数据链路层（ARP）
    L3,     // 网络层（TUN）
    L4,     // 传输层（WinDivert）
    L7,     // 应用层（系统代理）
    Process // 进程内
}

/// <summary>
/// 验证码策略
/// </summary>
public enum CaptchaStrategyType
{
    None,       // 无需处理
    AutoOcr,    // 自动 OCR
    AiSolve,    // AI 求解（滑块/图像识别）
    ThirdParty, // 第三方服务（2Captcha）
    Manual,     // 人工介入
    Bypass      // 跳过/规避
}
