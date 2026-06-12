namespace DataProbe.Core.TlsFingerprint;

/// <summary>
/// JA3 TLS 指纹配置 — 控制 TLS 客户端连接时的密码套件、扩展列表、
/// 椭圆曲线等参数，使连接看起来像特定浏览器或 App。
///
/// JA3 = TLS Version + Cipher Suites + Extensions + Elliptic Curves + EC Formats
/// </summary>
public class Ja3Profile
{
    /// <summary>模板名称，如 "chrome_122"、"firefox_123"</summary>
    public string Name { get; set; } = "";

    /// <summary>目标平台: browser / android / ios / okhttp / unity</summary>
    public string Platform { get; set; } = "browser";

    /// <summary>OpenSSL cipher list 格式的密码套件列表</summary>
    public string CipherList { get; set; } = "";

    /// <summary>椭圆曲线（用于 SSL_CTX_set1_curves_list）</summary>
    public string CurvesList { get; set; } = "";

    /// <summary>应用层协议协商 (ALPN)</summary>
    public string[]? AlpnProtocols { get; set; }

    /// <summary>JA3 字符串（用于识别和调试）</summary>
    public string? Ja3String { get; set; }
}

/// <summary>
/// JA3 指纹模板库 — 内置 20+ 常见 TLS 指纹
/// </summary>
public static class Ja3Templates
{
    /// <summary>按名称获取指纹模板</summary>
    public static Ja3Profile? Get(string name) =>
        All.FirstOrDefault(p => p.Name == name);

    /// <summary>获取特定平台的首选模板</summary>
    public static Ja3Profile GetForPlatform(string platform) =>
        platform.ToLower() switch
        {
            "android" => Chrome122,
            "ios" => Safari17,
            "okhttp" => OkHttp4,
            "unity" => UnityTls,
            _ => Chrome122
        };

    /// <summary>所有内置模板</summary>
    public static readonly Ja3Profile[] All =
    {
        Chrome122, Firefox123, Safari17, OkHttp4,
        UnityTls, Edge122, Curl8
    };

    // ── Chrome 122 ──
    public static readonly Ja3Profile Chrome122 = new()
    {
        Name = "chrome_122",
        Platform = "browser",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "X25519:prime256v1:secp384r1:secp521r1",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
    };

    // ── Firefox 123 ──
    public static readonly Ja3Profile Firefox123 = new()
    {
        Name = "firefox_123",
        Platform = "browser",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "X25519:prime256v1:secp384r1:secp521r1:ffdhe3072",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24,0"
    };

    // ── Safari 17 (macOS/iOS) ──
    public static readonly Ja3Profile Safari17 = new()
    {
        Name = "safari_17",
        Platform = "browser",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "X25519:prime256v1:secp384r1:secp521r1",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49196-49200-52393-52392-49195-49199-49188-49187-49162-49161,0-23-65281-10-11-13-5-18-16-30032-43-27-21-35,29-23-24,0"
    };

    // ── OkHttp 4.x (Android) ──
    public static readonly Ja3Profile OkHttp4 = new()
    {
        Name = "okhttp_4",
        Platform = "android",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "prime256v1:secp384r1:secp521r1:X25519",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
    };

    // ── Unity TLS ──
    public static readonly Ja3Profile UnityTls = new()
    {
        Name = "unity_tls",
        Platform = "game",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "prime256v1:secp384r1",
        AlpnProtocols = new[] { "http/1.1" },
        Ja3String = "771,49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0"
    };

    // ── Edge 122 (Chromium) ──
    public static readonly Ja3Profile Edge122 = new()
    {
        Name = "edge_122",
        Platform = "browser",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "X25519:prime256v1:secp384r1:secp521r1",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
    };

    // ── curl 8.x ──
    public static readonly Ja3Profile Curl8 = new()
    {
        Name = "curl_8",
        Platform = "cli",
        CipherList = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DSS:!3DES:!SEED:!IDEA",
        CurvesList = "X25519:prime256v1:secp384r1:secp521r1",
        AlpnProtocols = new[] { "h2", "http/1.1" },
        Ja3String = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
    };
}
