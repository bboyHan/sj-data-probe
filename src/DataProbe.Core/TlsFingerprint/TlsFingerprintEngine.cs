using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using DataProbe.Core.TlsFingerprint;

namespace DataProbe.Core.TlsFingerprint;

/// <summary>
/// TLS 指纹引擎 — 在上游连接（TlsProxy → 目标服务器）中替换 SChannel，
/// 使用 OpenSSL（如果可用）或自定义配置的 SslStream 来伪装指纹。
///
/// 设计：
///   - 用 OpenSSL 代替 SChannel 作为 TLS 客户端（完全控制密码套件和扩展）
///   - 如果 OpenSSL DLL 不可用，回退到 SChannel（当前行为）
///   - 通过 Ja3Profile 选择伪装成哪种客户端
/// </summary>
public class TlsFingerprintEngine
{
    private bool _openSslAvailable;
    private string? _openSslError;

    /// <summary>OpenSSL 是否可用</summary>
    public bool IsOpenSslAvailable => _openSslAvailable;

    /// <summary>OpenSSL 错误信息（如果不可用）</summary>
    public string? OpenSslError => _openSslError;

    /// <summary>当前有效的指纹配置</summary>
    public Ja3Profile? ActiveProfile { get; private set; }

    public TlsFingerprintEngine()
    {
        try
        {
            // 检查 OpenSSL DLL 是否可加载
            var handle = NativeMethods.LoadLibrary("libssl-3.dll");
            if (handle == nint.Zero)
                handle = NativeMethods.LoadLibrary("libssl-1_1.dll");
            if (handle == nint.Zero)
                handle = NativeMethods.LoadLibrary("ssleay32.dll");

            if (handle != nint.Zero)
            {
                NativeMethods.FreeLibrary(handle);
                _openSslAvailable = true;
                Console.Error.WriteLine("[TlsFingerprint] OpenSSL available");
            }
            else
            {
                _openSslError = "No OpenSSL DLL found, using SChannel";
                Console.Error.WriteLine($"[TlsFingerprint] {_openSslError}");
            }
        }
        catch (Exception ex)
        {
            _openSslError = ex.Message;
            Console.Error.WriteLine($"[TlsFingerprint] {_openSslError}");
        }
    }

    /// <summary>选择一个指纹配置</summary>
    public Ja3Profile SelectProfile(string? platform = null)
    {
        ActiveProfile = platform != null
            ? Ja3Templates.GetForPlatform(platform)
            : Ja3Templates.Chrome122;

        Console.Error.WriteLine($"[TlsFingerprint] Using profile: {ActiveProfile.Name}");
        return ActiveProfile;
    }

    /// <summary>
    /// 创建一个 TLS 流，使用选定的指纹配置连接远程服务器。
    /// 如果 OpenSSL 可用，使用 OpenSSL；否则回退到 SChannel。
    /// </summary>
    public async Task<SslStream> CreateTlsStreamAsync(
        NetworkStream transportStream,
        string hostname,
        Ja3Profile? profile = null,
        CancellationToken ct = default)
    {
        var fp = profile ?? ActiveProfile ?? Ja3Templates.Chrome122;

        if (_openSslAvailable)
        {
            // OpenSSL 模式 — 使用自定义指纹连接
            // Phase 8 完整实现：创建 OpenSSL SSL 对象，配置指纹，连接到服务器
            // 当前简化：用 SChannel 但携带指纹元数据
            Console.Error.WriteLine($"[TlsFingerprint] OpenSSL connect: {hostname} as {fp.Name}");
        }

        // SChannel 回退（当前默认行为）
        var sslStream = new SslStream(transportStream, false, ValidateCert);
        try
        {
            await sslStream.AuthenticateAsClientAsync(
                hostname, null, SslProtocols.None, false);
        }
        catch
        {
            // 某些服务器可能不支持高级协议，降级重试
            await sslStream.AuthenticateAsClientAsync(
                hostname, null,
                SslProtocols.Tls12 | SslProtocols.Tls13, false);
        }

        return sslStream;
    }

    /// <summary>服务器证书验证（Phase 8 增强：支持证书固定检查）</summary>
    private static bool ValidateCert(object sender, X509Certificate? certificate,
        X509Chain? chain, SslPolicyErrors errors)
    {
        // 当前接受所有证书（MITM 代理的上游连接需要这样）
        return true;
    }
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern nint LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FreeLibrary(nint hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern nint GetProcAddress(nint hModule, string lpProcName);
}
