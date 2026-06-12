using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace DataProbe.Core.TlsFingerprint;

/// <summary>
/// OpenSSL 包装器 — 通过 P/Invoke 调用 OpenSSL 原生库。
/// 提供比 .NET SslStream 更细粒度的 TLS 配置能力：
///   - 完全控制密码套件列表（JA3 指纹核心）
///   - 控制椭圆曲线和扩展
///   - 控制 ALPN 协议
///
/// 依赖: libssl-3.dll / libcrypto-3.dll（Windows OpenSSL 3.x）
///       或 libssl-1_1.dll（Windows OpenSSL 1.1.x）
///
/// 如果 DLL 不可用，所有方法返回 false/空，调用方回退到 SChannel。
/// </summary>
public class OpenSslWrapper : IDisposable
{
    private nint _sslCtx = nint.Zero;
    private nint _ssl = nint.Zero;
    private nint _bio = nint.Zero;
    private bool _initialized;
    private bool _disposed;

    /// <summary>是否已成功初始化</summary>
    public bool IsInitialized => _initialized;

    /// <summary>尝试加载 OpenSSL 库并初始化</summary>
    public bool Initialize()
    {
        if (_initialized) return true;

        try
        {
            // 1) 加载库（如果尚未加载）
            var libSsl = NativeMethods.LoadLibrary("libssl-3.dll");
            if (libSsl == nint.Zero)
                libSsl = NativeMethods.LoadLibrary("libssl-1_1.dll");
            if (libSsl == nint.Zero)
                libSsl = NativeMethods.LoadLibrary("ssleay32.dll");

            if (libSsl == nint.Zero) return false;

            // 2) 初始化 SSL 上下文
            var method = OpenSslMethods.TLS_client_method();
            if (method == nint.Zero) return false;

            _sslCtx = OpenSslMethods.SSL_CTX_new(method);
            if (_sslCtx == nint.Zero) return false;

            _initialized = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[OpenSSL] Init failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>设置密码套件列表（JA3 指纹核心）</summary>
    public bool SetCipherList(string cipherList)
    {
        if (!_initialized || _sslCtx == nint.Zero) return false;
        return OpenSslMethods.SSL_CTX_set_cipher_list(_sslCtx, cipherList) == 1;
    }

    /// <summary>设置椭圆曲线列表</summary>
    public bool SetCurvesList(string curvesList)
    {
        if (!_initialized || _sslCtx == nint.Zero) return false;
        return OpenSslMethods.SSL_CTX_set1_curves_list(_sslCtx, curvesList) == 1;
    }

    /// <summary>设置 ALPN 协议列表</summary>
    public bool SetAlpnProtocols(string[] protocols)
    {
        if (!_initialized || _sslCtx == nint.Zero || protocols.Length == 0)
            return false;

        // 构建 ALPN wire format: length-prefixed strings
        var wire = new List<byte>();
        foreach (var p in protocols)
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(p);
            wire.Add((byte)bytes.Length);
            wire.AddRange(bytes);
        }

        return OpenSslMethods.SSL_CTX_set_alpn_protos(_sslCtx, wire.ToArray(), wire.Count) == 0;
    }

    /// <summary>连接到远程服务器</summary>
    public async Task<bool> ConnectAsync(string hostname, int port, CancellationToken ct = default)
    {
        if (!_initialized || _sslCtx == nint.Zero) return false;

        try
        {
            // 创建 SSL 对象
            _ssl = OpenSslMethods.SSL_new(_sslCtx);
            if (_ssl == nint.Zero) return false;

            // 创建 TCP 连接
            var socket = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(10));
            await socket.ConnectAsync(hostname, port, connectCts.Token);

            // 创建 BIO
            _bio = OpenSslMethods.BIO_new_socket((nint)socket.Handle, 0);
            if (_bio == nint.Zero) return false;

            OpenSslMethods.SSL_set_bio(_ssl, _bio, _bio);
            OpenSslMethods.SSL_set_tlsext_host_name(_ssl, hostname);

            // TLS 握手
            var result = OpenSslMethods.SSL_connect(_ssl);
            return result == 1;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>读取解密后的数据</summary>
    public int Read(byte[] buffer, int offset, int count)
    {
        if (!_initialized || _ssl == nint.Zero) return -1;
        return OpenSslMethods.SSL_read(_ssl, buffer, count);
    }

    /// <summary>写入明文数据（自动加密）</summary>
    public int Write(byte[] data, int offset, int count)
    {
        if (!_initialized || _ssl == nint.Zero) return -1;
        return OpenSslMethods.SSL_write(_ssl, data, count);
    }

    /// <summary>从 OpenSSL SSL 对象创建 .NET SslStream 兼容包装</summary>
    public Stream? GetStream()
    {
        if (!_initialized || _ssl == nint.Zero) return null;
        // Phase 8 完整：创建 Stream 包装器将 SSL_read/SSL_write 暴露为 .NET Stream
        return null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_ssl != nint.Zero) { OpenSslMethods.SSL_free(_ssl); _ssl = nint.Zero; }
        if (_sslCtx != nint.Zero) { OpenSslMethods.SSL_CTX_free(_sslCtx); _sslCtx = nint.Zero; }
    }
}

/// <summary>
/// OpenSSL P/Invoke 方法表 — 仅在 OpenSSL DLL 可用时加载
/// </summary>
internal static class OpenSslMethods
{
    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "TLS_client_method", ExactSpelling = true)]
    private static extern nint TLS_client_method_3();

    [DllImport("libssl-1_1.dll", CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "TLS_client_method", ExactSpelling = true)]
    private static extern nint TLS_client_method_11();

    [DllImport("ssleay32.dll", CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "TLS_client_method", ExactSpelling = true)]
    private static extern nint TLS_client_method_legacy();

    public static nint TLS_client_method()
    {
        var m = TLS_client_method_3();
        if (m != nint.Zero) return m;
        m = TLS_client_method_11();
        if (m != nint.Zero) return m;
        return TLS_client_method_legacy();
    }

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern nint SSL_CTX_new(nint method);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_CTX_free(nint ctx);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_set_cipher_list(nint ctx,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string str);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_set1_curves_list(nint ctx,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string str);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_set_alpn_protos(nint ctx, byte[] protos, int len);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern nint SSL_new(nint ctx);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_free(nint ssl);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_fd(nint ssl, nint fd);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_set_bio(nint ssl, nint rbio, nint wbio);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_tlsext_host_name(nint ssl,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_connect(nint ssl);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_write(nint ssl, byte[] buf, int num);

    [DllImport("libssl-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_read(nint ssl, byte[] buf, int num);

    [DllImport("libcrypto-3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern nint BIO_new_socket(nint sock, int close_flag);
}
