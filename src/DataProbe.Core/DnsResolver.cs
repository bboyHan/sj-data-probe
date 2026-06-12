using System.Net;
using System.Net.Sockets;

namespace DataProbe.Core;

/// <summary>
/// DNS 解析器 — 提供域名解析和 TCP 连接功能。
/// 内置 ConnectAsync 供 TlsProxy 使用。
/// </summary>
public class DnsResolver
{
    private readonly TimeSpan _timeout;
    private readonly IPAddress _dnsServer;

    public DnsResolver(IPAddress? dnsServer = null, int timeoutMs = 3000)
    {
        _dnsServer = dnsServer ?? IPAddress.Parse("8.8.8.8");
        _timeout = TimeSpan.FromMilliseconds(timeoutMs);
    }

    /// <summary>异步解析域名，返回所有 A 记录 IP</summary>
    public async Task<IPAddress[]> ResolveAsync(string domain)
    {
        try
        {
            var entries = await Dns.GetHostAddressesAsync(domain);
            return entries;
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    /// <summary>同步解析域名</summary>
    public IPAddress[] Resolve(string domain)
    {
        try
        {
            return Dns.GetHostAddresses(domain);
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    /// <summary>
    /// 连接到远程主机的指定端口（用于 TlsProxy 的上游连接）
    /// </summary>
    public static async Task<Socket> ConnectAsync(string hostname, int port, CancellationToken ct = default)
    {
        var addresses = await Dns.GetHostAddressesAsync(hostname, ct);
        if (addresses.Length == 0)
            throw new SocketException((int)SocketError.HostNotFound);

        // 按优先顺序尝试连接（IPv6 优先）
        var sorted = addresses.OrderByDescending(a => a.AddressFamily == AddressFamily.InterNetworkV6 ? 1 : 0).ToArray();

        Socket? lastException = null;
        foreach (var addr in sorted)
        {
            try
            {
                var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(10));
#if NET8_0_OR_GREATER
                await socket.ConnectAsync(addr, port, cts.Token);
#else
                await socket.ConnectAsync(addr, port);
#endif
                return socket;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                // 尝试下一个地址
            }
        }

        throw new SocketException((int)SocketError.ConnectionRefused);
    }
}
