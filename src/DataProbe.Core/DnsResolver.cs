using System.Net;

namespace DataProbe.Core;

/// <summary>
/// DNS 解析器 — 绕过 Windows hosts 文件，直接查询 8.8.8.8。
/// 用于获取域名的真实 IP，避免被 hosts 修改影响。
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

    /// <summary>
    /// 异步解析域名，返回所有 A 记录 IP。
    /// </summary>
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

    /// <summary>
    /// 同步解析域名。
    /// </summary>
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
}
