using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 目标侦察器 — 对目标进行网络层面的情报收集。
/// 执行 DNS 解析、端口探测、TLS 握手分析、CDN 识别。
/// 所有侦察均在无管理员权限下完成。
/// </summary>
public class TargetRecon
{
    private static readonly int[] CommonPorts = { 80, 443, 8080, 8443, 3000, 5000, 9090, 9443 };

    /// <summary>
    /// 对目标执行完整侦察
    /// </summary>
    /// <param name="target">目标域名或 URL</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>目标情报报告</returns>
    public async Task<TargetProfile> ReconAsync(string target, CancellationToken ct = default)
    {
        var host = ExtractHost(target);
        var profile = new TargetProfile
        {
            TargetId = host,
            Type = DetectTargetType(target),
            DisplayName = host
        };

        // 并行执行所有侦察任务
        var dnsTask = ResolveDnsAsync(host, ct);
        var tlsTask = ProbeTlsAsync(host, ct);
        var portTask = ScanPortsAsync(host, ct);

        await Task.WhenAll(dnsTask, tlsTask, portTask);

        // DNS 结果
        profile.IPAddresses = dnsTask.Result;
        profile.CDNProvider = DetectCDN(profile.IPAddresses);

        // TLS 结果
        var tlsInfo = tlsTask.Result;
        if (tlsInfo != null)
        {
            profile.TLSVersion = tlsInfo.Version;
            // 检查是否有证书锁定行为（通过是否使用标准 CA）
            profile.HasCertPinning = tlsInfo.HasCertPinning;
        }

        // 端口结果
        var openPorts = portTask.Result;
        if (openPorts.Contains(443) || openPorts.Contains(8443) || openPorts.Contains(9443))
        {
            profile.ProtectionRating = DataProbe.Core.ProtectionLevel.Low;
        }

        // 综合评级（基础版：仅根据网络侦察结果）
        profile.ProtectionRating = EstimateProtectionLevel(profile);

        // 通道建议
        profile.RecommendedChannel = RecommendChannel(profile);

        return profile;
    }

    /// <summary>
    /// DNS 解析 — 获取目标所有 IP 地址
    /// </summary>
    private static async Task<string[]> ResolveDnsAsync(string host, CancellationToken ct)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, ct);
            return addresses.Select(a => a.ToString()).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// TLS 探测 — 建立 TLS 连接获取证书和版本信息
    /// </summary>
    private static async Task<TlsProbeResult?> ProbeTlsAsync(string host, CancellationToken ct)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(5));
#if NET8_0_OR_GREATER
            await socket.ConnectAsync(host, 443, connectCts.Token);
#else
            await socket.ConnectAsync(host, 443);
#endif

            if (!socket.Connected) return null;

            using var networkStream = new NetworkStream(socket, ownsSocket: false);
            using var sslStream = new SslStream(networkStream, false,
                (sender, certificate, chain, errors) =>
                {
                    // 检查证书是否由操作系统信任颁发
                    // 如果证书链不完整或自签名 → 可能有证书锁定
                    return true; // 接受所有证书用于探测
                });

            using var sslCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            sslCts.CancelAfter(TimeSpan.FromSeconds(5));

            try
            {
                await sslStream.AuthenticateAsClientAsync(host, null, System.Security.Authentication.SslProtocols.None, false);
            }
            catch
            {
                return null;
            }

            var result = new TlsProbeResult
            {
                Version = sslStream.SslProtocol.ToString(),
            };

            // 分析远程证书
            var remoteCert = sslStream.RemoteCertificate;
            if (remoteCert != null)
            {
                using var cert = new X509Certificate2(remoteCert);
                result.Issuer = cert.Issuer;
                result.Subject = cert.Subject;
                result.Expires = cert.NotAfter;
                result.IsValid = DateTime.UtcNow < cert.NotAfter;

                // 证书锁定无法通过 TLS 探测确定（需要逆向工程分析 APK/DLL）
                // HasCertPinning 由 ReverseEngineering 扫描器设置，此处始终为 false
                result.HasCertPinning = false;
            }

            return result;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 端口扫描 — 检查常见 Web 端口是否开放
    /// </summary>
    private static async Task<int[]> ScanPortsAsync(string host, CancellationToken ct)
    {
        var openPorts = new List<int>();

        foreach (var port in CommonPorts)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(2));

#if NET8_0_OR_GREATER
                await socket.ConnectAsync(host, port, connectCts.Token);
#else
                await socket.ConnectAsync(host, port);
#endif

                if (socket.Connected)
                    openPorts.Add(port);

                socket.Close();
            }
            catch
            {
                // 端口未开放或超时
            }
        }

        return openPorts.ToArray();
    }

    /// <summary>
    /// CDN 检测 — 通过 IP 地址范围判断 CDN 提供商
    /// </summary>
    private static string DetectCDN(string[] ips)
    {
        // 简化版：检查常见 CDN 的 ASN 或 IP 段
        // 完整版应使用 GeoIP/ASN 数据库
        foreach (var ip in ips)
        {
            if (string.IsNullOrEmpty(ip)) continue;

            // Cloudflare 常见 IP 段检测
            if (ip.StartsWith("104.") || ip.StartsWith("172.64.") ||
                ip.StartsWith("188.114.") || ip.StartsWith("103.21."))
                return "Cloudflare";

            // Akamai 常见 IP 段
            if (ip.StartsWith("23.") || ip.StartsWith("184.") ||
                ip.StartsWith("96.") || ip.StartsWith("72."))
                return "Akamai";

            // Amazon CloudFront
            if (ip.StartsWith("13.32.") || ip.StartsWith("13.224.") ||
                ip.StartsWith("54.192.") || ip.StartsWith("205.251."))
                return "CloudFront";
        }

        return "";
    }

    /// <summary>
    /// 从输入中提取主机名
    /// </summary>
    private static string ExtractHost(string target)
    {
        // 移除协议前缀
        var host = target;
        if (host.StartsWith("http://")) host = host[7..];
        if (host.StartsWith("https://")) host = host[8..];

        // 移除路径
        var slashIdx = host.IndexOf('/');
        if (slashIdx > 0) host = host[..slashIdx];

        // 移除端口
        var colonIdx = host.IndexOf(':');
        if (colonIdx > 0) host = host[..colonIdx];

        return host;
    }

    /// <summary>
    /// 检测目标类型
    /// </summary>
    private static TargetType DetectTargetType(string target)
    {
        if (target.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))
            return TargetType.MobileApp;
        if (target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return TargetType.PcGame;
        if (target.StartsWith("http"))
            return TargetType.Website;
        if (target.Contains('.') || char.IsLetter(target[0]))
            return TargetType.Website;

        return TargetType.Other;
    }

    /// <summary>
    /// 综合评定防护等级
    /// </summary>
    private static DataProbe.Core.ProtectionLevel EstimateProtectionLevel(TargetProfile profile)
    {
        // 基础评级逻辑（后续由逆向工程增强）
        if (profile.HasCertPinning)
            return DataProbe.Core.ProtectionLevel.Medium;

        if (!string.IsNullOrEmpty(profile.CDNProvider))
            return DataProbe.Core.ProtectionLevel.Low;

        if (profile.IPAddresses.Length == 0)
            return DataProbe.Core.ProtectionLevel.Unknown;

        return DataProbe.Core.ProtectionLevel.None;
    }

    /// <summary>
    /// 推荐采集通道
    /// </summary>
    private static string RecommendChannel(TargetProfile profile)
    {
        return profile.ProtectionRating switch
        {
            DataProbe.Core.ProtectionLevel.None => "SystemProxy",   // 零配置，浏览器目标
            DataProbe.Core.ProtectionLevel.Low => "SystemProxy",     // 有 CDN 但无锁定
            DataProbe.Core.ProtectionLevel.Medium => "WinDivert",    // 需要内核拦截
            DataProbe.Core.ProtectionLevel.High => "ProcessHook",    // 需要进程注入
            DataProbe.Core.ProtectionLevel.Extreme => "Passive",     // 仅被动分析
            _ => "SystemProxy"
        };
    }

    private class TlsProbeResult
    {
        public string? Version { get; set; }
        public string? Issuer { get; set; }
        public string? Subject { get; set; }
        public DateTime Expires { get; set; }
        public bool IsValid { get; set; }
        public bool HasCertPinning { get; set; }
    }
}
