using System.Net;
using System.Runtime.InteropServices;

namespace DataProbe.Capture;

/// <summary>
/// DNS 劫持器 — 拦截 DNS 响应，将支付域名的 A 记录替换为 127.0.0.1。
///
/// 原理：
///   应用请求 pay.qq.com → 系统 DNS 查询 → DNS 服务器返回真实 IP
///   → WinDivert 拦截 DNS 响应 → 替换 A 记录为 127.0.0.1
///   → 应用连接 127.0.0.1:443 → TLS 代理接收 → MITM
///
/// 覆盖场景：
///   - 微信小程序（使用系统 DNS 解析）
///   - 抖音小程序
///   - PC 端游（HTTP API 调用）
///   - 所有走系统 DNS 解析的应用
/// </summary>
public class DnsSpoofer : IDisposable
{
    private const string DllName = "WinDivert.dll";
    private nint _handle;
    private bool _disposed;
    private Thread? _captureThread;

    // DNS 相关常量
    private const int DNS_HEADER_LEN = 12;
    private const int UDP_HEADER_LEN = 8;

    // DNS 劫持目标域名（从外部配置注入，由调用方设置）
    private HashSet<string> _spoofDomains = new(StringComparer.OrdinalIgnoreCase);

    public void SetSpoofDomains(string[] domains)
    {
        _spoofDomains = new HashSet<string>(
            (domains ?? Array.Empty<string>()).Select(d =>
                d.EndsWith(".") ? d : d + "."),
            StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>当前劫持域名数量</summary>
    public int SpoofDomainCount => _spoofDomains.Count;

    // ── WinDivert P/Invoke ────────────────────────────

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WinDivertOpen(string filter, int layer, short priority, long flags);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertClose(nint handle);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertRecv(nint handle, byte[] pPacket, int packetLen, out int recvLen, ref WinDivertAddress pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertSend(nint handle, byte[] pPacket, int packetLen, out int sendLen, ref WinDivertAddress pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertSetParam(nint handle, int param, long value);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong WinDivertHelperCalcChecksums(byte[] pPacket, int packetLen, ref WinDivertAddress pAddr, ulong flags);

    private const int WINDIVERT_PARAM_QUEUE_LEN = 0;
    private const int WINDIVERT_LAYER_NETWORK = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct WinDivertAddress
    {
        public long Timestamp;
        public uint LayerEvent;
        public uint IfIdx;
        public uint SubIfIdx;
        public uint DstAddr;
        public uint SrcAddr;
        public ushort DstPort;
        public ushort SrcPort;
    }

    // ── 公共接口 ─────────────────────────────────────

    private long _spoofedCount;
    public long SpoofedCount => Interlocked.Read(ref _spoofedCount);
    public bool IsRunning => _captureThread?.IsAlive ?? false;

    public void Start()
    {
        if (_disposed || _handle != nint.Zero) return;

        // SNIFF 模式：捕获入站的 DNS 响应（来自 DNS 服务器端口 53）
        // 使用 priority=1，避免与 WinDivertDriver (priority=0) 冲突
        var filter = "inbound and udp.SrcPort == 53 and udp.PayloadLength > 0";
        _handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 1, 0);

        if (_handle == nint.Zero || _handle == (nint)(-1))
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"DNS WinDivert open failed (error {error}). Requires Administrator.");
        }

        // 较浅的队列（DNS 响应延迟要求高）
        WinDivertSetParam(_handle, 0, 256);

        _captureThread = new Thread(CaptureLoop) { Name = "DNS-Spoofer", IsBackground = true };
        _captureThread.Start();
        Console.Error.WriteLine("[DnsSpoofer] Started");
    }

    public void Stop()
    {
        if (_handle != nint.Zero)
        {
            WinDivertClose(_handle);
            _handle = nint.Zero;
        }
    }

    // ── 捕获循环 ─────────────────────────────────────

    private void CaptureLoop()
    {
        var packet = new byte[4096];
        var addr = new WinDivertAddress();

        try
        {
            while (!_disposed)
            {
                if (!WinDivertRecv(_handle, packet, packet.Length, out var recvLen, ref addr))
                {
                    if (_disposed) break;
                    continue;
                }
                if (recvLen <= 0) continue;

                // IP 头长度: (packet[0] & 0x0F) * 4
                var ipHdrLen = (packet[0] & 0x0F) * 4;
                if (ipHdrLen < 20 || ipHdrLen + UDP_HEADER_LEN >= recvLen) continue;

                // UDP 头偏移 = ipHdrLen
                // DNS 消息偏移 = ipHdrLen + 8 (UDP header)
                var dnsOffset = ipHdrLen + UDP_HEADER_LEN;
                var dnsLen = recvLen - dnsOffset;
                if (dnsLen < DNS_HEADER_LEN) continue;

                // 解析并劫持 DNS 响应
                if (TrySpoof(packet, dnsOffset, dnsLen))
                {
                    Interlocked.Increment(ref _spoofedCount);

                    // 重新计算 IP + UDP 校验和
                    WinDivertHelperCalcChecksums(packet, recvLen, ref addr, 0);

                    // 发送修改后的包
                    WinDivertSend(_handle, packet, recvLen, out _, ref addr);
                }
                else
                {
                    // 未修改 → 原样发出
                    WinDivertSend(_handle, packet, recvLen, out _, ref addr);
                }
            }
        }
        catch (Exception ex)
        {
            if (!_disposed)
                Console.Error.WriteLine($"[DnsSpoofer] Error: {ex.Message}");
        }
    }

    // ── DNS 解析与劫持 ───────────────────────────────

    /// <summary>
    /// 尝试劫持 DNS 响应。成功时修改 packet 中的 DNS 内容，返回 true。
    /// </summary>
    private bool TrySpoof(byte[] packet, int dnsOffset, int dnsLen)
    {
        var flags = (packet[dnsOffset + 2] << 8) | packet[dnsOffset + 3];

        // 必须是标准查询响应 (QR=1) 且无错误 (RCODE=0)
        if ((flags & 0x8000) == 0) return false;  // QR=0 → 请求，忽略
        if ((flags & 0x000F) != 0) return false;  // RCODE != 0 → 错误响应

        var qdCount = (packet[dnsOffset + 4] << 8) | packet[dnsOffset + 5];
        var anCount = (packet[dnsOffset + 6] << 8) | packet[dnsOffset + 7];

        if (qdCount == 0 || anCount == 0) return false;

        // 跳过 DNS 头部 + questions，找到 answers 区域
        var pos = dnsOffset + DNS_HEADER_LEN;
        var end = dnsOffset + dnsLen;

        // 解析问题区域（跳过所有 questions）
        for (int i = 0; i < qdCount; i++)
        {
            pos = SkipDnsName(packet, pos, end);
            if (pos < 0) return false;
            pos += 4; // QTYPE + QCLASS
        }

        // 遍历 Answer 区域，找到匹配域名的 A 记录
        var modified = false;
        for (int i = 0; i < anCount; i++)
        {
            var nameStart = pos;
            string? name = ReadDnsName(packet, ref pos, end, dnsOffset);
            if (name == null) return false;

            if (pos + 10 > end) return false;
            var type = (packet[pos] << 8) | packet[pos + 1];
            var cls = (packet[pos + 2] << 8) | packet[pos + 3];
            var ttl = (uint)((packet[pos + 4] << 24) | (packet[pos + 5] << 16) |
                             (packet[pos + 6] << 8) | packet[pos + 7]);
            var rdLen = (packet[pos + 8] << 8) | packet[pos + 9];
            pos += 10;

            // A 记录 (type=1) 且域名匹配
            if (type == 1 && rdLen == 4 && _spoofDomains.Contains(name))
            {
                // 修改 IP 为 127.0.0.1
                packet[pos] = 127;
                packet[pos + 1] = 0;
                packet[pos + 2] = 0;
                packet[pos + 3] = 1;
                modified = true;
                Console.Error.WriteLine($"[DnsSpoofer] Spoofed: {name} -> 127.0.0.1");
            }

            pos += rdLen;
        }

        return modified;
    }

    /// <summary>
    /// 从 DNS 消息中读取域名（支持指针压缩）。
    /// </summary>
    private static string? ReadDnsName(byte[] data, ref int pos, int end, int dnsOffset)
    {
        var labels = new List<string>();
        var jumped = false;
        var origPos = pos;

        while (pos < end)
        {
            var len = data[pos];

            // 指针压缩 (0xC0 | 0xC0+)
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= end) return null;
                var ptr = ((len & 0x3F) << 8) | data[pos + 1];
                if (!jumped) origPos = pos + 2;
                pos = dnsOffset + ptr;  // 注意：指针相对于 DNS 消息起始
                jumped = true;
                continue;
            }

            if (len == 0) break; // 域名结束

            pos++;
            if (pos + len > end) return null;
            labels.Add(System.Text.Encoding.ASCII.GetString(data, pos, len));
            pos += len;
        }

        if (!jumped) pos++;

        return string.Join(".", labels) + ".";
    }

    private static int SkipDnsName(byte[] data, int pos, int end)
    {
        while (pos < end)
        {
            var len = data[pos];
            if ((len & 0xC0) == 0xC0) return pos + 2;  // 指针
            if (len == 0) return pos + 1;               // 结束
            pos += 1 + len;
        }
        return -1;
    }

    public void Dispose()
    {
        _disposed = true;
        Stop();
    }
}
