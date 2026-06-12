using System.Net;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// 数据包捕获驱动抽象层。
/// 生产环境: WinDivert P/Invoke
/// 开发环境: Mock / pcap 回放
/// </summary>
public interface ICaptureDriver : IDisposable
{
    void Open(int queueLen = 8192);
    void Close();
    bool Read(out CapturedPacket packet);
    void Send(CapturedPacket packet);
    event Action<CapturedPacket>? OnPacketCaptured;
}

public class CapturedPacket
{
    public byte[] RawData { get; set; } = Array.Empty<byte>();
    public IPAddress SrcAddr { get; set; } = IPAddress.Any;
    public IPAddress DstAddr { get; set; } = IPAddress.Any;
    public ushort SrcPort { get; set; }
    public ushort DstPort { get; set; }
    public bool IsOutbound { get; set; } = true;

    public string? ExtractSni()
    {
        return TlsHelper.ExtractSni(RawData.AsSpan());
    }

    public ConnectionKey GetConnectionKey()
    {
        return new ConnectionKey(
            BitConverter.ToUInt32(SrcAddr.GetAddressBytes()),
            SrcPort,
            BitConverter.ToUInt32(DstAddr.GetAddressBytes()),
            DstPort
        );
    }
}

/// <summary>
/// TLS SNI 提取工具。
/// </summary>
public static class TlsHelper
{
    /// <summary>
    /// 从 TCP 负载中提取 TLS SNI (ClientHello)。
    /// </summary>
    public static string? ExtractSni(ReadOnlySpan<byte> data)
    {
        if (data.Length < 50) return null;
        if (data[0] != 0x16) return null; // TLS content type: Handshake
        if (data[5] != 0x01) return null; // Handshake type: ClientHello

        var pos = 43; // skip fixed TLS header
        if (pos + 2 > data.Length) return null;
        var sessionIdLen = data[pos]; pos++;
        pos += sessionIdLen;
        if (pos + 2 > data.Length) return null;
        var cipherSuitesLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
        pos += cipherSuitesLen;
        if (pos + 1 > data.Length) return null;
        var compressionMethodsLen = data[pos]; pos++;
        pos += compressionMethodsLen;
        if (pos + 2 > data.Length) return null;
        var extensionsLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
        var end = pos + extensionsLen;
        if (end > data.Length) end = data.Length;

        while (pos + 4 <= end)
        {
            var extType = (data[pos] << 8) | data[pos + 1]; pos += 2;
            var extLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
            if (pos + extLen > end) break;

            if (extType == 0x00) // Server Name Indication
            {
                var sniStart = pos + 5;
                var sniLen = (data[pos + 2] << 8) | data[pos + 3];
                if (sniStart + sniLen <= data.Length)
                {
                    return System.Text.Encoding.UTF8.GetString(data[sniStart..(sniStart + sniLen)]);
                }
            }
            pos += extLen;
        }
        return null;
    }
}
