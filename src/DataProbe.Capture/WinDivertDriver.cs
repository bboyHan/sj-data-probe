using System.Net;
using System.Runtime.InteropServices;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// WinDivert 内核驱动封装 — DIVERT 模式，TCP SYN 拦截。
/// 支持动态设置 SNI 关键词，由调用方决定哪些域名需要深度处理。
/// </summary>
public class WinDivertDriver : ICaptureDriver
{
    private const string DllName = "WinDivert.dll";
    private nint _handle;
    private bool _disposed;
    private byte[] _packetBuffer = new byte[65535];
    private WinDivertAddress _addr;
    private long _directPacketCount;
    private string[] _sniKeywords = Array.Empty<string>();

    public bool DivertEnabled { get; set; } = true;
    public int ProxyPort { get; set; } = 18802;
    public long DirectPacketCount => Interlocked.Read(ref _directPacketCount);
    public event Action<CapturedPacket>? OnPacketCaptured;

    /// <summary>设置 SNI 关键词。命中则转发到 TlsProxy；空列表 = 全部转发。</summary>
    public void SetSniKeywords(string[] keywords) => _sniKeywords = keywords ?? Array.Empty<string>();

    private bool IsTargetSni(string sni)
    {
        if (sni == null) return false;
        if (_sniKeywords.Length == 0) return true;
        foreach (var kw in _sniKeywords)
            if (sni.Contains(kw, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint WinDivertOpen(string filter, int layer, short priority, long flags);
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertClose(nint handle);
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertSetParam(nint handle, int param, long value);
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertRecv(nint handle, byte[] pPacket, int packetLen, out int recvLen, ref WinDivertAddress pAddr);
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertSend(nint handle, byte[] pPacket, int packetLen, out int sendLen, ref WinDivertAddress pAddr);
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

    public void Open(int queueLen = 8192)
    {
        var filter = "outbound and tcp.DstPort == 443 and tcp.Syn and not tcp.Ack";
        var flags = DivertEnabled ? 0L : 0x0001L;
        _handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
        if (_handle == nint.Zero || _handle == (nint)(-1))
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"WinDivert open failed (error {error})");
        }
        WinDivertSetParam(_handle, WINDIVERT_PARAM_QUEUE_LEN, queueLen);
        var t = new Thread(CaptureThread) { Name = "WinDivert", IsBackground = true };
        t.Start();
    }

    public void Close()
    {
        if (_handle != nint.Zero && _handle != (nint)(-1))
            WinDivertClose(_handle);
        _handle = nint.Zero;
    }

    public bool Read(out CapturedPacket packet) { packet = null!; return false; }
    public void Send(CapturedPacket packet) { }

    private void CaptureThread()
    {
        var proxyIp = BitConverter.ToUInt32(new byte[] { 127, 0, 0, 1 });
        try
        {
            while (!_disposed)
            {
                if (!WinDivertRecv(_handle, _packetBuffer, _packetBuffer.Length, out var recvLen, ref _addr))
                { if (_disposed) break; continue; }
                if (recvLen <= 0) continue;
                Interlocked.Increment(ref _directPacketCount);

                // Redirect ALL to TlsProxy; proxy decides MITM vs transparent
                _addr.DstAddr = proxyIp;
                _addr.DstPort = (ushort)ProxyPort;
                WinDivertHelperCalcChecksums(_packetBuffer, recvLen, ref _addr, 0);
                WinDivertSend(_handle, _packetBuffer, recvLen, out _, ref _addr);
            }
        }
        catch (Exception ex)
        { if (!_disposed) Console.Error.WriteLine($"[WinDivert] Error: {ex.Message}"); }
    }

    public void Dispose() { _disposed = true; Close(); }
}
