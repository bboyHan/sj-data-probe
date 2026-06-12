using System.Text;

namespace DataProbe.Http;

/// <summary>
/// HTTP/2 协议检测器 — 识别 HTTP/2 连接。
/// 注意：当前为检测阶段，完整解析需要实现 HPACK 和帧处理（后续版本）。
///
/// HTTP/2 连接以 PRI preface 开头：
/// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
/// </summary>
public class Http2Parser : IProtocolParser
{
    public string ProtocolName => "HTTP/2";

    // PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    private static readonly byte[] Http2Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0");

    public bool CanParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < Http2Preface.Length) return false;

        for (int i = 0; i < Http2Preface.Length; i++)
            if (data[i] != Http2Preface[i]) return false;

        return true;
    }

    public ParseResult? ParseRequest(ReadOnlySpan<byte> data)
    {
        // HTTP/2 帧解析需要实现 HPACK 解压缩和帧重组
        // 当前返回 null 表示无法解析，后续版本实现
        return null;
    }

    public ParseResult? ParseResponse(ReadOnlySpan<byte> data)
    {
        // HTTP/2 响应帧解析需要 HPACK
        return null;
    }
}
