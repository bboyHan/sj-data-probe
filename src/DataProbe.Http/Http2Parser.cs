using System.Text;
using DataProbe.Core;
using DataProbe.Http.Http2;

namespace DataProbe.Http;

/// <summary>
/// HTTP/2 协议解析器 — 完整实现。
/// 支持帧解析、HPACK 解压缩、流管理。
/// 输出统一的 ParseResult 供后续处理。
/// </summary>
public class Http2Parser : IProtocolParser
{
    public string ProtocolName => "HTTP/2";

    // HTTP/2 PRI preface (RFC 7540 Section 3.5)
    private static readonly byte[] Http2Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    // 每个连接一个 HPACK 解码器（动态表跨帧维护）
    private readonly Dictionary<string, HpackDecoder> _decoders = new();
    private readonly object _decoderLock = new();

    /// <summary>检测是否为 HTTP/2 流量（PRI preface 或 SETTINGS 帧）</summary>
    public bool CanParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10) return false;

        // PRI preface 检测（24 字节）
        if (data.Length >= Http2Preface.Length)
        {
            bool match = true;
            for (int i = 0; i < Http2Preface.Length; i++)
                if (data[i] != Http2Preface[i]) { match = false; break; }
            if (match) return true;
        }

        // 客户端 SETTINGS 帧检测（连接建立后的第一个帧）
        // 帧头: 0x00 0x00 0x00 0x04 0x00 0x00 0x00 0x00 0x00
        // Length=0, Type=SETTINGS(4), Flags=0, StreamID=0
        if (data[3] == 0x04 && data[5] == 0x00 && data[6] == 0x00 && data[7] == 0x00 && data[8] == 0x00)
            return true;

        return false;
    }

    /// <summary>解析请求（HTTP/2 请求帧序列）</summary>
    public ParseResult? ParseRequest(ReadOnlySpan<byte> data)
    {
        return ParseFrames(data, isRequest: true);
    }

    /// <summary>解析响应（HTTP/2 响应帧序列）</summary>
    public ParseResult? ParseResponse(ReadOnlySpan<byte> data)
    {
        return ParseFrames(data, isRequest: false);
    }

    /// <summary>
    /// 从帧序列中解析出一个完整的请求或响应
    /// </summary>
    private ParseResult? ParseFrames(ReadOnlySpan<byte> data, bool isRequest)
    {
        var buffer = data.ToArray();
        int offset = 0;
        var headerFrames = new List<(int StreamId, byte[] Data)>();
        ParseResult? result = null;

        while (offset + 9 <= buffer.Length)
        {
            if (!Http2FrameHeader.TryParse(buffer, offset, out var header))
                break;

            int frameDataStart = offset + 9;
            int frameDataEnd = frameDataStart + header.Length;

            if (frameDataEnd > buffer.Length) break;

            switch (header.Type)
            {
                case Http2FrameType.Headers:
                    // 收集 HEADERS 帧（可能包含 CONTINUATION 帧）
                    var headerBlock = CollectHeaderBlock(buffer, offset);
                    if (headerBlock.HasValue)
                    {
                        var parsed = DecodeHeaders(headerBlock.Value.Data, headerBlock.Value.StreamId);
                        if (parsed != null)
                        {
                            result = parsed;
                            result.Headers.TryGetValue("content-length", out var cl);
                            // HEADERS 后可能紧跟 DATA 帧
                        }
                    }
                    break;

                case Http2FrameType.Data:
                    // 数据帧 — body 内容
                    int padLen = 0;
                    int dataStart = frameDataStart;
                    if (header.IsPadded && header.Length > 0)
                    {
                        padLen = buffer[dataStart];
                        dataStart++;
                    }
                    int dataLen = header.Length - padLen - (header.IsPadded ? 1 : 0);
                    if (dataLen > 0 && result != null)
                    {
                        result.Body = buffer[dataStart..(dataStart + dataLen)];
                    }
                    break;

                case Http2FrameType.Settings:
                    // SETTINGS 帧 — 不包含请求/响应数据
                    break;

                case Http2FrameType.GoAway:
                    // GOAWAY — 连接关闭
                    break;
            }

            offset = frameDataEnd;
        }

        return result;
    }

    /// <summary>
    /// 收集完整的 HEADERS 块（HEADERS + CONTINUATION 帧）
    /// </summary>
    private (byte[] Data, int StreamId)? CollectHeaderBlock(byte[] buffer, int offset)
    {
        if (!Http2FrameHeader.TryParse(buffer, offset, out var firstHeader))
            return null;

        int streamId = firstHeader.StreamId;
        int frameDataStart = offset + 9;

        using var ms = new MemoryStream();

        // 跳过填充字节（如果有）
        int dataStart = frameDataStart;
        int dataLen = firstHeader.Length;
        if (firstHeader.IsPadded && firstHeader.Length > 0)
        {
            int padLen = buffer[dataStart];
            dataStart++;
            dataLen -= padLen + 1;
        }
        if (dataLen > 0)
            ms.Write(buffer, dataStart, dataLen);

        // 如果非 END_HEADERS，继续收集 CONTINUATION 帧
        if (!firstHeader.IsEndHeaders)
        {
            int nextOffset = frameDataStart + firstHeader.Length;
            while (nextOffset + 9 <= buffer.Length)
            {
                if (!Http2FrameHeader.TryParse(buffer, nextOffset, out var contHeader))
                    break;

                if (contHeader.Type != Http2FrameType.Continuation)
                    break;
                if (contHeader.StreamId != streamId)
                    break;

                int contDataStart = nextOffset + 9;
                if (contHeader.Length > 0)
                    ms.Write(buffer, contDataStart, contHeader.Length);

                nextOffset = contDataStart + contHeader.Length;

                if (contHeader.IsEndHeaders)
                    break;
            }
        }

        return (ms.ToArray(), streamId);
    }

    /// <summary>
    /// 使用 HPACK 解码 HEADERS 块并转换为 ParseResult
    /// </summary>
    private ParseResult? DecodeHeaders(byte[] headerBlock, int streamId)
    {
        if (headerBlock.Length == 0) return null;

        HpackDecoder decoder;
        string sessionKey = $"stream_{streamId}";

        lock (_decoderLock)
        {
            if (!_decoders.TryGetValue(sessionKey, out decoder))
            {
                decoder = new HpackDecoder();
                _decoders[sessionKey] = decoder;
            }
        }

        var headers = decoder.Decode(headerBlock, 0, headerBlock.Length);
        if (headers.Count == 0) return null;

        var result = new ParseResult();
        foreach (var (name, value) in headers)
        {
            var lower = name.ToLowerInvariant();

            switch (lower)
            {
                case ":method":
                    result.Method = value;
                    break;
                case ":path":
                    var qIdx = value.IndexOf('?');
                    result.Path = qIdx >= 0 ? value[..qIdx] : value;
                    result.QueryString = qIdx >= 0 ? value[qIdx..] : "";
                    break;
                case ":scheme":
                    // 用于构造完整 URL
                    break;
                case ":authority":
                    result.Headers["host"] = value;
                    break;
                case ":status":
                    result.StatusCode = int.TryParse(value, out var code) ? code : 0;
                    break;
                default:
                    result.Headers[lower] = value;
                    break;
            }
        }

        return result;
    }

    /// <summary>清理解码器（连接关闭时调用）</summary>
    public void RemoveDecoder(string sessionKey)
    {
        lock (_decoderLock)
        {
            if (_decoders.TryGetValue(sessionKey, out var decoder))
            {
                decoder.Dispose();
                _decoders.Remove(sessionKey);
            }
        }
    }

    /// <summary>清理所有解码器</summary>
    public void ClearDecoders()
    {
        lock (_decoderLock)
        {
            foreach (var decoder in _decoders.Values)
                decoder.Dispose();
            _decoders.Clear();
        }
    }
}
