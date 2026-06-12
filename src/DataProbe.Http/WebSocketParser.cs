using System.Text;
using DataProbe.Core;

namespace DataProbe.Http;

/// <summary>
/// WebSocket 帧解析器 (RFC 6455) — 在 TLS 解密后的数据流中
/// 检测并解析 WebSocket 帧。
///
/// 帧格式:
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-------+------------------------------------------------+
///   |F|R|R|R| opcode|M| Payload len |         Extended payload       |
///   |I|S|S|S|  (4)  |A|     (7)     |       length (16/64 bits)      |
///   |N|V|V|V|       |S|             |   (if payload_len==126/127)    |
///   | |1|2|3|       |K|             |                                 |
///   +-+-+-+-+-------+- - - - - - - -+ - - - - - - - - - - - - - - -+
///   |     Mask key (if MASK set)    |          Payload Data          |
///   +-------------------------------+--------------------------------+
/// </summary>
public class WebSocketParser
{
    /// <summary>WebSocket OpCode</summary>
    public enum OpCode : byte
    {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA
    }

    /// <summary>
    /// 尝试从缓冲区中解析一个 WebSocket 帧
    /// </summary>
    /// <param name="buffer">数据缓冲区</param>
    /// <param name="offset">起始偏移</param>
    /// <param name="frame">解析出的帧</param>
    /// <returns>是否成功解析，以及消耗的字节数</returns>
    public static bool TryParseFrame(byte[] buffer, int offset, out WebSocketFrame frame, out int consumed)
    {
        frame = default;
        consumed = 0;

        if (buffer.Length - offset < 2) return false;

        byte b1 = buffer[offset];
        byte b2 = buffer[offset + 1];

        bool fin = (b1 & 0x80) != 0;
        byte opcode = (byte)(b1 & 0x0F);
        bool mask = (b2 & 0x80) != 0;
        int payloadLen = b2 & 0x7F;

        int headerLen = 2;

        // Extended payload length
        if (payloadLen == 126)
        {
            if (buffer.Length - offset < 4) return false;
            payloadLen = (buffer[offset + 2] << 8) | buffer[offset + 3];
            headerLen = 4;
        }
        else if (payloadLen == 127)
        {
            if (buffer.Length - offset < 10) return false;
            payloadLen = (int)((long)buffer[offset + 2] << 56 |
                               (long)buffer[offset + 3] << 48 |
                               (long)buffer[offset + 4] << 40 |
                               (long)buffer[offset + 5] << 32 |
                               (long)buffer[offset + 6] << 24 |
                               (long)buffer[offset + 7] << 16 |
                               (long)buffer[offset + 8] << 8 |
                               buffer[offset + 9]);
            headerLen = 10;
        }

        // Mask key
        byte[]? maskKey = null;
        if (mask)
        {
            if (buffer.Length - offset < headerLen + 4) return false;
            maskKey = new byte[4];
            Array.Copy(buffer, offset + headerLen, maskKey, 0, 4);
            headerLen += 4;
        }

        // Payload
        int totalLen = headerLen + payloadLen;
        if (buffer.Length - offset < totalLen) return false;

        byte[] payload = new byte[payloadLen];
        Array.Copy(buffer, offset + headerLen, payload, 0, payloadLen);

        // Unmask if needed
        if (mask && maskKey != null)
        {
            for (int i = 0; i < payloadLen; i++)
                payload[i] ^= maskKey[i % 4];
        }

        frame = new WebSocketFrame
        {
            Fin = fin,
            OpCode = (OpCode)opcode,
            Mask = mask,
            Payload = payload,
            IsText = opcode == 1,
            IsBinary = opcode == 2,
            IsClose = opcode == 8,
            IsPing = opcode == 9,
            IsPong = opcode == 0xA
        };

        consumed = totalLen;
        return true;
    }

    /// <summary>
    /// 检测数据流是否包含 WebSocket 握手升级
    /// </summary>
    public static bool IsWebSocketUpgrade(string requestHeaders)
    {
        return requestHeaders.Contains("Upgrade: websocket", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 从 TLS 解密后的数据流中提取所有 WebSocket 消息
    /// </summary>
    public static List<WebSocketMessage> ExtractMessages(byte[] streamData, int stepIndex, string direction)
    {
        var messages = new List<WebSocketMessage>();
        int offset = 0;
        int msgIndex = 0;

        while (offset < streamData.Length)
        {
            if (!TryParseFrame(streamData, offset, out var frame, out var consumed))
                break;

            if (frame.OpCode == OpCode.Text || frame.OpCode == OpCode.Binary)
            {
                messages.Add(new WebSocketMessage
                {
                    StepIndex = stepIndex,
                    Index = ++msgIndex,
                    Direction = direction,
                    OpCode = (int)frame.OpCode,
                    Payload = frame.IsText
                        ? Encoding.UTF8.GetString(frame.Payload)
                        : Convert.ToBase64String(frame.Payload),
                    Timestamp = DateTime.UtcNow
                });
            }

            offset += consumed;
        }

        return messages;
    }
}

/// <summary>
/// 解析后的 WebSocket 帧
/// </summary>
public struct WebSocketFrame
{
    public bool Fin { get; set; }
    public WebSocketParser.OpCode OpCode { get; set; }
    public bool Mask { get; set; }
    public byte[] Payload { get; set; }
    public bool IsText { get; set; }
    public bool IsBinary { get; set; }
    public bool IsClose { get; set; }
    public bool IsPing { get; set; }
    public bool IsPong { get; set; }

    public readonly string PayloadAsString =>
        IsText ? Encoding.UTF8.GetString(Payload) : Convert.ToBase64String(Payload);
}
