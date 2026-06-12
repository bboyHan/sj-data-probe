using System.IO.Compression;
using System.Text;

namespace DataProbe.Core;

/// <summary>
/// HTTP 响应体解码工具：
///   1. chunked transfer → 合并
///   2. gzip 压缩 → 解压
/// </summary>
public static class GzipHelper
{
    /// <summary>
    /// 对原始 HTTP 响应（含头部）进行传输层解码。
    /// </summary>
    public static string DecompressBody(string raw)
    {
        if (raw == null) return raw;

        var isChunked = raw.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase);
        var isGzip = raw.Contains("Content-Encoding: gzip", StringComparison.OrdinalIgnoreCase);

        if (!isChunked && !isGzip) return raw;

        var sep = raw.IndexOf("\r\n\r\n");
        if (sep < 0) return raw;

        var headers = raw[..(sep + 4)];
        var bodyStr = raw[(sep + 4)..];

        if (isChunked) bodyStr = DecodeChunked(bodyStr);
        if (isGzip) bodyStr = DecompressGzip(bodyStr);

        return headers + bodyStr;
    }

    private static string DecodeChunked(string body)
    {
        if (string.IsNullOrEmpty(body)) return body;

        var result = new StringBuilder(body.Length);
        var pos = 0;

        while (pos < body.Length)
        {
            var crlf = body.IndexOf("\r\n", pos, StringComparison.Ordinal);
            if (crlf < 0) break;

            var sizeStr = body[pos..crlf].Trim();
            if (sizeStr == "") break;

            var semiIdx = sizeStr.IndexOf(';');
            if (semiIdx >= 0) sizeStr = sizeStr[..semiIdx];

            if (!int.TryParse(sizeStr,
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture,
                out var chunkSize))
                break;

            if (chunkSize == 0) break;

            var chunkStart = crlf + 2;
            if (chunkStart + chunkSize > body.Length) break;

            result.Append(body, chunkStart, chunkSize);
            pos = chunkStart + chunkSize;
            if (pos + 1 < body.Length && body[pos] == '\r' && body[pos + 1] == '\n')
                pos += 2;
        }

        var decoded = result.ToString();
        return decoded.Length > 0 ? decoded : body;
    }

    private static string DecompressGzip(string body)
    {
        if (string.IsNullOrEmpty(body)) return body;

        var rawBytes = Encoding.UTF8.GetBytes(body);
        if (rawBytes.Length < 2 || rawBytes[0] != 0x1F || rawBytes[1] != 0x8B)
            return body;

        try
        {
            using var compressed = new MemoryStream(rawBytes);
            using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gzip.CopyTo(output);
            return Encoding.UTF8.GetString(output.ToArray());
        }
        catch { return body; }
    }
}
