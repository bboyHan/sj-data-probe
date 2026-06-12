using System.Text;

namespace DataProbe.Http;

/// <summary>
/// HTTP/1.1 协议解析器 — 实现 IProtocolParser。
/// 从现有 HttpParser 提取核心逻辑，适配新的接口体系。
/// </summary>
public class Http11Parser : IProtocolParser
{
    public string ProtocolName => "HTTP/1.1";

    private static readonly string[] RequestMethods =
        { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" };

    /// <summary>
    /// 检测是否为 HTTP/1.1 请求或响应。
    /// 请求以方法名开头（GET/POST等），响应以 "HTTP/" 开头。
    /// </summary>
    public bool CanParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10) return false;

        // HTTP/2 preface detection (PRI * HTTP/2.0) — not HTTP/1.1
        if (data[0] == 0x50 && data.Length > 3 &&
            data[1] == 0x52 && data[2] == 0x49) return false; // "PRI"

        var text = Encoding.UTF8.GetString(data[..Math.Min(data.Length, 20)]);

        // Response: "HTTP/"
        if (text.StartsWith("HTTP/")) return true;

        // Request: method + space
        foreach (var m in RequestMethods)
            if (text.StartsWith(m + " ")) return true;

        return false;
    }

    public ParseResult? ParseRequest(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        if (string.IsNullOrEmpty(text)) return null;

        var lines = text.Split("\r\n");
        if (lines.Length < 1) return null;

        var firstLine = lines[0];
        var parts = firstLine.Split(' ');
        if (parts.Length < 2) return null;
        if (!RequestMethods.Contains(parts[0])) return null;

        var result = new ParseResult
        {
            Method = parts[0],
        };

        var pathQuery = parts[1];
        var qIdx = pathQuery.IndexOf('?');
        if (qIdx >= 0)
        {
            result.Path = pathQuery[..qIdx];
            result.QueryString = pathQuery[qIdx..];
        }
        else
        {
            result.Path = pathQuery;
        }

        var headersEnd = text.IndexOf("\r\n\r\n");
        if (headersEnd < 0) return null;

        // Headers
        var headerLines = text[..headersEnd].Split("\r\n");
        for (int i = 1; i < headerLines.Length; i++)
        {
            var idx = headerLines[i].IndexOf(':');
            if (idx > 0)
                result.Headers[headerLines[i][..idx].Trim().ToLower()] =
                    headerLines[i][(idx + 1)..].Trim();
        }

        // Body
        var bodyStart = headersEnd + 4;
        if (bodyStart < text.Length)
        {
            var cl = result.Headers.GetValueOrDefault("content-length", "0");
            if (int.TryParse(cl, out var len) && len > 0)
            {
                var bodyEnd = Math.Min(bodyStart + len, text.Length);
                result.Body = Encoding.UTF8.GetBytes(text[bodyStart..bodyEnd]);
            }
        }

        return result;
    }

    public ParseResult? ParseResponse(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        if (string.IsNullOrEmpty(text) || !text.StartsWith("HTTP/"))
            return null;

        var lines = text.Split("\r\n");
        if (lines.Length < 1) return null;

        var firstLine = lines[0];
        var parts = firstLine.Split(' ', 3);
        if (parts.Length < 2) return null;

        var result = new ParseResult
        {
            StatusCode = int.TryParse(parts[1], out var code) ? code : 0,
        };

        var headersEnd = text.IndexOf("\r\n\r\n");
        if (headersEnd < 0) return null;

        // Headers
        var headerLines = text[..headersEnd].Split("\r\n");
        for (int i = 1; i < headerLines.Length; i++)
        {
            var idx = headerLines[i].IndexOf(':');
            if (idx > 0)
                result.Headers[headerLines[i][..idx].Trim().ToLower()] =
                    headerLines[i][(idx + 1)..].Trim();
        }

        // Body
        var bodyStart = headersEnd + 4;
        if (bodyStart < text.Length)
        {
            var cl = result.Headers.GetValueOrDefault("content-length", "0");
            if (int.TryParse(cl, out var len) && len > 0)
            {
                var bodyEnd = Math.Min(bodyStart + len, text.Length);
                result.Body = Encoding.UTF8.GetBytes(text[bodyStart..bodyEnd]);
            }
            else
            {
                result.Body = Encoding.UTF8.GetBytes(text[bodyStart..]);
            }
        }

        return result;
    }
}
