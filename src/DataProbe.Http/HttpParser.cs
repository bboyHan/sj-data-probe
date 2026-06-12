using System.Text;
using System.Text.RegularExpressions;
using DataProbe.Core;

namespace DataProbe.Http;

public class HttpRequest
{
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new();
    public byte[] Body { get; set; } = Array.Empty<byte>();
    public string BodyString => Encoding.UTF8.GetString(Body);
}

public class HttpResponse
{
    public int StatusCode { get; set; }
    public string ReasonPhrase { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new();
    public byte[] Body { get; set; } = Array.Empty<byte>();
    public string BodyString => Encoding.UTF8.GetString(Body);
}

/// <summary>
/// Minimal HTTP/1.1 parser for TLS proxy traffic.
/// Parses request/response lines, headers, and body.
/// Does not support chunked transfer encoding (suitable for short responses).
/// </summary>
public class HttpParser
{
    private static readonly string[] RequestMethods =
        { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" };

    public HttpRequest? ParseRequest(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10) return null;

        var text = Encoding.UTF8.GetString(data);
        if (string.IsNullOrEmpty(text)) return null;

        // Detect HTTP/2 preface
        if (data[0] == 0x50 && data[1] == 0x52 && data[2] == 0x49) // "PRI"
            return null; // HTTP/2 not yet supported in this parser

        // Parse first line
        var lines = text.Split("\r\n");
        if (lines.Length < 1) return null;

        var firstLine = lines[0];
        var parts = firstLine.Split(' ');

        if (parts.Length < 2) return null;
        if (!RequestMethods.Contains(parts[0])) return null;

        var request = new HttpRequest
        {
            Method = parts[0],
        };

        // Path or full URL
        var path = parts[1];
        var headersEnd = text.IndexOf("\r\n\r\n");
        if (headersEnd < 0) return null;

        // Parse headers
        var headerLines = text[..headersEnd].Split("\r\n");
        var host = "";
        for (int i = 1; i < headerLines.Length; i++)
        {
            var headerParts = headerLines[i].Split(": ", 2);
            if (headerParts.Length == 2)
            {
                request.Headers[headerParts[0].ToLower()] = headerParts[1];
                if (headerParts[0].ToLower() == "host")
                    host = headerParts[1];
            }
        }

        request.Url = path.StartsWith("http")
            ? path
            : $"https://{host}{path}";

        // Body
        var bodyStart = headersEnd + 4;
        if (bodyStart < text.Length)
        {
            var contentLength = request.Headers
                .GetValueOrDefault("content-length", "0");
            if (int.TryParse(contentLength, out var len) && len > 0)
            {
                var bodyEnd = Math.Min(bodyStart + len, text.Length);
                request.Body = Encoding.UTF8.GetBytes(text[bodyStart..bodyEnd]);
            }
        }

        return request;
    }

    public HttpResponse? ParseResponse(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        if (string.IsNullOrEmpty(text) || !text.StartsWith("HTTP/"))
            return null;

        var lines = text.Split("\r\n");
        if (lines.Length < 1) return null;

        var firstLine = lines[0];
        var parts = firstLine.Split(' ', 3);
        if (parts.Length < 2) return null;

        var response = new HttpResponse
        {
            StatusCode = int.TryParse(parts[1], out var code) ? code : 0,
            ReasonPhrase = parts.Length > 2 ? parts[2] : "",
        };

        var headersEnd = text.IndexOf("\r\n\r\n");
        if (headersEnd < 0) return null;

        // Parse headers
        var headerLines = text[..headersEnd].Split("\r\n");
        for (int i = 1; i < headerLines.Length; i++)
        {
            var headerParts = headerLines[i].Split(": ", 2);
            if (headerParts.Length == 2)
                response.Headers[headerParts[0].ToLower()] = headerParts[1];
        }

        // Body
        var bodyStart = headersEnd + 4;
        if (bodyStart < text.Length)
        {
            var contentLength = response.Headers
                .GetValueOrDefault("content-length", "0");
            if (int.TryParse(contentLength, out var len) && len > 0)
            {
                var bodyEnd = Math.Min(bodyStart + len, text.Length);
                response.Body = Encoding.UTF8.GetBytes(text[bodyStart..bodyEnd]);
            }
            else
            {
                // Read until connection close for short responses
                response.Body = Encoding.UTF8.GetBytes(text[bodyStart..]);
            }
        }

        return response;
    }
}
