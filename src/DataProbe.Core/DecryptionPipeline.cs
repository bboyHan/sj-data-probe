using DataProbe.Core.Plugin;

namespace DataProbe.Core;

/// <summary>
/// 解密流水线 — 在 TLS 解密之后、规则引擎之前运行。
/// 负责退掉应用层的自定义加密/编码层。
///
/// 执行顺序：
///   ① 内置解码器（Base64、URL decode、Hex）
///   ② 插件解密器（IDecryptionPlugin）
///   ③ 输出解密后的 NormalizedTransaction → 规则引擎
///
/// 每个解码器/解密器只负责退掉自己认识的那一层。
/// 可以链式调用：Base64 → AES → JSON
/// </summary>
public class DecryptionPipeline
{
    private readonly List<Func<NormalizedTransaction, NormalizedTransaction?>> _decoders = new();
    private readonly PluginManager? _pluginManager;

    public DecryptionPipeline(PluginManager? pluginManager = null)
    {
        _pluginManager = pluginManager;

        // 内置解码器（按优先级排序）
        _decoders.Add(DecodeBase64Body);       // ① Base64 解码
        _decoders.Add(DecodeJsonEscaped);      // ② JSON 转义解码
        _decoders.Add(DecodeUrlEncoded);       // ③ URL 编码解码
        _decoders.Add(DecodeHexBody);          // ④ Hex 解码
    }

    /// <summary>解密一个事务</summary>
    public NormalizedTransaction Decrypt(NormalizedTransaction tx)
    {
        if (string.IsNullOrEmpty(tx.ResponseBody)) return tx;

        var current = tx;
        int maxIterations = 10;

        // 1) 链式运行内置解码器
        for (int i = 0; i < maxIterations; i++)
        {
            var before = current.ResponseBody;
            foreach (var decoder in _decoders)
            {
                var result = decoder(current);
                if (result != null) current = result;
            }
            if (current.ResponseBody == before) break; // 没有变化时停止
        }

        // 2) 运行插件解密器
        if (_pluginManager != null)
        {
            var decryptors = _pluginManager.GetPlugins<IDecryptionPlugin>();
            foreach (var plugin in decryptors.Where(p => p.CanDecrypt(current)))
            {
                try
                {
                    var result = plugin.DecryptAsync(current).GetAwaiter().GetResult();
                    if (result != null) current = result;
                    Console.Error.WriteLine($"[Decrypt] {plugin.Name} applied");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[Decrypt] {plugin.Name} error: {ex.Message}");
                }
            }
        }

        return current;
    }

    /// <summary>对 SessionSnapshot 中的所有事务执行解密流水线</summary>
    public SessionSnapshot DecryptSession(SessionSnapshot session)
    {
        foreach (var step in session.Steps)
        {
            for (int i = 0; i < step.HttpTransactions.Count; i++)
            {
                var tx = step.HttpTransactions[i];
                // 重建 NormalizedTransaction 作为管道输入
                var normalized = new NormalizedTransaction
                {
                    Domain = ExtractDomain(tx.Url),
                    Method = tx.Method,
                    Path = ExtractPath(tx.Url),
                    Url = tx.Url,
                    StatusCode = tx.StatusCode,
                    RequestBody = tx.RequestBody.RawText,
                    ResponseBody = tx.ResponseBody.RawText,
                    RequestHeaders = tx.RequestHeaders.AsPairs,
                    ResponseHeaders = tx.ResponseHeaders.AsPairs,
                };

                var decrypted = Decrypt(normalized);
                if (decrypted.ResponseBody != tx.ResponseBody.RawText)
                {
                    // 解密成功，更新 HttpResponseBody
                    tx.ResponseBody = DataFragment.FromBody(
                        decrypted.ResponseBody, "decrypted");
                    Console.Error.WriteLine($"[Decrypt] Body decrypted for {tx.Url}");
                }
            }
        }
        return session;
    }

    // ═══════════════════ 内置解码器 ═══════════════════

    /// <summary>Base64 解码 — 检测高熵 + Base64 字符集</summary>
    private static NormalizedTransaction? DecodeBase64Body(NormalizedTransaction tx)
    {
        var body = tx.ResponseBody?.Trim();
        if (string.IsNullOrEmpty(body) || body.Length < 20) return null;

        // 检查是否是 Base64（只含合法字符）
        var base64Chars = body.Count(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=');
        if (base64Chars < body.Length * 0.9) return null;

        try
        {
            // 修复 Base64 填充
            var b64 = body;
            var padding = 4 - b64.Length % 4;
            if (padding != 4) b64 += new string('=', padding);

            var decoded = Convert.FromBase64String(b64);
            var text = System.Text.Encoding.UTF8.GetString(decoded);

            // 只接受解码后可读的内容
            if (text.Any(c => c >= 32 && c <= 126) || text.Contains('\n'))
            {
                tx.ResponseBody = text;
                tx.ResponseBodyBase64 = body;
                return tx;
            }
        }
        catch { }

        return null;
    }

    /// <summary>JSON 转义解码 — 处理 JSON 字符串中被转义的 JSON</summary>
    private static NormalizedTransaction? DecodeJsonEscaped(NormalizedTransaction tx)
    {
        var body = tx.ResponseBody?.Trim();
        if (string.IsNullOrEmpty(body)) return null;

        // 检测是否为被转义的 JSON (外层有 \" 或 \\)
        if (body.Contains("\\\"") && body.Contains("\\\\"))
        {
            try
            {
                var unescaped = System.Text.RegularExpressions.Regex.Unescape(body);
                if (unescaped != body)
                {
                    tx.ResponseBody = unescaped;
                    return tx;
                }
            }
            catch { }
        }

        return null;
    }

    /// <summary>URL 编码解码</summary>
    private static NormalizedTransaction? DecodeUrlEncoded(NormalizedTransaction tx)
    {
        var body = tx.ResponseBody?.Trim();
        if (string.IsNullOrEmpty(body) || !body.Contains('%')) return null;

        try
        {
            var decoded = Uri.UnescapeDataString(body);
            if (decoded != body && decoded.Length > 10)
            {
                tx.ResponseBody = decoded;
                return tx;
            }
        }
        catch { }

        return null;
    }

    /// <summary>Hex 解码</summary>
    private static NormalizedTransaction? DecodeHexBody(NormalizedTransaction tx)
    {
        var body = tx.ResponseBody?.Trim();
        if (string.IsNullOrEmpty(body) || body.Length < 20) return null;

        // 检查是否为 Hex
        if (!body.All(c => char.IsAsciiHexDigit(c))) return null;

        try
        {
            var bytes = Convert.FromHexString(body);
            var text = System.Text.Encoding.UTF8.GetString(bytes);
            if (text.Any(c => c >= 32 && c <= 126))
            {
                tx.ResponseBody = text;
                return tx;
            }
        }
        catch { }

        return null;
    }

    private static string ExtractDomain(string url)
    {
        try { return new Uri(url).Host; }
        catch { return ""; }
    }

    private static string ExtractPath(string url)
    {
        try { return new Uri(url).AbsolutePath; }
        catch { return ""; }
    }
}
