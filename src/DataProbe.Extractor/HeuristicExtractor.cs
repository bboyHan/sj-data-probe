using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DataProbe.Core;

namespace DataProbe.Extractor;

/// <summary>
/// 启发式提取器 — 不需要预设规则也能自动发现高价值数据。
/// 作为预设规则引擎的补充，在 ProcessSessionAsync 末尾自动运行。
///
/// 检测能力：
///   ① 高熵值检测 → 疑似 Token/API Key/Secret
///   ② JSON 敏感字段扫描 → token/password/secret 等字段自动提取
///   ③ JWT 格式检测 + 解码
///   ④ 高频值跨请求关联
/// </summary>
public class HeuristicExtractor
{
    private readonly double _entropyThreshold;

    /// <summary>高熵检测的最低字符串长度</summary>
    private const int MinHighEntropyLength = 20;

    /// <summary>JWT 正则</summary>
    private static readonly Regex JwtRegex = new(
        @"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        RegexOptions.Compiled);

    /// <summary>敏感字段名（不区分大小写）</summary>
    private static readonly HashSet<string> SensitiveFieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "token", "access_token", "accessToken", "secret", "api_key", "apikey",
        "apiSecret", "api_secret", "password", "passwd", "auth_token", "authToken",
        "refresh_token", "refreshToken", "id_token", "idToken", "session_key",
        "sessionKey", "ssid", "auth", "authorization", "private_key", "privateKey",
        "client_secret", "clientSecret", "app_secret", "appSecret"
    };

    /// <summary>支付/资金相关字段</summary>
    private static readonly HashSet<string> PaymentFieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "pay_url", "payUrl", "payment_url", "paymentUrl", "order_id", "orderId",
        "trade_no", "tradeNo", "transaction_id", "transactionId", "amount",
        "price", "total", "currency", "pay_method", "payMethod", "qr_code"
    };

    public HeuristicExtractor(double entropyThreshold = 4.5)
    {
        _entropyThreshold = entropyThreshold;
    }

    /// <summary>
    /// 对 SessionSnapshot 执行启发式提取
    /// </summary>
    public List<DataEvidence> Extract(SessionSnapshot session)
    {
        var results = new List<DataEvidence>();

        foreach (var step in session.Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                // 1. JSON 敏感字段扫描
                results.AddRange(ScanJsonFields(http, step.StepIndex));

                // 2. 高熵值检测（响应体）
                results.AddRange(ScanHighEntropy(http.ResponseBody, http, step.StepIndex));

                // 3. JWT 检测
                results.AddRange(ScanJwt(http, step.StepIndex));
            }

            // 4. WebSocket 高熵检测
            foreach (var ws in step.WebSocketMessages)
            {
                if (ws.Payload.Length < MinHighEntropyLength) continue;
                var entropy = CalculateEntropy(ws.Payload);
                if (entropy >= _entropyThreshold)
                {
                    results.Add(DataEvidence.Heuristic(
                        "heuristic_high_entropy", Truncate(ws.Payload, 100),
                        CapturedDataType.Token, ws.LocationId, 0.7f));
                }
            }
        }

        return results;
    }

    /// <summary>
    /// JSON 敏感字段扫描 — 自动发现 Token/Key/密码等
    /// </summary>
    private List<DataEvidence> ScanJsonFields(HttpTransaction http, int stepIndex)
    {
        var results = new List<DataEvidence>();

        // 扫描响应体 JSON
        if (http.ResponseJson != null)
        {
            results.AddRange(ExtractSensitiveJsonFields(
                http.ResponseJson, http, stepIndex, "response.body"));
        }

        // 扫描请求体 JSON
        if (http.RequestJson != null)
        {
            results.AddRange(ExtractSensitiveJsonFields(
                http.RequestJson, http, stepIndex, "request.body"));
        }

        return results;
    }

    private List<DataEvidence> ExtractSensitiveJsonFields(
        JsonDoc doc, HttpTransaction http, int stepIndex, string source)
    {
        var results = new List<DataEvidence>();

        foreach (var fieldPath in doc.FieldNames())
        {
            var fieldName = fieldPath.Split('.').Last();

            // 检测敏感字段
            if (SensitiveFieldNames.Contains(fieldName))
            {
                var value = doc.SelectValue(fieldPath);
                if (!string.IsNullOrEmpty(value) && value.Length >= 8)
                {
                    var isJwt = JwtRegex.IsMatch(value);
                    results.Add(DataEvidence.Heuristic(
                        "heuristic_json_field." + fieldName.ToLower(),
                        Truncate(value, 200),
                        isJwt ? CapturedDataType.Token : CapturedDataType.Key,
                        $"step.{stepIndex}.{source}.json.{fieldPath}",
                        isJwt ? 0.9f : 0.75f
                    ));
                }
            }

            // 检测支付相关字段
            if (PaymentFieldNames.Contains(fieldName))
            {
                var value = doc.SelectValue(fieldPath);
                if (!string.IsNullOrEmpty(value))
                {
                    results.Add(DataEvidence.Heuristic(
                        "heuristic_payment_field." + fieldName.ToLower(),
                        Truncate(value, 200),
                        CapturedDataType.Payment,
                        $"step.{stepIndex}.{source}.json.{fieldPath}",
                        0.7f
                    ));
                }
            }
        }

        return results;
    }

    /// <summary>
    /// 高熵值检测 — 发现随机性高的字符串（可能是 Token/Key）
    /// </summary>
    private List<DataEvidence> ScanHighEntropy(DataFragment fragment, HttpTransaction http, int stepIndex)
    {
        var results = new List<DataEvidence>();
        if (fragment.Size < MinHighEntropyLength) return results;

        // 在文本中查找连续的高熵子串
        var text = fragment.RawText;
        var wordMatches = Regex.Matches(text, @"[a-zA-Z0-9_\-/+=]{20,100}");

        foreach (Match match in wordMatches)
        {
            if (match.Value.Length < MinHighEntropyLength) continue;

            var entropy = CalculateEntropy(match.Value);
            if (entropy >= _entropyThreshold)
            {
                // 检查是否已经包含相同值（去重）
                var alreadyFound = results.Any(r => r.Value == match.Value);
                if (!alreadyFound)
                {
                    results.Add(DataEvidence.Heuristic(
                        "heuristic_high_entropy",
                        Truncate(match.Value, 100),
                        CapturedDataType.Token,
                        $"step.{stepIndex}.{fragment.LocationId}",
                        Math.Min(1.0f, (float)(entropy / 8.0))
                    ));
                }
            }
        }

        return results;
    }

    /// <summary>
    /// JWT 检测 — 识别 eyJxxx.yyy.zzz 格式的 Token 并尝试解码
    /// </summary>
    private List<DataEvidence> ScanJwt(HttpTransaction http, int stepIndex)
    {
        var results = new List<DataEvidence>();

        Action<DataFragment, string> checkJwt = (fragment, location) =>
        {
            if (fragment.Size == 0) return;

            var match = JwtRegex.Match(fragment.RawText);
            if (!match.Success) return;

            var jwt = match.Value;
            var parts = jwt.Split('.');

            // 尝试解码 JWT Header/Payload
            string? decodedPayload = null;
            try
            {
                var payload = parts[1];
                // 修复 Base64 URL 编码
                payload = payload.Replace('-', '+').Replace('_', '/');
                var padding = 4 - payload.Length % 4;
                if (padding != 4) payload += new string('=', padding);

                var payloadBytes = Convert.FromBase64String(payload);
                decodedPayload = Encoding.UTF8.GetString(payloadBytes);
            }
            catch
            {
                // JWT payload 解码失败，仍然检测到 JWT 格式
            }

            var evidence = DataEvidence.Heuristic(
                "heuristic_jwt",
                Truncate(jwt, 100),
                CapturedDataType.Token,
                $"step.{stepIndex}.{location}",
                0.9f
            );
            if (decodedPayload != null)
                evidence.Metadata["jwt_payload"] = Truncate(decodedPayload, 500);

            results.Add(evidence);
        };

        checkJwt(http.ResponseBody, "response.body");
        checkJwt(http.RequestBody, "request.body");
        checkJwt(http.RequestHeaders, "request.headers");
        checkJwt(http.ResponseHeaders, "response.headers");

        return results;
    }

    // ── 工具方法 ──

    /// <summary>计算 Shannon 熵</summary>
    internal static double CalculateEntropy(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0;

        var freq = new Dictionary<char, int>();
        foreach (char c in text)
        {
            freq.TryGetValue(c, out var count);
            freq[c] = count + 1;
        }

        double entropy = 0;
        int len = text.Length;
        foreach (var count in freq.Values)
        {
            double p = (double)count / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string Truncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text[..maxLen] + "...";
    }
}
