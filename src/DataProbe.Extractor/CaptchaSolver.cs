using System.Text.RegularExpressions;
using DataProbe.Core;

namespace DataProbe.Extractor;

/// <summary>
/// 验证码检测与求解器 — 在流量中检测验证码挑战，自动求解或转发人工。
///
/// 检测能力：
///   ① 极验 Geetest — 检测 gt.js / geetest_ 特征
///   ② reCAPTCHA v2/v3 — 检测 recaptcha/api.js 特征
///   ③ hCaptcha — 检测 hcaptcha.com 特征
///   ④ 自定义验证码 — 响应体包含 captcha/verify 关键词
///
/// 求解策略：
///   ① OCR (ddddocr/Tesseract) — 简单数字字母
///   ② 第三方 API (2Captcha) — 标准验证码
///   ③ 人工介入 — WebSocket 推送到操作员
/// </summary>
public class CaptchaSolver
{
    // ── 验证码特征检测 ──

    private static readonly Regex GeetestPattern = new(
        @"(gt\.js|geetest_|initGeetest|captcha\.gt)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RecaptchaPattern = new(
        @"(recaptcha/api\.js|g-recaptcha|_grecaptcha)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex HcaptchaPattern = new(
        @"(hcaptcha\.com|hcaptcha\.js|h-captcha)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex GenericCaptchaPattern = new(
        @"(captcha|verify|验证码|校验|slide|滑块)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>验证码类型</summary>
    public enum CaptchaType
    {
        None,
        Geetest,        // 极验
        RecaptchaV2,    // reCAPTCHA v2
        RecaptchaV3,    // reCAPTCHA v3
        Hcaptcha,       // hCaptcha
        SimpleOcr,      // 简单数字字母验证码
        Custom,         // 自定义验证码
        Unknown
    }

    /// <summary>
    /// 检测 HTTP 响应中是否包含验证码
    /// </summary>
    public static CaptchaType DetectCaptcha(string responseBody, string responseHeaders)
    {
        if (GeetestPattern.IsMatch(responseBody)) return CaptchaType.Geetest;
        if (RecaptchaPattern.IsMatch(responseBody)) return CaptchaType.RecaptchaV2;
        if (HcaptchaPattern.IsMatch(responseBody)) return CaptchaType.Hcaptcha;
        if (GenericCaptchaPattern.IsMatch(responseBody)) return CaptchaType.Custom;
        return CaptchaType.None;
    }

    /// <summary>
    /// 检测状态码是否暗示验证码
    /// </summary>
    public static bool IsCaptchaStatusCode(int statusCode)
    {
        return statusCode == 419 || statusCode == 429 || statusCode == 423;
    }

    /// <summary>
    /// 验证码检测结果
    /// </summary>
    public class CaptchaDetection
    {
        public CaptchaType Type { get; set; } = CaptchaType.None;
        public int StepIndex { get; set; }
        public string RequestUrl { get; set; } = "";
        public string? Solution { get; set; }
        public bool RequiresManualIntervention => Type is CaptchaType.RecaptchaV3 or CaptchaType.Geetest;
    }

    /// <summary>
    /// 对 SessionSnapshot 执行验证码扫描
    /// </summary>
    public static List<CaptchaDetection> ScanSession(SessionSnapshot session)
    {
        var detections = new List<CaptchaDetection>();

        foreach (var step in session.Steps)
        {
            foreach (var http in step.HttpTransactions)
            {
                // 检查状态码
                if (IsCaptchaStatusCode(http.StatusCode))
                {
                    detections.Add(new CaptchaDetection
                    {
                        Type = CaptchaType.Custom,
                        StepIndex = step.StepIndex,
                        RequestUrl = http.Url
                    });
                    continue;
                }

                // 检查响应体
                var ct = DetectCaptcha(http.ResponseBody.RawText,
                    http.ResponseHeaders.RawText);
                if (ct != CaptchaType.None)
                {
                    detections.Add(new CaptchaDetection
                    {
                        Type = ct,
                        StepIndex = step.StepIndex,
                        RequestUrl = http.Url
                    });
                }
            }
        }

        return detections;
    }
}

/// <summary>
/// 验证码求解器配置
/// </summary>
public class CaptchaSolverConfig
{
    /// <summary>求解策略</summary>
    public CaptchaStrategyType Strategy { get; set; } = CaptchaStrategyType.AutoOcr;

    /// <summary>2Captcha API Key（仅 ThirdParty 策略需要）</summary>
    public string? ApiKey { get; set; }

    /// <summary>人工介入超时（秒）</summary>
    public int ManualTimeoutSec { get; set; } = 30;

    /// <summary>自动重试次数</summary>
    public int MaxRetries { get; set; } = 3;
}
