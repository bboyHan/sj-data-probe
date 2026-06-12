using System.Text.Json;
using System.Text.RegularExpressions;
using DataProbe.Core;

namespace DataProbe.Extractor;

// ═══════════════════════════════════════════════════════════
// 验 证 码 检 测
// ═══════════════════════════════════════════════════════════

/// <summary>验证码类型</summary>
public enum CaptchaType
{
    None, Geetest, RecaptchaV2, RecaptchaV3, Hcaptcha, SimpleOcr, Custom, Unknown
}

/// <summary>求解策略</summary>
public enum CaptchaStrategyType
{
    None, AutoOcr, AiSolve, ThirdParty, Manual, Bypass
}

/// <summary>求解器接口 — 本地/远程/人工统一抽象</summary>
public interface ICaptchaSolver
{
    string Name { get; }
    CaptchaType[] HandledTypes { get; }
    Task<CaptchaSolution?> SolveAsync(CaptchaChallenge challenge, CancellationToken ct = default);
}

/// <summary>验证码挑战描述</summary>
public class CaptchaChallenge
{
    public CaptchaType Type { get; set; }
    public int StepIndex { get; set; }
    public string RequestUrl { get; set; } = "";

    /// <summary>挑战图片的 Base64 或 URL（从响应体中提取）</summary>
    public string? ImageBase64 { get; set; }

    /// <summary>挑战参数（极验的 gt/challenge、reCAPTCHA 的 sitekey）</summary>
    public Dictionary<string, string> Params { get; set; } = new();

    /// <summary>完整的响应体（用于复杂验证码分析）</summary>
    public string? RawResponse { get; set; }
}

/// <summary>求解结果</summary>
public class CaptchaSolution
{
    public bool Success { get; set; }
    public string? Answer { get; set; }
    public string? SolverName { get; set; }
    public int SolveTimeMs { get; set; }
    public string? ErrorMessage { get; set; }
}

// ═══════════════════════════════════════════════════════════
// 验 证 码 检 测（已有逻辑保留 + 增强）
// ═══════════════════════════════════════════════════════════

public class CaptchaDetector
{
    private static readonly Regex GeetestPattern = new(
        @"(gt\.js|geetest_|initGeetest|captcha\.gt|\.gt\b)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RecaptchaPattern = new(
        @"(recaptcha/api\.js|g-recaptcha|_grecaptcha|recaptcha\.net)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex HcaptchaPattern = new(
        @"(hcaptcha\.com|hcaptcha\.js|h-captcha)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex GenericCaptchaPattern = new(
        @"(captcha|verify|验证码|校验|slide|滑块)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static CaptchaType Detect(string responseBody, string responseHeaders)
    {
        if (GeetestPattern.IsMatch(responseBody)) return CaptchaType.Geetest;
        if (RecaptchaPattern.IsMatch(responseBody)) return CaptchaType.RecaptchaV2;
        if (HcaptchaPattern.IsMatch(responseBody)) return CaptchaType.Hcaptcha;
        if (GenericCaptchaPattern.IsMatch(responseBody)) return CaptchaType.Custom;
        return CaptchaType.None;
    }

    public static bool IsCaptchaStatus(int statusCode) =>
        statusCode is 419 or 429 or 423;

    /// <summary>从响应体中提取验证码挑战参数</summary>
    public static CaptchaChallenge? ExtractChallenge(string responseBody, int stepIndex, string requestUrl)
    {
        var type = Detect(responseBody, "");
        if (type == CaptchaType.None) return null;

        var challenge = new CaptchaChallenge
        {
            Type = type,
            StepIndex = stepIndex,
            RequestUrl = requestUrl,
            RawResponse = responseBody
        };

        // 提取验证码图片（<img> 或 Base64）
        var imgMatch = Regex.Match(responseBody,
            @"<img[^>]+src=[""']([^""']+captcha[^""']*)[""']",
            RegexOptions.IgnoreCase);
        if (imgMatch.Success)
            challenge.ImageBase64 = imgMatch.Groups[1].Value;

        // 提取极验参数
        if (type == CaptchaType.Geetest)
        {
            var gt = Regex.Match(responseBody, @"""gt""\s*:\s*""([^""]+)""");
            var ch = Regex.Match(responseBody, @"""challenge""\s*:\s*""([^""]+)""");
            if (gt.Success) challenge.Params["gt"] = gt.Groups[1].Value;
            if (ch.Success) challenge.Params["challenge"] = ch.Groups[1].Value;
        }

        return challenge;
    }
}

// ═══════════════════════════════════════════════════════════
// 本 地 求 解 器 — ddddocr (Python)
// ═══════════════════════════════════════════════════════════

public class DdddocrSolver : ICaptchaSolver
{
    public string Name => "ddddocr_local";

    public CaptchaType[] HandledTypes =>
        new[] { CaptchaType.SimpleOcr, CaptchaType.Custom };

    /// <summary>ddddocr Python 脚本路径（默认自动查找）</summary>
    public string ScriptPath { get; set; } = "ddddocr_solver.py";

    /// <summary>Python 解释器路径</summary>
    public string PythonPath { get; set; } = "python";

    public async Task<CaptchaSolution?> SolveAsync(CaptchaChallenge challenge, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(challenge.ImageBase64))
            return new CaptchaSolution { Success = false, ErrorMessage = "No image data" };

        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // 将 Base64 图片写入临时文件
            var tempImg = Path.Combine(Path.GetTempPath(), $"dp_captcha_{Guid.NewGuid():N}.png");
            try
            {
                var imgBytes = Convert.FromBase64String(challenge.ImageBase64);
                await File.WriteAllBytesAsync(tempImg, imgBytes, ct);

                // 调用 ddddocr CLI
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = PythonPath,
                    Arguments = $"{ScriptPath} {tempImg}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null)
                    throw new InvalidOperationException("Failed to start Python process");

                var output = await process.StandardOutput.ReadToEndAsync(ct);
                var error = await process.StandardError.ReadToEndAsync(ct);
                await process.WaitForExitAsync(ct);

                sw.Stop();

                if (process.ExitCode != 0)
                    return new CaptchaSolution { Success = false, ErrorMessage = $"ddddocr error: {error}" };

                return new CaptchaSolution
                {
                    Success = true,
                    Answer = output.Trim(),
                    SolverName = Name,
                    SolveTimeMs = (int)sw.ElapsedMilliseconds
                };
            }
            finally
            {
                if (File.Exists(tempImg)) File.Delete(tempImg);
            }
        }
        catch (Exception ex)
        {
            return new CaptchaSolution { Success = false, ErrorMessage = ex.Message };
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 远 程 求 解 器 — 2Captcha API
// ═══════════════════════════════════════════════════════════

public class TwoCaptchaSolver : ICaptchaSolver
{
    public string Name => "2captcha_remote";

    public CaptchaType[] HandledTypes =>
        new[] { CaptchaType.RecaptchaV2, CaptchaType.Hcaptcha, CaptchaType.SimpleOcr, CaptchaType.Geetest };

    private readonly HttpClient _http;
    private readonly string _apiKey;
    private const string BaseUrl = "https://2captcha.com";

    public TwoCaptchaSolver(string apiKey)
    {
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
    }

    public async Task<CaptchaSolution?> SolveAsync(CaptchaChallenge challenge, CancellationToken ct = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // Step 1: 发送验证码到 2Captcha
            var inResult = await SendInAsync(challenge, ct);
            if (!inResult.Success)
                return new CaptchaSolution { Success = false, ErrorMessage = inResult.ErrorMessage };

            // Step 2: 轮询获取结果
            var answer = await PollResultAsync(inResult.RequestId!, ct);
            sw.Stop();

            if (answer == null)
                return new CaptchaSolution { Success = false, ErrorMessage = "Timeout waiting for solution" };

            return new CaptchaSolution
            {
                Success = true,
                Answer = answer,
                SolverName = Name,
                SolveTimeMs = (int)sw.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new CaptchaSolution { Success = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<(bool Success, string? RequestId, string? ErrorMessage)> SendInAsync(
        CaptchaChallenge challenge, CancellationToken ct)
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["key"] = _apiKey,
            ["method"] = challenge.Type switch
            {
                CaptchaType.RecaptchaV2 => "userrecaptcha",
                CaptchaType.Hcaptcha => "hcaptcha",
                CaptchaType.Geetest => "geetest",
                _ => "base64"
            },
            ["json"] = "1",
            ["pageurl"] = challenge.RequestUrl,
            ["body"] = challenge.ImageBase64 ?? ""
        });

        var response = await _http.PostAsync($"{BaseUrl}/in.php", content, ct);
        var json = await response.Content.ReadAsStringAsync(ct);

        try
        {
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.GetProperty("status").GetInt32() == 1)
            {
                var requestId = root.GetProperty("request").GetString();
                return (true, requestId, null);
            }
            return (false, null, root.TryGetProperty("error", out var err) ? err.GetString() : "Unknown error");
        }
        catch { return (false, null, "Failed to parse 2Captcha response"); }
    }

    private async Task<string?> PollResultAsync(string requestId, CancellationToken ct)
    {
        for (int i = 0; i < 30; i++)
        {
            await Task.Delay(2000, ct);

            var response = await _http.GetAsync(
                $"{BaseUrl}/res.php?key={_apiKey}&action=get&id={requestId}&json=1", ct);
            var json = await response.Content.ReadAsStringAsync(ct);

            try
            {
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.GetProperty("status").GetInt32() == 1)
                    return root.GetProperty("request").GetString();
            }
            catch { }
        }

        return null;
    }

    public void Dispose() => _http.Dispose();
}

// ═══════════════════════════════════════════════════════════
// 人 工 求 解 器 — WebSocket 推送到操作员
// ═══════════════════════════════════════════════════════════

public class ManualCaptchaSolver : ICaptchaSolver
{
    public string Name => "manual_human";

    public CaptchaType[] HandledTypes =>
        new[] { CaptchaType.Unknown, CaptchaType.RecaptchaV3, CaptchaType.Custom };

    /// <summary>人工处理超时（秒）</summary>
    public int TimeoutSec { get; set; } = 60;

    /// <summary>收到人工回答时触发的事件</summary>
    public event Action<string>? OnManualAnswer;

    /// <summary>由操作员调用：提交验证码结果</summary>
    public void SubmitAnswer(string answer)
    {
        OnManualAnswer?.Invoke(answer);
    }

    public async Task<CaptchaSolution?> SolveAsync(CaptchaChallenge challenge, CancellationToken ct = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var tcs = new TaskCompletionSource<string?>();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(TimeoutSec));

        void OnAnswer(string answer) => tcs.TrySetResult(answer);
        OnManualAnswer += OnAnswer;

        try
        {
            Console.Error.WriteLine($"[Captcha] 📩 Manual intervention required: {challenge.Type}");
            Console.Error.WriteLine($"[Captcha]    URL: {challenge.RequestUrl}");

            var answer = await tcs.Task.WaitAsync(cts.Token);
            sw.Stop();

            return new CaptchaSolution
            {
                Success = answer != null,
                Answer = answer,
                SolverName = Name,
                SolveTimeMs = (int)sw.ElapsedMilliseconds
            };
        }
        catch (OperationCanceledException)
        {
            return new CaptchaSolution { Success = false, ErrorMessage = "Manual timeout" };
        }
        finally
        {
            OnManualAnswer -= OnAnswer;
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 统 一 求 解 编 排 器
// ═══════════════════════════════════════════════════════════

public class CaptchaSolverOrchestrator
{
    private readonly List<ICaptchaSolver> _solvers;

    public CaptchaSolverOrchestrator(params ICaptchaSolver[] solvers)
    {
        _solvers = solvers.ToList();
    }

    /// <summary>注册求解器</summary>
    public void Register(ICaptchaSolver solver) => _solvers.Add(solver);

    /// <summary>自动选择求解器处理验证码</summary>
    public async Task<CaptchaSolution?> SolveAsync(CaptchaChallenge challenge, CancellationToken ct = default)
    {
        // 按优先级尝试匹配的求解器
        var applicable = _solvers
            .Where(s => s.HandledTypes.Contains(challenge.Type))
            .ToList();

        foreach (var solver in applicable)
        {
            var result = await solver.SolveAsync(challenge, ct);
            if (result?.Success == true)
            {
                Console.Error.WriteLine($"[Captcha] Solved by {solver.Name}: {result.Answer}");
                return result;
            }
        }

        return new CaptchaSolution { Success = false, ErrorMessage = "No solver could handle this captcha" };
    }
}
