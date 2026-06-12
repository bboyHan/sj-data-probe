using System.Text.RegularExpressions;

namespace DataProbe.Extractor;

/// <summary>
/// SMS 验证桥 — 通过虚拟号码池接收短信验证码，
/// 自动提取验证码并回填到自动化流程。
///
/// 支持:
///   - Twilio / 国内虚拟运营商 API
///   - SIM 卡池（串口/USB 猫）
///   - 手动输入回填
/// </summary>
public class SmsVerificationBridge
{
    private static readonly Regex CodePattern = new(
        @"(\d{4,8})", RegexOptions.Compiled);

    /// <summary>虚拟号码池配置</summary>
    public SmsProviderConfig Provider { get; set; } = new();

    /// <summary>获取一个临时号码</summary>
    public async Task<string?> GetNumberAsync(CancellationToken ct = default)
    {
        Console.Error.WriteLine($"[SMS] Requesting number from {Provider.Type}...");

        await Task.Delay(500, ct); // 模拟 API 调用
        // Phase 11 完整：调用 Twilio / 虚拟运营商 API 获取号码

        return Provider.Type switch
        {
            "twilio" => $"+1{RandomDigits(10)}",
            "china" => $"1{RandomDigits(10)}",
            _ => null
        };
    }

    /// <summary>等待并提取验证码</summary>
    public async Task<string?> WaitForCodeAsync(string phoneNumber, int timeoutSec = 120, CancellationToken ct = default)
    {
        Console.Error.WriteLine($"[SMS] Waiting for code to {phoneNumber}...");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

        try
        {
            while (!cts.Token.IsCancellationRequested)
            {
                // Phase 11 完整: 轮询 SMS API
                var message = await PollSmsAsync(phoneNumber, cts.Token);
                if (message != null)
                {
                    var code = ExtractCode(message);
                    if (code != null)
                    {
                        Console.Error.WriteLine($"[SMS] Code received: {code}");
                        return code;
                    }
                }
                await Task.Delay(2000, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        Console.Error.WriteLine("[SMS] Timeout waiting for code");
        return null;
    }

    /// <summary>轮询短信</summary>
    private Task<string?> PollSmsAsync(string phoneNumber, CancellationToken ct)
    {
        // Phase 11 完整: 调用 SMS API
        return Task.FromResult<string?>(null);
    }

    public static string? ExtractCode(string message)
    {
        var match = CodePattern.Match(message);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string RandomDigits(int len)
    {
        var rng = new Random();
        return new string(Enumerable.Range(0, len).Select(_ => (char)('0' + rng.Next(10))).ToArray());
    }
}

public class SmsProviderConfig
{
    /// <summary>提供商类型: twilio / china / sim_pool</summary>
    public string Type { get; set; } = "twilio";

    public string? AccountSid { get; set; }
    public string? AuthToken { get; set; }
    public string? ApiKey { get; set; }
}
