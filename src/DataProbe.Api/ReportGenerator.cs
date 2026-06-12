using System.Text;
using System.Text.Json;
using DataProbe.Core;

namespace DataProbe.Api;

/// <summary>
/// 报告生成器 — 将调查结果导出为 JSON / CSV / 可读摘要。
/// </summary>
public static class ReportGenerator
{
    /// <summary>导出为 JSON</summary>
    public static string ToJson(SessionSnapshot session, List<DataEvidence> evidences)
    {
        return JsonSerializer.Serialize(new
        {
            session.TargetName,
            session.StartedAt,
            session.CompletedAt,
            protection = session.TargetRating.ToString(),
            steps = session.Steps.Select(s => new
            {
                step = s.StepIndex,
                action = s.UserAction,
                httpCount = s.HttpTransactions.Count,
                websocketCount = s.WebSocketMessages.Count,
            }),
            evidence = evidences.Select(e => new
            {
                rule = e.RuleName,
                type = e.Type.ToString(),
                value = e.Value.Length > 500 ? e.Value[..500] : e.Value,
                location = e.LocationId,
                confidence = e.Confidence,
                url = e.RequestUrl
            }),
            summary = new
            {
                totalEvidences = evidences.Count,
                totalSteps = session.Steps.Count,
                tokens = evidences.Count(e => e.Type == CapturedDataType.Token),
                payments = evidences.Count(e => e.Type == CapturedDataType.Payment),
                urls = evidences.Count(e => e.Type == CapturedDataType.Url)
            }
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>导出为 CSV</summary>
    public static string ToCsv(List<DataEvidence> evidences)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Rule,Type,Value,Location,Confidence,URL,Timestamp");
        foreach (var e in evidences)
        {
            var value = e.Value.Contains(',') ? $"\"{e.Value}\"" : e.Value;
            sb.AppendLine($"{e.RuleName},{e.Type},{value},{e.LocationId},{e.Confidence},{e.RequestUrl},{e.CapturedAt:O}");
        }
        return sb.ToString();
    }

    /// <summary>导出为人类可读摘要</summary>
    public static string ToSummary(SessionSnapshot session, List<DataEvidence> evidences)
    {
        var sb = new StringBuilder();
        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine($"  DataProbe 调查报告");
        sb.AppendLine($"  目标: {session.TargetName}");
        sb.AppendLine($"  时间: {session.StartedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  防护等级: {session.TargetRating}");
        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine();

        // 按类型分组
        var groups = evidences.GroupBy(e => e.Type);
        foreach (var g in groups.OrderByDescending(g => g.Count()))
        {
            sb.AppendLine($"  {g.Key} ({g.Count()})");
            foreach (var e in g.Take(10))
            {
                var val = e.Value.Length > 80 ? e.Value[..80] + "..." : e.Value;
                sb.AppendLine($"    ├─ {val}");
                sb.AppendLine($"    │  位置: {e.LocationId} | 置信度: {e.Confidence:P0}");
            }
            if (g.Count() > 10)
                sb.AppendLine($"    └─ ... and {g.Count() - 10} more");
            sb.AppendLine();
        }

        sb.AppendLine($"--- {evidences.Count} items in total ---");
        return sb.ToString();
    }
}
