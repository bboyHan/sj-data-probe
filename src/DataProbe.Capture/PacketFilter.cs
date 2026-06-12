namespace DataProbe.Capture;

/// <summary>
/// 基于 SNI 的域名过滤器 — 使用后缀匹配快速判断目标域名。
/// 用户可动态设置目标域名列表，不包含任何业务语义。
/// </summary>
public class PacketFilter
{
    private string[] _targetDomains;

    public PacketFilter(string[] targetDomains)
    {
        _targetDomains = targetDomains ?? throw new ArgumentNullException(nameof(targetDomains));
    }

    /// <summary>
    /// 动态更新目标域名列表（运行时热切换）。
    /// </summary>
    public void SetTargetDomains(string[] domains)
    {
        _targetDomains = domains ?? Array.Empty<string>();
    }

    /// <summary>
    /// 判断 SNI 是否匹配目标域名列表。
    /// 列表为空时返回 false（不处理任何域名）。
    /// </summary>
    public bool IsTargetDomain(ReadOnlySpan<char> sni)
    {
        if (sni.IsEmpty) return false;
        if (_targetDomains.Length == 0) return false;

        foreach (var domain in _targetDomains)
        {
            // Exact match
            if (sni.SequenceEqual(domain.AsSpan()))
                return true;

            // Suffix match: .domain.com matches subdomain.domain.com
            if (sni.Length > domain.Length &&
                sni[sni.Length - domain.Length - 1] == '.' &&
                sni.Slice(sni.Length - domain.Length).SequenceEqual(domain.AsSpan()))
                return true;
        }

        return false;
    }
}
