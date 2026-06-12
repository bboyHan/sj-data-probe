namespace DataProbe.Http;

/// <summary>
/// 协议解析器注册表 — 管理所有 IProtocolParser。
/// 对输入数据依次尝试已注册的解析器，第一个 CanParse 返回 true 的胜出。
/// </summary>
public class ProtocolRegistry
{
    private readonly List<IProtocolParser> _parsers = new();

    /// <summary>已注册的协议数量</summary>
    public int Count => _parsers.Count;

    /// <summary>所有协议名称</summary>
    public string[] Names => _parsers.Select(p => p.ProtocolName).ToArray();

    /// <summary>注册一个协议解析器</summary>
    public void AddParser(IProtocolParser parser)
    {
        _parsers.Add(parser);
    }

    /// <summary>根据数据选择最匹配的协议解析器</summary>
    public IProtocolParser? SelectParser(ReadOnlySpan<byte> data)
    {
        foreach (var parser in _parsers)
            if (parser.CanParse(data))
                return parser;
        return null;
    }

    /// <summary>尝试解析请求</summary>
    public ParseResult? TryParseRequest(ReadOnlySpan<byte> data)
    {
        var parser = SelectParser(data);
        return parser?.ParseRequest(data);
    }

    /// <summary>尝试解析响应</summary>
    public ParseResult? TryParseResponse(ReadOnlySpan<byte> data)
    {
        var parser = SelectParser(data);
        return parser?.ParseResponse(data);
    }
}
