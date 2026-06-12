namespace DataProbe.Core;

/// <summary>
/// 循环流量缓冲 — 保存最近 N 条已解密的 HTTP 流量记录。
/// 用于 Dashboard 展示，Fiddler 风格。
/// </summary>
public class TrafficBuffer
{
    private readonly List<TrafficRecord> _records = new();
    private readonly int _capacity;
    private readonly object _lock = new();

    public TrafficBuffer(int capacity = 500)
    {
        _capacity = capacity;
    }

    public void Record(string sni, string method, string path, string requestBody,
        int statusCode, Dictionary<string, string> headers, string responseBody)
    {
        var record = new TrafficRecord
        {
            Timestamp = DateTime.UtcNow,
            Sni = sni,
            Method = method,
            Path = path,
            RequestBody = requestBody,
            StatusCode = statusCode,
            Headers = headers,
            ResponseBody = responseBody,
        };

        lock (_lock)
        {
            _records.Add(record);
            if (_records.Count > _capacity)
                _records.RemoveRange(0, _records.Count - _capacity);
        }
    }

    public List<TrafficRecord> GetAll()
    {
        lock (_lock) return new List<TrafficRecord>(_records);
    }
}

public class TrafficRecord
{
    public DateTime Timestamp { get; set; }
    public string Sni { get; set; } = "";
    public string Method { get; set; } = "";
    public string Path { get; set; } = "";
    public string RequestBody { get; set; } = "";
    public int StatusCode { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
    public string ResponseBody { get; set; } = "";
}
