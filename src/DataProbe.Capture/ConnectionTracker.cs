using System.Collections.Concurrent;
using System.Net;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// TCP connection state machine
/// </summary>
public enum TcpState
{
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
}

/// <summary>
/// Represents a single tracked TCP connection.
/// </summary>
public class TcpConnection
{
    public ConnectionKey Key { get; }
    public TcpState State { get; set; } = TcpState.Closed;
    public string? Sni { get; set; }
    public IPEndPoint? OriginalDestination { get; set; }
    public DateTime CreatedAt { get; }
    public DateTime LastActivity { get; set; }
    public byte[] ClientBuffer { get; set; } = Array.Empty<byte>();
    public byte[] ServerBuffer { get; set; } = Array.Empty<byte>();

    public TcpConnection(ConnectionKey key)
    {
        Key = key;
        CreatedAt = DateTime.UtcNow;
        LastActivity = DateTime.UtcNow;
    }

    public bool IsExpired(int timeoutSec) =>
        (DateTime.UtcNow - LastActivity).TotalSeconds > timeoutSec;

    public void AppendClientData(ReadOnlySpan<byte> data)
    {
        var newBuffer = new byte[ClientBuffer.Length + data.Length];
        ClientBuffer.CopyTo(newBuffer, 0);
        data.CopyTo(newBuffer.AsSpan(ClientBuffer.Length));
        ClientBuffer = newBuffer;
        LastActivity = DateTime.UtcNow;
    }

    public void AppendServerData(ReadOnlySpan<byte> data)
    {
        var newBuffer = new byte[ServerBuffer.Length + data.Length];
        ServerBuffer.CopyTo(newBuffer, 0);
        data.CopyTo(newBuffer.AsSpan(ServerBuffer.Length));
        ServerBuffer = newBuffer;
        LastActivity = DateTime.UtcNow;
    }
}

/// <summary>
/// Uniquely identifies a TCP connection by its 4-tuple.
/// Uses Jenkins hash for fast lookup.
/// </summary>
public readonly struct ConnectionKey : IEquatable<ConnectionKey>
{
    public readonly uint SrcAddr;
    public readonly ushort SrcPort;
    public readonly uint DstAddr;
    public readonly ushort DstPort;

    public ConnectionKey(uint srcAddr, ushort srcPort, uint dstAddr, ushort dstPort)
    {
        SrcAddr = srcAddr;
        SrcPort = srcPort;
        DstAddr = dstAddr;
        DstPort = dstPort;
    }

    public override int GetHashCode()
    {
        unchecked
        {
            var h = (int)(SrcAddr ^ DstAddr);
            h = (h * 31) + SrcPort;
            h = (h * 31) + DstPort;
            // Jenkins avalanche
            h = (int)((h ^ (h >> 16)) * 0x85EBCA6B);
            h = (int)((h ^ (h >> 13)) * 0xC2B2AE35);
            return h ^ (h >> 16);
        }
    }

    public bool Equals(ConnectionKey other) =>
        SrcAddr == other.SrcAddr && SrcPort == other.SrcPort &&
        DstAddr == other.DstAddr && DstPort == other.DstPort;

    public override bool Equals(object? obj) =>
        obj is ConnectionKey other && Equals(other);

    public static bool operator ==(ConnectionKey left, ConnectionKey right) => left.Equals(right);
    public static bool operator !=(ConnectionKey left, ConnectionKey right) => !left.Equals(right);
}

/// <summary>
/// Thread-safe TCP connection tracker with LRU eviction.
/// </summary>
public class ConnectionTracker : IDisposable
{
    private readonly ConcurrentDictionary<ConnectionKey, TcpConnection> _connections;
    private readonly int _maxCapacity;
    private readonly int _timeoutSec;
    private readonly Timer _cleanupTimer;
    private long _evictedCount;

    public ConnectionTracker(DataProbeConfig config)
    {
        _maxCapacity = config.MaxConnections;
        _timeoutSec = config.ConnectionTimeoutSec;
        _connections = new ConcurrentDictionary<ConnectionKey, TcpConnection>(
            Environment.ProcessorCount, (int)Math.Min(config.MaxConnections, int.MaxValue));

        _cleanupTimer = new Timer(
            _ => CleanupExpired(),
            null,
            TimeSpan.FromSeconds(config.ConnectionCleanupIntervalSec),
            TimeSpan.FromSeconds(config.ConnectionCleanupIntervalSec));
    }

    public int ActiveCount => _connections.Count;
    public long EvictedCount => Interlocked.Read(ref _evictedCount);

    public TcpConnection GetOrCreate(ConnectionKey key)
    {
        // Fast path: existing connection
        if (_connections.TryGetValue(key, out var conn))
            return conn;

        // Slow path: create new, may evict if over capacity
        if (_connections.Count >= _maxCapacity)
            EvictOne();

        conn = new TcpConnection(key);
        _connections[key] = conn;
        return conn;
    }

    public bool TryGet(ConnectionKey key, out TcpConnection? conn) =>
        _connections.TryGetValue(key, out conn);

    public bool Remove(ConnectionKey key) =>
        _connections.TryRemove(key, out _);

    public IEnumerable<TcpConnection> GetActiveConnections() =>
        _connections.Values;

    private void EvictOne()
    {
        KeyValuePair<ConnectionKey, TcpConnection> oldest = default;
        foreach (var kvp in _connections)
        {
            if (oldest.Value == null || kvp.Value.LastActivity < oldest.Value.LastActivity)
                oldest = kvp;
        }

        if (oldest.Value != null && _connections.TryRemove(oldest.Key, out _))
            Interlocked.Increment(ref _evictedCount);
    }

    private void CleanupExpired()
    {
        var expired = new List<ConnectionKey>();
        foreach (var kvp in _connections)
        {
            if (kvp.Value.IsExpired(_timeoutSec))
                expired.Add(kvp.Key);
        }

        foreach (var key in expired)
        {
            if (_connections.TryRemove(key, out _))
                Interlocked.Increment(ref _evictedCount);
        }
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
        _connections.Clear();
    }
}
