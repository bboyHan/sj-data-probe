using System.Threading.Channels;
using DataProbe.Core;

namespace DataProbe.Capture;

/// <summary>
/// Core packet capture service.
/// Filters outbound HTTPS traffic, extracts SNI, and forwards
/// matching payment domain traffic to the TLS proxy.
/// </summary>
public class CaptureService : IDisposable
{
    private readonly DataProbeConfig _config;
    private readonly PacketFilter _filter;
    private readonly ConnectionTracker _tracker;
    private readonly ICaptureDriver _driver;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private long _packetsCaptured;
    private long _packetsFiltered;
    private readonly Channel<CapturedPacket> _redirectQueue;

    public CaptureService(DataProbeConfig config, ConnectionTracker tracker,
                          PacketFilter filter, ICaptureDriver driver)
    {
        _config = config;
        _tracker = tracker;
        _filter = filter;
        _driver = driver;

        _redirectQueue = Channel.CreateBounded<CapturedPacket>(
            new BoundedChannelOptions(config.PacketQueueSize)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });
    }

    public long PacketsCaptured => Interlocked.Read(ref _packetsCaptured);
    public long PacketsFiltered => Interlocked.Read(ref _packetsFiltered);
    public bool IsRunning => _cts != null && !_cts.IsCancellationRequested;
    public ChannelReader<CapturedPacket> RedirectQueue => _redirectQueue.Reader;

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        _driver.OnPacketCaptured += OnPacketCaptured;

        _captureTask = Task.Run(() =>
        {
            _driver.Open(_config.WinDivertQueueLen);
            // Main capture loop runs in driver's event callback
        });
    }

    private void OnPacketCaptured(CapturedPacket packet)
    {
        Interlocked.Increment(ref _packetsCaptured);

        var sni = packet.ExtractSni();
        if (sni == null) return;

        if (!_filter.IsTargetDomain(sni)) return;

        Interlocked.Increment(ref _packetsFiltered);

        var conn = _tracker.GetOrCreate(packet.GetConnectionKey());
        conn.Sni = sni;
        conn.State = TcpState.Established;

        // Queue for TLS proxy redirection
        _redirectQueue.Writer.TryWrite(packet);
    }

    public void Stop()
    {
        _cts?.Cancel();
        _driver.OnPacketCaptured -= OnPacketCaptured;
        _driver.Close();
    }

    public void Dispose()
    {
        Stop();
        _tracker.Dispose();
        _driver.Dispose();
    }
}
