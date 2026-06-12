using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using DataProbe.Capture;
using DataProbe.Core;

namespace DataProbe.Tls;

/// <summary>
/// TLS proxy that performs MITM using SChannel (Windows native TLS).
///
/// Each intercepted connection is proxied through SslStream:
///   Client → SslStream (server mode, fake cert) → Proxy → SslStream (client mode) → Remote Server
///                                                         ↓
///                                                     Extract payment credentials
///                                                         ↓
///                                                     HTTP POST to Python backend
/// </summary>
public class TlsProxy : IAsyncDisposable
{
    private readonly DataProbeConfig _config;
    private readonly CertificateManager _certMgr;
    private readonly CredentialQueue _credentialQueue;
    private readonly DataProbe.Extractor.RuleEngine? _ruleEngine;
    private readonly DataProbe.Http.ProtocolRegistry? _protocolRegistry;
    private readonly DataProbe.Core.TrafficBuffer? _trafficBuffer;
    private readonly TcpListener _listener;
    private TcpListener? _dnsListener;
    private Task? _dnsListenTask;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;
    private long _totalConnections;
    private long _activeConnections;
    private long _failedConnections;

    /// <summary>捕获到新事务时触发（用于 SessionBuilder 桥接）</summary>
    public event Action<DataProbe.Core.NormalizedTransaction>? OnTransactionCaptured;

    public TlsProxy(DataProbeConfig config, CertificateManager certMgr,
                    CredentialQueue credentialQueue,
                    DataProbe.Extractor.RuleEngine? ruleEngine = null,
                    DataProbe.Http.ProtocolRegistry? protocolRegistry = null,
            DataProbe.Core.TrafficBuffer? trafficBuffer = null)
    {
        _config = config;
        _certMgr = certMgr;
        _credentialQueue = credentialQueue;
        _ruleEngine = ruleEngine;
            _protocolRegistry = protocolRegistry;
            _trafficBuffer = trafficBuffer;
        _listener = new TcpListener(IPAddress.Any, config.TlsProxyPort);
    }

    public bool IsRunning => _cts != null && !_cts.IsCancellationRequested;
    public long TotalConnections => Interlocked.Read(ref _totalConnections);
    public long ActiveConnections => Interlocked.Read(ref _activeConnections);
    public long FailedConnections => Interlocked.Read(ref _failedConnections);

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();

        // Port 18802: Browser CONNECT proxy
        _listener.Start();
        _listenTask = Task.Run(() => AcceptLoop("Proxy", _listener, _cts.Token));

        // Port 443: DNS-spoofed app traffic (微信小程序/端游)
        try
        {
            _dnsListener = new TcpListener(IPAddress.Any, 443);
            _dnsListener.Start();
            _dnsListenTask = Task.Run(() => AcceptLoop("DNS", _dnsListener, _cts.Token));
            Console.Error.WriteLine("[TlsProxy] Port 443 listener started (DNS redirect)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TlsProxy] Port 443 unavailable: {ex.Message}");
            Console.Error.WriteLine("[TlsProxy] Run as Administrator to listen on port 443");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener.Stop(); } catch { }
        try { _dnsListener?.Stop(); } catch { }
    }

    private async Task AcceptLoop(string name, TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var clientSocket = await listener.AcceptSocketAsync(ct);
                Interlocked.Increment(ref _activeConnections);
                Interlocked.Increment(ref _totalConnections);

                _ = HandleConnectionAsync(clientSocket, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[TlsProxy] Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleConnectionAsync(Socket clientSocket, CancellationToken ct)
    {
        NetworkStream? clientStream = null;
        NetworkStream? remoteStream = null;
        SslStream? clientSsl = null;
        SslStream? remoteSsl = null;

        try
        {
            clientStream = new NetworkStream(clientSocket, ownsSocket: false);

            // 1. Read the first bytes (could be TLS ClientHello or HTTP CONNECT)
            var firstBytes = new byte[4096];
            var bytesRead = await clientStream.ReadAsync(firstBytes, ct);
            if (bytesRead == 0) return;

            string? sni = null;

            // Check if this is an HTTP CONNECT proxy request
            if (bytesRead > 8 && firstBytes[0] == (byte)'C' &&
                firstBytes[1] == (byte)'O' && firstBytes[2] == (byte)'N' &&
                firstBytes[3] == (byte)'N' && firstBytes[4] == (byte)'E' &&
                firstBytes[5] == (byte)'C' && firstBytes[6] == (byte)'T')
            {
                var connectLine = System.Text.Encoding.ASCII.GetString(firstBytes, 0, bytesRead);
                var parts = connectLine.Split(' ');
                if (parts.Length >= 2)
                {
                    var hostPort = parts[1].Split(':');
                    sni = hostPort[0];
                    // Send 200 Connection Established
                    var response = System.Text.Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await clientStream.WriteAsync(response, ct);
                    await clientStream.FlushAsync(ct);
                    bytesRead = 0;  // CONNECT text already consumed; TLS data comes next
                }
            }
            else
            {
                // Direct TLS connection - extract SNI from ClientHello
                sni = TlsHelper.ExtractSni(firstBytes.AsSpan(0, bytesRead));
            }

            if (string.IsNullOrEmpty(sni))
            {
                clientSocket.Close();
                return;
            }

            // ⭐ 判断是否为目标域名 — 使用配置中的 TargetDomains 白名单
            var isTargetDomain = false;
            if (!string.IsNullOrEmpty(sni))
            {
                foreach (var domain in _config.TargetDomains)
                {
                    // 精确匹配
                    if (sni.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    { isTargetDomain = true; break; }
                    // 子域名匹配
                    if (sni.Length > domain.Length &&
                        sni[sni.Length - domain.Length - 1] == '.' &&
                        sni.AsSpan(sni.Length - domain.Length).Equals(domain.AsSpan(), StringComparison.OrdinalIgnoreCase))
                    { isTargetDomain = true; break; }
                }
            }


            if (!isTargetDomain)
            {
                Console.WriteLine($"[TlsProxy] ⟳ Transparent: {sni}");
                await TransparentForward(clientSocket, clientStream, firstBytes, bytesRead, sni, ct);
                return;
            }

            Console.WriteLine($"[TlsProxy] 🔒 MITM: {sni}");

            // 2. Get the fake certificate for this domain
            var fakeCert = _certMgr.GetOrCreateCert(sni);

            // 3. Connect to remote server
            var remoteSocket = await DataProbe.Core.DnsResolver.ConnectAsync(sni, 443, ct);
            remoteStream = new NetworkStream(remoteSocket, ownsSocket: false);

            // 4. TLS handshake with client (server mode) - using SChannel via SslStream
            clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: true);
            await clientSsl.AuthenticateAsServerAsync(
                fakeCert,
                clientCertificateRequired: false,
                enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                checkCertificateRevocation: false);

            // 5. TLS handshake with remote (client mode)
            remoteSsl = new SslStream(remoteStream, leaveInnerStreamOpen: true);
            await remoteSsl.AuthenticateAsClientAsync(sni);

            // 6. Relay traffic in both directions
            await RelayTrafficAsync(clientSsl, remoteSsl, sni, ct);
        }
        catch (AuthenticationException ex)
        {
            Console.Error.WriteLine($"[TlsProxy] Auth error: {ex.Message}");
            Interlocked.Increment(ref _failedConnections);
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"[TlsProxy] IO error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TlsProxy] Error: {ex.Message}");
            Interlocked.Increment(ref _failedConnections);
        }
        finally
        {
            clientSsl?.Dispose();
            remoteSsl?.Dispose();
            clientStream?.Dispose();
            remoteStream?.Dispose();
            clientSocket.Close();
            Interlocked.Decrement(ref _activeConnections);
        }
    }

    // Shared state between request and response tasks
    private class RequestCapture
    {
        public string Method = "";
        public string Path = "";
        public string Body = "";
        public bool Captured = false;
    }

    private async Task RelayTrafficAsync(
        SslStream client, SslStream remote, string sni, CancellationToken ct)
    {
        var buffer = new byte[_config.TlsRelayBufferSize];
        var requestCapture = new RequestCapture();

        // Client → Remote (requests) - also capture the first request for analysis
        var clientTask = Task.Run(async () =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var n = await client.ReadAsync(buffer, ct);
                    if (n == 0) break;

                    var requestData = buffer[..n];
                    // [DEBUG] 取消注释可查看实时请求流量
                    // Console.Error.WriteLine($"[DBG] {System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(n, 200))}");

                    // Detect HTTP request line (supports keep-alive multi-request)
                    var line = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(n, 4000));
                    if ((line.StartsWith("GET ") || line.StartsWith("POST ") ||
                         line.StartsWith("PUT ") || line.StartsWith("DELETE ")) &&
                        line.Contains(" HTTP/"))
                    {
                        var parts = line.Split(' ');
                        if (parts.Length >= 2)
                        {
                            requestCapture.Method = parts[0];
                            var pathQuery = parts[1];
                            var qIdx = pathQuery.IndexOf('?');
                            requestCapture.Path = qIdx >= 0 ? pathQuery[..qIdx] : pathQuery;
                            requestCapture.Body = line.Contains("\r\n\r\n")
                                ? line[(line.IndexOf("\r\n\r\n") + 4)..]
                                : "";
                            requestCapture.Captured = true;
                        }
                    }

                    await remote.WriteAsync(requestData, ct);
                    await remote.FlushAsync(ct);
                }
            }
            catch { }
        }, ct);

        // Remote → Client (responses) - extract credentials using RuleEngine
        var remoteTask = Task.Run(async () =>
        {
            try
            {
                var responseBuffer = new List<byte>();

                while (!ct.IsCancellationRequested)
                {
                    var n = await remote.ReadAsync(buffer, ct);
                    if (n == 0) break;

                    // Buffer the response for credential extraction
                    if (n > 0)
                    {
                        responseBuffer.AddRange(buffer[..n]);

                        // Try to extract credentials using the RuleEngine
                        var responseStr = System.Text.Encoding.UTF8.GetString(buffer, 0, n);

                        var rawResp = System.Text.Encoding.UTF8.GetString(responseBuffer.ToArray());
                        rawResp = DataProbe.Core.GzipHelper.DecompressBody(rawResp);

                        // Record ALL decrypted traffic (Fiddler-style) regardless of rules
                        if (requestCapture.Captured)
                        {
                            _trafficBuffer?.Record(sni, requestCapture.Method, requestCapture.Path,
                                requestCapture.Body, ParseHttpStatus(rawResp),
                                new Dictionary<string, string>(), rawResp);
                        }

                        if (_ruleEngine != null && requestCapture.Captured)
                        {
                            var tx = new NormalizedTransaction
                            {
                                Domain = sni,
                                Method = requestCapture.Method,
                                Path = requestCapture.Path,
                                StatusCode = ParseHttpStatus(rawResp),
                                RequestBody = requestCapture.Body,
                                ResponseBody = rawResp,
                                ResponseBodyBase64 = Convert.ToBase64String(responseBuffer.ToArray()),
                            };

                            var credentials = _ruleEngine.Process(tx);
                            foreach (var cred in credentials)
                            {
                                await _credentialQueue.EnqueueAsync(cred);
                                Console.Error.WriteLine($"[DataProbe] Captured: {cred.Platform}/{cred.Value[..Math.Min(50, cred.Value.Length)]}");
                            }

                            // 通知 SessionBuilder（新架构）
                            OnTransactionCaptured?.Invoke(tx);
                        }
                    }

                    var responseData = new byte[n];
                    Array.Copy(buffer, responseData, n);
                    await client.WriteAsync(responseData, ct);
                    await client.FlushAsync(ct);
                }
            }
            catch { }
        }, ct);

        await Task.WhenAny(clientTask, remoteTask);
    }

    private static Dictionary<string, string> ParseHttpHeaders(string response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // Parse HTTP headers from response (skip status line, stop at empty line)
        var headerSection = response.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.None)[0];
        var headerLines = headerSection.Split('\n');
        for (int i = 1; i < headerLines.Length; i++) // skip HTTP status line
        {
            var hl = headerLines[i].Trim('\r', ' ');
            if (string.IsNullOrEmpty(hl)) break;
            var idx = hl.IndexOf(':');
            if (idx > 0)
                headers[hl[..idx].Trim().ToLower()] = hl[(idx + 1)..].Trim();
        }
        return headers;
    }

    private static int ParseHttpStatus(string response)
    {
        if (!response.StartsWith("HTTP/")) return 200;
        var line = response.Split('\r', '\n')[0];
        var parts = line.Split(' ');
        return parts.Length >= 2 && int.TryParse(parts[1], out var c) ? c : 200;
    }

    public async ValueTask DisposeAsync()
    {
        Stop();
        await Task.CompletedTask;
    }

    private async Task TransparentForward(Socket clientSocket, NetworkStream clientStream,
        byte[] firstBytes, int bytesRead, string sni, CancellationToken ct)
    {
        Console.WriteLine($"[TlsProxy] Forward: {sni}");
        Socket? remoteSocket = null;
        NetworkStream? remoteStream = null;
        try
        {
            remoteSocket = await DataProbe.Core.DnsResolver.ConnectAsync(sni, 443, ct);
            remoteStream = new NetworkStream(remoteSocket, ownsSocket: false);

            if (bytesRead > 0)
                await remoteStream.WriteAsync(firstBytes, 0, bytesRead, ct);

            var buffer = new byte[65536];
            var clientTask = Task.Run(async () =>
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var n = await clientStream.ReadAsync(buffer, ct);
                        if (n == 0) break;
                        await remoteStream.WriteAsync(buffer, 0, n, ct);
                        await remoteStream.FlushAsync(ct);
                    }
                }
                catch { }
            }, ct);

            var remoteTask = Task.Run(async () =>
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var n = await remoteStream.ReadAsync(buffer, ct);
                        if (n == 0) break;
                        await clientStream.WriteAsync(buffer, 0, n, ct);
                        await clientStream.FlushAsync(ct);
                    }
                }
                catch { }
            }, ct);

            await Task.WhenAny(clientTask, remoteTask);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[TlsProxy] Forward error {sni}: {ex.Message}");
        }
        finally
        {
            remoteStream?.Dispose();
            remoteSocket?.Close();
            clientSocket.Close();
            // 注意：不在这里减 _activeConnections
            // HandleConnectionAsync 的 finally 块统一处理
        }
    }

}