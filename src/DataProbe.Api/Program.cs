using System.Text.Json;
using DataProbe.Capture;
using DataProbe.Core;
using DataProbe.Extractor;
using DataProbe.Http;
using DataProbe.Tls;

var _startTime = DateTime.UtcNow;
var _isRunning = false;           // 真实运行状态，修复 status 硬编码 bug
var _sessionSnapshot = new SessionSnapshot();  // 当前调查的 Session 快照
SessionBuilder? _sessionBuilder = null;        // Session 构建器（延迟初始化）

// ── Configuration ──────────────────────────────────────
var configPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "DataProbe", "config.json");

var config = new DataProbeConfig();
if (File.Exists(configPath))
{
    var json = File.ReadAllText(configPath);
    var deserialized = JsonSerializer.Deserialize<DataProbeConfig>(json);
    if (deserialized != null) config = deserialized;  // ← 修复：反序列化结果已赋值
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
var ade = new DefaultAdversarialDecisionEngine(channelMgr);

// 插件管理器（统一扩展入口）
var pluginMgr = new DataProbe.Core.Plugin.PluginManager();
pluginMgr.OnChannelDiscovered += (name, ch) =>
{
    try { channelMgr.Register(ch); Console.Error.WriteLine($"[Plugin] Channel loaded: {name}"); }
    catch (Exception ex) { Console.Error.WriteLine($"[Plugin] Channel {name} registration failed: {ex.Message}"); }
};
pluginMgr.OnParserDiscovered += (name, parser) =>
{
    try { if (parser is DataProbe.Http.IProtocolParser p) protocolRegistry.AddParser(p); Console.Error.WriteLine($"[Plugin] Parser loaded: {name}"); }
    catch (Exception ex) { Console.Error.WriteLine($"[Plugin] Parser {name} registration failed: {ex.Message}"); }
};
pluginMgr.OnRuleDiscovered += (name, rule) =>
{
    try { ruleEngine.SaveRule(rule); Console.Error.WriteLine($"[Plugin] Rule loaded: {name}"); }
    catch (Exception ex) { Console.Error.WriteLine($"[Plugin] Rule {name} registration failed: {ex.Message}"); }
};

var winDivertCh = new WinDivertChannel(config, connTracker, packetFilter);
winDivertCh.SetSniKeywords(config.SniKeywords);
channelMgr.Register(winDivertCh);

var dnsSpoofCh = new DnsSpoofChannel();
dnsSpoofCh.SetSpoofDomains(config.SpoofDomains);
channelMgr.Register(dnsSpoofCh);

var tlsProxyCh = new TlsProxyChannel(config, certMgr, credQueue, ruleEngine, protocolRegistry, trafficBuffer);
channelMgr.Register(tlsProxyCh);

// 系统代理通道（零权限，自动配置浏览器流量到 TlsProxy）
try
{
    var sysProxyCh = new SystemProxyChannel
    {
        ProxyAddress = "127.0.0.1",
        ProxyPort = config.TlsProxyPort
    };
    channelMgr.Register(sysProxyCh);
    Console.Error.WriteLine($"[SystemProxy] Registered, proxy 127.0.0.1:{config.TlsProxyPort}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[SystemProxy] Register failed: {ex.Message}");
}

// TUN 虚拟网卡通道（L3 全流量，需管理员）
try
{
    var tunCh = new TunChannel();
    channelMgr.Register(tunCh);
    Console.Error.WriteLine("[TUN] Registered");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[TUN] Register failed: {ex.Message}");
}

// 进程 Hook 通道（突破证书锁定）
try
{
    var hookCh = new ProcessHookChannel();
    channelMgr.Register(hookCh);
    Console.Error.WriteLine("[ProcessHook] Registered");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ProcessHook] Register failed: {ex.Message}");
}

// 加载插件（扫描 plugins/ 目录，自动注册通道/解析器/规则包）
_ = Task.Run(async () =>
{
    try
    {
        await pluginMgr.LoadAllAsync();
        Console.Error.WriteLine($"[PluginManager] Scan complete, {pluginMgr.Count} extensions loaded");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[PluginManager] Scan error: {ex.Message}");
    }
});

// Session 构建器（新架构 — 桥接 TlsProxy 数据到 SessionSnapshot）
_sessionBuilder = new SessionBuilder(_sessionSnapshot);
tlsProxyCh.OnTransactionCaptured += tx => _sessionBuilder?.AddTransaction(tx);

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
        status = _isRunning ? "running" : "stopped",  // ← 修复：使用真实运行状态
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
    _isRunning = true;  // ← 修复：更新真实运行状态
    return Results.Ok(new { status = "started" });
}).WithName("StartCapture").WithDescription("启动所有采集通道");

app.MapPost("/stop", () =>
{
    channelMgr.StopAllAsync().GetAwaiter().GetResult();
    _isRunning = false;  // ← 修复：更新真实运行状态
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

app.MapPost("/api/capture/ingest", async (Microsoft.AspNetCore.Http.HttpRequest req) =>
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
            investigate = "POST /api/investigate/start — Start new investigation",
            session = "GET /api/session — View current session snapshot",
            evidence = "GET /api/evidence — View extracted evidence",
            docs = "GET /api/docs (Swagger UI)",
        }
    });
}).WithName("GetHelp").WithDescription("API 帮助");

// ── 新增：调查引擎 API ────────────────────────────────

app.MapPost("/api/investigate/start", async (Microsoft.AspNetCore.Http.HttpRequest req) =>
{
    try
    {
        var body = await req.ReadFromJsonAsync<Dictionary<string, object>>();
        var target = body?.GetValueOrDefault("target", "")?.ToString() ?? "";
        if (string.IsNullOrEmpty(target))
            return Results.BadRequest(new { error = "target_required" });

        // 创建新的 Session 快照
        _sessionSnapshot = new SessionSnapshot
        {
            TargetName = target,
            StartedAt = DateTime.UtcNow
        };
        _sessionBuilder = new SessionBuilder(_sessionSnapshot);

        // ⭐ ADE 阶段 I: 目标洞察
        var profile = await ade.AnalyzeTargetAsync(target);

        // ⭐ ADE 阶段 II: 生成执行计划
        var plan = ade.CreateExecutionPlan(profile);

        // 存储 TargetProfile 供后续使用
        _sessionSnapshot.TargetRating = profile.ProtectionRating;

        // SSLKEYLOGFILE（浏览器目标自动启用）
        SslKeyLogService? keylog = null;
        if (plan.UseSslKeyLog)
        {
            keylog = new SslKeyLogService();
            keylog.EnableForProcess(ExtractProcessName(target));
            Console.Error.WriteLine($"[Investigation] SSLKEYLOGFILE enabled for browser target");
        }

        // 按执行计划启动通道，跳过启动失败的通道
        var startedChannels = new List<string>();
        foreach (var chName in plan.ChannelNames)
        {
            var ch = channelMgr.Get(chName);
            if (ch == null) continue;

            // 检查管理员权限要求
            if (ch.Capability.RequiresAdmin)
            {
                try
                {
                    // 快速检查是否以管理员身份运行
                    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    if (!principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    {
                        Console.Error.WriteLine($"[ADE] Skipping {chName}: requires admin");
                        continue;
                    }
                }
                catch
                {
                    // 无法检测权限时尝试启动
                }
            }

            try
            {
                await ch.InitializeAsync();
                await ch.StartAsync();
                startedChannels.Add(chName);
                Console.Error.WriteLine($"[ADE] Started channel: {chName}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ADE] Failed to start {chName}: {ex.Message}");
            }
        }

        _isRunning = startedChannels.Count > 0;

        return Results.Ok(new
        {
            investigation_id = _sessionSnapshot.SessionId,
            target,
            profile = new
            {
                ips = profile.IPAddresses,
                cdn = profile.CDNProvider,
                tls = profile.TLSVersion,
                protection = profile.ProtectionRating.ToString(),
                has_pinning = profile.HasCertPinning
            },
            plan = new
            {
                summary = plan.Summary,
                channels = plan.ChannelNames,
                coverage = plan.ExpectedCoverage,
                limitations = plan.Limitations
            },
            status = _isRunning ? "started" : "no_channels_available",
            message = plan.ChannelNames.Length > 0
                ? $"Using {string.Join(" + ", plan.ChannelNames)}. View progress at GET /api/session"
                : "No suitable channels available for this target."
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
}).WithName("StartInvestigation").WithDescription("发起新调查。自动侦察目标 → 选择最佳通道 → 启动采集");

app.MapPost("/api/investigate/stop", () =>
{
    channelMgr.StopAllAsync().GetAwaiter().GetResult();
    _isRunning = false;
    _sessionSnapshot.CompletedAt = DateTime.UtcNow;
    _sessionSnapshot.BuildIndex();

    return Results.Ok(new
    {
        investigation_id = _sessionSnapshot.SessionId,
        status = "completed",
        steps = _sessionSnapshot.Steps.Count,
        duration_seconds = (_sessionSnapshot.CompletedAt.Value - _sessionSnapshot.StartedAt).TotalSeconds
    });
}).WithName("StopInvestigation").WithDescription("停止当前调查");

app.MapGet("/api/session", () =>
{
    return Results.Ok(new
    {
        session_id = _sessionSnapshot.SessionId,
        target = _sessionSnapshot.TargetName,
        started_at = _sessionSnapshot.StartedAt,
        completed_at = _sessionSnapshot.CompletedAt,
        steps = _sessionSnapshot.Steps.Select(s => new
        {
            step = s.StepIndex,
            action = s.UserAction,
            http_count = s.HttpTransactions.Count,
            websocket_count = s.WebSocketMessages.Count,
            schema_count = s.UrlSchemes.Count
        }),
        is_running = _isRunning
    });
}).WithName("GetSession").WithDescription("查看当前调查的 Session 快照");

app.MapGet("/api/evidence", () =>
{
    // 从当前 Session 运行规则引擎
    if (_sessionSnapshot.Steps.Count == 0)
        return Results.Ok(new { total = 0, items = Array.Empty<object>() });

    var evidences = ruleEngine.ProcessSessionAsync(_sessionSnapshot)
        .GetAwaiter().GetResult();

    return Results.Ok(new
    {
        total = evidences.Count,
        items = evidences.Select(e => new
        {
            id = e.EvidenceId,
            rule = e.RuleName,
            type = e.Type.ToString(),
            value = e.Value,
            location = e.LocationId,
            step = e.StepIndex,
            url = e.RequestUrl,
            confidence = e.Confidence,
            match_type = e.MatchType.ToString()
        })
    });
}).WithName("GetEvidence").WithDescription("在当前 Session 上运行规则并返回提取结果");

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
║          DataProbe v2.0 — 数据开采对抗平台                   ║
║          Data Extraction & Anti-Defense Platform            ║
╠══════════════════════════════════════════════════════════╣
║  API Server  : http://{config.ApiBindAddress}:{config.ApiPort}       ║
║  HTTPS Proxy : 127.0.0.1:{config.TlsProxyPort}                        ║
║  Backend     : {config.BackendUrl ?? "(none)",-44}║
║  Rules       : {ruleEngine.RuleCount,-2} loaded                          ║
║  Targets     : {config.TargetDomains.Length,-2} domains                   ║
║  Channels    : {channelMgr.ChannelCount,-2} registered                      ║
║  Swagger     : http://{config.ApiBindAddress}:{config.ApiPort}/api/docs  ║
║  Investigate : POST /api/investigate/start                                ║
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

/// <summary>从目标输入中提取进程名（用于 SSLKEYLOGFILE 注入）</summary>
static string ExtractProcessName(string target)
{
    if (target.StartsWith("http")) return "chrome";
    if (target.Contains('.')) return "chrome";
    return target.Replace(".exe", "").Trim();
}
