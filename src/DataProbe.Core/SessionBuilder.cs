namespace DataProbe.Core;

/// <summary>
/// Session 构建器 — 接收协议解析层产出的 NormalizedTransaction，
/// 将其转换为 HttpTransaction 并追加到当前 SessionSnapshot。
/// 这是连接"旧管道"（TlsProxy → CredentialQueue）和"新架构"
/// （TlsProxy → SessionSnapshot）的桥梁。
/// </summary>
public class SessionBuilder
{
    private readonly SessionSnapshot _session;
    private int _stepCounter;
    private int _httpCounter;
    private readonly object _lock = new();

    /// <summary>当前正在构建的 Session</summary>
    public SessionSnapshot Session => _session;

    /// <summary>当前已追加的 HTTP 事务数</summary>
    public int TransactionCount => _httpCounter;

    /// <summary>收到新 HTTP 事务时触发（用于实时监听）</summary>
    public event Action<HttpTransaction>? OnTransactionAdded;

    public SessionBuilder(SessionSnapshot session)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
    }

    /// <summary>
    /// 追加一个新的操作步骤（对应一次用户操作）。
    /// </summary>
    /// <param name="userAction">人类可读的操作描述</param>
    /// <returns>创建的步骤</returns>
    public OperationStep AddStep(string userAction)
    {
        var step = new OperationStep
        {
            StepIndex = Interlocked.Increment(ref _stepCounter),
            UserAction = userAction,
            Timestamp = DateTime.UtcNow
        };

        lock (_lock)
        {
            _session.Steps.Add(step);
        }

        return step;
    }

    /// <summary>
    /// 将 NormalizedTransaction 转换为 HttpTransaction 并追加到最新步骤。
    /// 如果最新步骤不存在则自动创建。
    /// </summary>
    public HttpTransaction AddTransaction(NormalizedTransaction tx)
    {
        var http = ConvertToHttpTransaction(tx);

        lock (_lock)
        {
            OperationStep? step;
            if (_session.Steps.Count == 0)
            {
                step = new OperationStep
                {
                    StepIndex = Interlocked.Increment(ref _stepCounter),
                    UserAction = "auto_capture",
                    Timestamp = tx.CapturedAt
                };
                _session.Steps.Add(step);
            }
            else
            {
                step = _session.Steps[^1]; // 追加到最新步骤
            }

            step.HttpTransactions.Add(http);
            Interlocked.Increment(ref _httpCounter);
        }

        OnTransactionAdded?.Invoke(http);
        return http;
    }

    /// <summary>
    /// 添加 WebSocket 消息到最新步骤
    /// </summary>
    public void AddWebSocketMessage(string direction, int opCode, string payload)
    {
        lock (_lock)
        {
            var step = GetOrCreateStep();
            step.WebSocketMessages.Add(new WebSocketMessage
            {
                StepIndex = step.StepIndex,
                Index = step.WebSocketMessages.Count + 1,
                Direction = direction,
                OpCode = opCode,
                Payload = payload,
                Timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// 添加 URL Schema 调用到最新步骤
    /// </summary>
    public void AddUrlSchema(string uri)
    {
        lock (_lock)
        {
            var step = GetOrCreateStep();
            step.UrlSchemes.Add(new SchemaInvocation
            {
                StepIndex = step.StepIndex,
                Uri = uri,
                Timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// 添加 Hook 捕获数据到最新步骤
    /// </summary>
    public void AddHookData(string functionName, string direction, string value, string? argJson = null)
    {
        lock (_lock)
        {
            var step = GetOrCreateStep();
            step.HookData.Add(new HookCapture
            {
                StepIndex = step.StepIndex,
                FunctionName = functionName,
                Direction = direction,
                Value = value,
                ArgJson = argJson,
                Timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// 完成 Session 构建，填充索引
    /// </summary>
    public void Complete()
    {
        _session.CompletedAt = DateTime.UtcNow;
        _session.BuildIndex();
    }

    private OperationStep GetOrCreateStep()
    {
        if (_session.Steps.Count == 0)
        {
            var step = new OperationStep
            {
                StepIndex = Interlocked.Increment(ref _stepCounter),
                UserAction = "auto_capture",
                Timestamp = DateTime.UtcNow
            };
            _session.Steps.Add(step);
            return step;
        }
        return _session.Steps[^1];
    }

    /// <summary>
    /// 核心转换方法：NormalizedTransaction → HttpTransaction
    /// 将 6 个数据位置分别填充到 HttpTransaction 的 DataFragment 中。
    /// </summary>
    private static HttpTransaction ConvertToHttpTransaction(NormalizedTransaction tx)
    {
        var http = new HttpTransaction
        {
            Method = tx.Method,
            Url = tx.Url,
            StatusCode = tx.StatusCode
        };

        // 位置 1: 请求 URL
        http.RequestUrl = DataFragment.FromUrl(tx.Url);

        // 位置 2: 请求头
        http.RequestHeaders = DataFragment.FromHeaders(tx.RequestHeaders);

        // 位置 3: 请求体
        http.RequestBody = DataFragment.FromBody(tx.RequestBody, DetectContentType(tx.RequestHeaders));

        // 位置 4: 响应头
        http.ResponseHeaders = DataFragment.FromHeaders(tx.ResponseHeaders);

        // 位置 5: 响应体
        http.ResponseBody = DataFragment.FromBody(tx.ResponseBody, DetectContentType(tx.ResponseHeaders));

        // 位置 6: 响应状态
        http.ResponseStatus = DataFragment.FromStatus(tx.StatusCode);

        return http;
    }

    /// <summary>
    /// 从响应头中检测内容类型
    /// </summary>
    private static string DetectContentType(Dictionary<string, string> headers)
    {
        if (headers.TryGetValue("content-type", out var ct))
        {
            var lower = ct.ToLower();
            if (lower.Contains("json")) return "json";
            if (lower.Contains("html")) return "html";
            if (lower.Contains("xml")) return "xml";
            if (lower.Contains("form")) return "form";
            if (lower.Contains("image")) return "binary";
        }
        return "plain";
    }
}
