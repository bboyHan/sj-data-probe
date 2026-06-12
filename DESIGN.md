# DataProbe（神机数探）技术设计白皮书

> 版本: 2.0 | 最后更新: 2026-06-12
> 定位: 数据开采对抗平台 — 极致渗透、多方攻破、简易操作

---

## 目录

1. [产品定义与定位](#1-产品定义与定位)
2. [总体架构](#2-总体架构)
3. [核心数据模型](#3-核心数据模型)
4. [五阶段调查流水线](#4-五阶段调查流水线)
5. [通道矩阵](#5-通道矩阵)
6. [TLS 解密矩阵](#6-tls-解密矩阵)
7. [协议解析栈](#7-协议解析栈)
8. [仿真模拟层](#8-仿真模拟层)
9. [逆向工程中心](#9-逆向工程中心)
10. [验证对抗引擎](#10-验证对抗引擎)
11. [反作弊感知与规避](#11-反作弊感知与规避)
12. [规则引擎与提取体系](#12-规则引擎与提取体系)
13. [技术壁垒总图](#13-技术壁垒总图)
14. [实施路线图](#14-实施路线图)
15. [风险与边界](#15-风险与边界)

---

## 1. 产品定义与定位

### 1.1 一句话定义

> **给任意数字目标（App/网站/游戏/小程序），自动突破其所有防御层，提取你关心的结构化数据，并附上不可抵赖的证据链。**

### 1.2 目标用户

| 用户类型 | 技能水平 | 使用方式 | 核心诉求 |
|----------|----------|----------|----------|
| 操作员 | 非技术 | 输入目标 → 按开始 → 读报告 | "我要这个 App 里的支付数据" |
| 分析师 | 半技术 | 选规则包 → 调通道 → 读报告 | "我要看这个游戏的 API 结构" |
| 工程师 | 高 | 自定义规则 → 深度通道配置 | "我要 Hook 这个函数的返回值" |

### 1.3 与竞品的本质区别

```
传统工具: "给你数据，自己找答案"
  Fiddler → "这是所有 HTTP 请求，你自己看"
  Wireshark → "这是所有报文，你自己分析"
  Burp → "这是所有请求/响应，你自己测"

DataProbe: "告诉我问题，我给你答案"
  "我要提取 Token" → 引擎自动完成 → "Token 在这里，共 5 处"
```

---

## 2. 总体架构

### 2.1 架构总图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              操 作 面                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │  Easy Mode       │  │  Pro Mode        │  │  报告中心                    │  │
│  │  目标输入框       │  │  通道面板         │  │  证据链展示                  │  │
│  │  规则选择         │  │  规则编辑器      │  │  导出/分享                  │  │
│  │  一键调查         │  │  流量查看器      │  │  历史存档                   │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬───────────────┘  │
└───────────┼────────────────────┼──────────────────────────┼──────────────────┘
            │                    │                          │
┌───────────▼────────────────────▼──────────────────────────▼──────────────────┐
│                          对 抗 决 策 引 擎（ADE）                              │
│                                                                               │
│  输入: 目标 + 用户问题                                                         │
│  流程: 目标洞察 → 方案生成 → 执行监控 → 遇阻调整 → 完成                       │
│  反馈: 通道异常 → 自动降级/切换/报告                                           │
└──────────────────────────────────────────────────────────────────────────────┘
            │                    │                          │
┌───────────▼────────────────────▼──────────────────────────▼──────────────────┐
│  阶 段 流 水 线                                                                │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ ① 目标   │→│ ② 突破   │→│ ③ 捕获   │→│ ④ 分析   │→│ ⑤ 报告   │       │
│  │ 洞察     │  │ 策略     │  │ 全量采集  │  │ 规则提取  │  │ 证据呈现  │       │
│  │          │  │          │  │          │  │          │  │          │       │
│  │ 侦察+逆向 │  │ 通道选择 │  │ 多通道   │  │ 全位置   │  │ 证据链   │       │
│  │ 防护评估 │  │ 仿真配置 │  │ 解密+解析 │  │ 启发式   │  │ 报告导出 │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└──────────────────────────────────────────────────────────────────────────────┘
            │                    │                          │
┌───────────▼────────────────────▼──────────────────────────▼──────────────────┐
│                          底 层 引 擎 组 件                                     │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ 通道矩阵  │  │ 解密矩阵  │  │ 协议解析  │  │ 仿真模拟  │  │ 逆向工程  │       │
│  │ 8通道    │  │ 5路解密  │  │ 8协议    │  │ 4维度   │  │ 3阶段   │       │
│  │ 自动调度  │  │ 自动选路  │  │ 可扩展   │  │ 可控    │  │ 自动化  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────────────┐  │
│  │ 验证对抗  │  │ 规则引擎  │  │ 数据模型  │  │ 反作弊感知                   │  │
│  │ 4类处理  │  │ 全位置   │  │ Session  │  │ 3级检测                     │  │
│  │ 人工介入  │  │ 热加载   │  │ 证据链   │  │ 自动降级                    │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 核心设计原则

```
原则 1: 数据模型先行
  所有数据不管来源（WinDivert/TUN/Hook/RE），统一为 SessionSnapshot
  规则引擎只认一种数据结构，不关心数据怎么来的

原则 2: 通道与逻辑分离
  通道只负责"捕获原始数据"
  逻辑层（解析/解密/提取）不依赖具体通道
  通道可插拔，逻辑层不变

原则 3: 遇阻透明降级
  每个通道声明自己的能力 + 限制
  ADE 根据目标情报 + 当前状态选择/切换通道
  用户看到的是"方案 A 不行 → 自动换方案 B"

原则 4: 一切结果可溯源
  每个提取结果都附证据链：
  "什么规则 / 哪个步骤 / 哪个位置 / 原始数据片段"
```

---

## 3. 核心数据模型

### 3.1 SessionSnapshot（操作流快照）

整个平台的核心数据结构——一个"完整数字操作"的全部数据痕迹。

```
class SessionSnapshot {
    // ── 元数据 ──
    string SessionId;              // 唯一标识
    string TargetName;             // 目标名称
    DateTime StartedAt;            // 开始时间
    DateTime CompletedAt;          // 结束时间
    CaptureMethod UsedMethod;      // 使用的通道方案
    ProtectionLevel TargetRating;  // 目标防护评级
    
    // ── 操作步骤 ──
    List<OperationStep> Steps;     // 按时间排序的操作步骤
    
    // ── 跨位置索引（用于快速规则扫描）──
    TextIndex AllText;             // 所有位置的纯文本聚合（用于全局正则）
    JsonIndex AllJson;             // 所有 JSON 的结构化索引
    UriIndex AllUris;              // 所有 URL 的索引
    TokenIndex PotentialTokens;    // 潜在 Token 的聚合
}

class OperationStep {
    int StepIndex;                 // 步序号
    string UserAction;             // 用户操作描述："点击购买按钮"
    DateTime Timestamp;
    
    // HTTP 交互
    List<HttpTransaction> HttpTransactions;
    
    // 非 HTTP 交互
    List<WebSocketMessage> WebSocketMessages;
    List<SchemaInvocation> UrlSchemes;     // weixin://, intent://
    List<RedirectChain> RedirectChains;
    
    // 进程内数据（通过 Hook 获得）
    List<HookCapture> HookData;            // 函数调用参数/返回值
    
    // 运行态数据（通过浏览器注入获得）
    RuntimeSnapshot? RuntimeData;          // DOM/Storage/Console
}
```

### 3.2 HttpTransaction（HTTP 交互）

替代当前的 NormalizedTransaction，覆盖完整的 6 个数据位置。

```
class HttpTransaction {
    int StepIndex;
    string Method;
    string Url;                     // 完整 URL，含 query
    int StatusCode;
    
    // 6 个核心数据位置
    DataFragment RequestUrl;        // URL 本身（含 path + query）
    DataFragment RequestHeaders;    // 请求头键值对
    DataFragment RequestBody;       // 请求体
    DataFragment ResponseHeaders;   // 响应头键值对
    DataFragment ResponseBody;      // 响应体
    DataFragment ResponseStatus;    // 状态码 + 原因短语
    
    // 结构化解码结果（自动）
    JsonDoc? RequestJson;           // 如果请求体是 JSON
    JsonDoc? ResponseJson;          // 如果响应体是 JSON
    FormDoc? RequestForm;           // 如果请求体是 Form
    HtmlDoc? ResponseHtml;          // 如果响应体是 HTML
    ProtoDoc? ResponseProto;        // 如果是 Protobuf
}
```

### 3.3 DataFragment（数据片段）

规则匹配的最小单元，统一所有数据位置的访问方式。

```
class DataFragment {
    string LocationId;              // 位置标识: "step.3.response.body"
    string ContentType;             // "json" / "html" / "form" / "plain" / "binary"
    long Size;                      // 数据大小
    
    // 多种访问方式
    string RawText;                 // 纯文本（适用于正则匹配）
    Dictionary<string,string> AsPairs;    // 键值对（适用于 headers）
    JsonDoc? AsJson;                // JSON 结构（适用于 JSONPath）
    HtmlDoc? AsHtml;                // HTML 结构（适用于 XPath）
    byte[]? RawBytes;               // 原始字节
}
```

### 3.4 DataEvidence（数据证据）

规则匹配产出的"证据"，附带完整溯源信息。

```
class DataEvidence {
    string EvidenceId;
    string RuleName;                // 匹配的规则名
    string Value;                   // 提取到的值
    DataType Type;                  // Token / URL / Key / Image / Params / Raw
    
    // 溯源
    string LocationId;              // 在哪找到的: "step.3.response.body.json"
    string RequestUrl;              // 所属请求
    int StepIndex;                  // 第几步
    string RawSnippet;              // 原始数据片段（上下文）
    
    // 提取方式
    MatchType MatchType;            // regex / jsonpath / semantic / heuristic
    float Confidence;               // 1.0 = 精确, 0.7 = 启发式
    
    // 关联
    string? RelatedTo;              // 关联的证据 ID
    Dictionary<string,string> Context;  // 额外上下文
}
```

### 3.5 数据流图

```
通道采集 → 原始字节 → 协议解析 → HttpTransaction
                                    ↓
                              加入 SessionSnapshot
                                    ↓
                           ADE 判断：继续采集还是分析
                                    ↓
                           RuleEngine 全位置扫描
                                    ↓
                           DataEvidence 集合
                                    ↓
                           报告生成器 → 用户可见
```

---

## 4. 五阶段调查流水线

### 4.1 阶段 I：目标洞察

```
输入：
  ├─ 域名     → "example.com"
  ├─ URL      → "https://example.com/api"
  ├─ App      → "com.example.app" 或 .apk 文件
  ├─ 游戏     → "Game.exe" 文件路径
  ├─ 二维码   → 图片文件
  └─ IP       → "192.168.1.1"

并行执行：

┌─ 网络侦察 ───────────────────────────────────────────┐
│  DNS 枚举: A/AAAA/CNAME/MX/NS → 子域名发现            │
│  CDN 检测: Cloudflare/Akamai/CloudFront/阿里云        │
│  TLS 探测: 版本/套件/证书/OCSP 装订                   │
│  端口扫描: 常见 Web 端口（80/443/8080/8443）          │
│  WAF 检测: 响应头/状态码/阻断页指纹                   │
│  crt.sh:   证书透明度日志 → 历史子域名                 │
└─────────────────────────────────────────────────────┘

┌─ 逆向分析 ───────────────────────────────────────────┐
│  APK/IPA:                                               │
│  ├─ 解包 → AndroidManifest.xml → 权限/URL/Intent      │
│  ├─ DEX 反编译 → 字符串提取 → API 端点 / Token 硬编码  │
│  ├─ 证书锁定检测 → OkHttp CertificatePinner            │
│  ├─ 反模拟器检测 → Build 检测 / 传感器检测 / proc 检测  │
│  ├─ 第三方 SDK 识别 → 支付/统计/风控 SDK               │
│  └─ 加密算法识别 → AES S-box / Base64 表 / 自定义常数  │
│  DLL/EXE:                                               │
│  ├─ PE 解析 → 导入表 / 导出表 / 资源节                  │
│  ├─ 字符串提取 → URL / IP / 加密 Key                   │
│  └─ 反作弊检测 → 扫描 ACE/TenSafe 驱动                  │
└─────────────────────────────────────────────────────┘

输出：TargetProfile

class TargetProfile {
    string TargetId;
    ProtectionLevel ProtectionRating;  // NONE/LOW/MED/HIGH/EXTREME
    
    // 防护详情
    bool HasCertPinning;
    string PinningLibrary;             // okhttp/trustmanager/nsurlsession
    bool HasAntiEmulator;
    bool HasAntiCheat;
    string AntiCheatType;              // ace/tensafe/eac/battleye
    bool HasCustomEncryption;
    bool HasCaptcha;
    
    // 网络信息
    string[] IPAddresses;
    string[] Subdomains;
    string CDNProvider;
    string TLSVersion;
    
    // 应用信息
    string[] APIEndpoints;
    string[] URLSchemes;
    string[] HardcodedTokens;
    
    // 建议
    string RecommendedChannel;
    string[] BypassSuggestions;
}
```

### 4.2 阶段 II：突破策略

```
输入: TargetProfile + 用户选定的规则

ADE 策略生成流程：

Step 1: 防护等级评估
  ├─ NONE  → 系统代理 + TLS MITM（零配置）
  ├─ LOW   → WinDivert + DNS + TLS MITM
  ├─ MED   → 模拟器 + 反模拟器补丁 + TLS MITM
  ├─ HIGH  → 进程注入 + SSL Hook + Frida
  └─ EXTREME → 仅被动分析（不解密）

Step 2: 仿真配置
  ├─ TLS 指纹: 根据目标终端选择
  │  ├─ Web 浏览器 → 伪装 Chrome 122
  │  ├─ Android App → 伪装 OkHttp 4.x
  │  ├─ iOS App → 伪装 NSURLSession
  │  └─ 游戏 → 伪装 Unity TLS
  ├─ 设备指纹: 根据目标平台选择
  │  ├─ Android → 小米 14 / Samsung S24 等
  │  ├─ iOS → iPhone 15 Pro
  │  └─ PC → 模拟 Windows 11 / macOS 特征
  └─ 行为模式: 
     ├─ 普通 → 自然间隔 + 鼠标轨迹
     └─ 快速 → 最小延迟（适用于纯 API 分析）

Step 3: 验证方案
  ├─ 无验证码 → 不需要
  ├─ 基础验证码 → OCR（Tesseract / ddddocr）
  ├─ 高级验证码 → 2Captcha API
  └─ 极端验证码 → 人工介入通道

输出: ExecutionPlan

class ExecutionPlan {
    CaptureChannel[] Channels;
    DecryptionMethod[] DecryptionMethods;
    FingerprintConfig TlsFingerprint;
    DeviceProfile DeviceFingerprint;
    BehaviorProfile BehaviorConfig;
    CaptchaStrategy CaptchaPlan;
    
    string Summary;  // 人类可读的方案描述
    int ExpectedCoverage;     // 预期可提取率: 0-100
    string[] Limitations;     // 已知限制
}
```

### 4.3 阶段 III：数据捕获

```
执行 ExecutionPlan →

┌─ 通道层 ─────────────────────────────────────────────┐
│  选定通道并行启动                                      │
│  每个通道输出原始数据包或已解密的 HttpTransaction      │
│  通道管理器实时监控健康状态                            │
└─────────────────────────────────────────────────────┘

┌─ ADE 监控层 ──────────────────────────────────────────┐
│  监听通道异常信号:                                      │
│  ├─ TLS 握手失败 → 可能证书锁定 → 切换解密方案         │
│  ├─ 连接被拒 → 被 WAF 阻断 → 换 IP/指纹               │
│  ├─ 返回验证码 → 启动验证处理                          │
│  ├─ 检测到反作弊扫描 → 降级到 Passive 模式             │
│  └─ 无数据 → 通道不工作 → 切换备用通道                 │
└─────────────────────────────────────────────────────┘

┌─ Session 构建器 ──────────────────────────────────────┐
│  从通道输出流中聚合 HttpTransaction                     │
│  按时间排序 → 生成 OperationStep                       │
│  关联同源数据 → 合并 Token 复用关系                    │
│  输出: SessionSnapshot（持续追加）                     │
└─────────────────────────────────────────────────────┘
```

### 4.4 阶段 IV：数据分析

```
输入: SessionSnapshot + 启用的规则集

┌─ 并行分析 ───────────────────────────────────────────┐
│                                                        │
│  ┌─ 预设规则扫描 ───────────────────────┐              │
│  │  每个规则遍历 SessionSnapshot 的        │              │
│  │  所有指定位置                          │              │
│  │  → 产出 DataEvidence                   │              │
│  └────────────────────────────────────────┘              │
│                                                        │
│  ┌─ 启发式发现 ───────────────────────────┐              │
│  │  ① 高熵值检测 → 疑似 Token/Key        │              │
│  │  ② JSON 结构分析 → 字段名 + 类型推断  │              │
│  │  ③ JWT 自动解码 → payload 字段提取    │              │
│  │  ④ Base64 解码 → 图片/序列化内容检测  │              │
│  │  ⑤ 高频值检测 → 跨请求复用字段        │              │
│  └────────────────────────────────────────┘              │
│                                                        │
│  ┌─ 差异分析 ─────────────────────────────┐              │
│  │  相同请求 带/不带 Token 的响应对比     │              │
│  │  → 差异部分 = 受保护的高价值数据       │              │
│  └────────────────────────────────────────┘              │
│                                                        │
└─────────────────────────────────────────────────────┘

输出: List<DataEvidence>
```

### 4.5 阶段 V：报告呈现

```
输入: List<DataEvidence> + SessionSnapshot

报告结构:

┌─────────────────────────────────────────────────────────┐
│  调查报告                                              │
│                                                        │
│  概览:                                                 │
│  ├─ 目标: xxx                                          │
│  ├─ 耗时: 45s                                          │
│  ├─ 捕获: 47 请求 / 3 WebSocket / 2 Schema             │
│  └─ 遇阻: 证书锁定 → Frida Hook 绕过 ✅                │
│                                                        │
│  数据摘要:                                             │
│  ├─ 🔑 Token (5)      ─── 来自 3 个规则               │
│  ├─ 🔗 支付链接 (3)   ─── 来自规则 "支付数据提取包"    │
│  ├─ 📄 API 端点 (12)  ─── 启发式自动发现               │
│  └─ 📊 商品数据 (6)   ─── 来自规则 "电商数据提取包"   │
│                                                        │
│  [点击任意项展开证据链] →                               │
│                                                        │
│  ┌─ 证据详情 ─────────────────────────────────────┐   │
│  │  value: weixin://pay?token=eyJ...              │   │
│  │  位置: 步骤 3 响应头 → Location                  │   │
│  │  规则: 支付链接提取包 / 微信支付                  │   │
│  │  置信度: 1.0（精确匹配）                        │   │
│  │  原始请求: POST /api/order/create               │   │
│  │  [复制值] [查看原始数据] [导出]                 │   │
│  └───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 5. 通道矩阵

### 5.1 通道总览

```
通道名称           层        管理员   拦截能力   解密能力   跨平台   支持协议        状态
══════════════════════════════════════════════════════════════════════════════════════
SystemProxy        L7        ❌       HTTP       TLS MITM   ✅      HTTP 族        🔴 待开发
WinDivertChannel   L4        ✅       TCP/443    ❌         ❌      TCP 全协议      ✅ 已有
DnsSpoofChannel    L4        ✅       DNS        ❌         ❌      DNS             ✅ 已有
TlsProxyChannel    L4-L7     ❌       ❌(需上游)  SChannel  ❌      HTTP 族        ✅ 已有
TunChannel         L3        ✅       全流量     ❌         ✅(TUN) 全协议           🔴 待开发
ArpSpoofChannel    L2        ✅       局域网     ❌         ❌      L2-L7           🔴 待开发
ProcessHookChannel L7        ⚠️      进程内      SSL Hook   ❌      全协议(进程内)  🔴 待开发
MobileVpnChannel   L3        ⚠️      全流量     ❌         ✅(移动)全协议           🔴 待开发
PassiveChannel     L2-L7     ❌       无         ❌         ✅      全被动           🔴 待开发
```

### 5.2 通道能力声明（ChannelCapability 扩展）

每个通道必须声明的能力，供 ADE 策略选择使用。

```csharp
public class ChannelCapability
{
    // ── 基础 ──
    public string Name { get; set; }
    public string Description { get; set; }
    
    // ── 操作层级 ──
    public CaptureLayer Layer { get; set; }     // L2 / L3 / L4 / L7 / Process
    
    // ── 权限需求 ──
    public bool RequiresAdmin { get; set; }
    public bool RequiresCertInstall { get; set; }
    public bool RequiresRoot { get; set; }       // 移动端
    
    // ── 能力声明 ──
    public bool CanIntercept { get; set; }       // 是否拦截流量
    public bool CanDecryptTls { get; set; }
    public bool CanModify { get; set; }          // 是否修改流量
    public bool CanInject { get; set; }          // 是否注入进程
    
    // ── 覆盖范围 ──
    public string[] SupportedProtocols { get; set; }
    public string[] SupportedPlatforms { get; set; }  // windows/android/ios
    public string[] TargetScenarios { get; set; }     // browser/app/game/miniapp
    
    // ── 限制 ──
    public string[] AntiCheatConflicts { get; set; }  // 会被哪些反作弊检测
    public string[] Limitations { get; set; }
    
    // ── 性能 ──
    public int ExpectedOverheadMs { get; set; }   // 预期延迟增量
}
```

### 5.3 通道自动选择策略

```
ADE 通道选择逻辑（决策树）：

IF 防护等级 == EXTREME:
  通道 = [PassiveChannel]          // 只能被动看，不解密
  说明 = "目标防护极强，仅能获得元数据"

ELIF 有反作弊 (ACE/TenSafe):
  IF 目标类型 == 游戏:
    通道 = [WinDivert, DnsSpoof, TlsProxy]  // 禁用注入
    说明 = "检测到反作弊，仅使用内核级通道"
  ELSE:
    通道 = [ProcessHook]           // 非游戏可以注入

ELIF 有证书锁定:
  IF 目标类型 == Android App:
    通道 = [MobileVpn, ProcessHook(Frida)]
  ELIF 目标类型 == Windows App:
    通道 = [SystemProxy, ProcessHook(Detours)]
  ELSE:
    通道 = [SystemProxy, TlsProxy]  // 浏览器无锁定问题

ELIF 目标类型 == 移动端:
  IF 有 USB 调试:
    通道 = [MobileVpn, ADBProxy]
  ELSE:
    通道 = [MobileVpn]             // 仅 VPN，不解密

ELSE:
  通道 = [SystemProxy, TlsProxy]   // 最简单，零配置
```

---

## 6. TLS 解密矩阵

### 6.1 解密方案总览

```
方案编号  方案名称             原理                   适用场景              成功率   可实现性
═════════════════════════════════════════════════════════════════════════════════════════
D1        CA 证书 MITM        自签根 CA + 动态域名证书   浏览器/标准 HTTP 库  高       现有
D2        SSLKEYLOGFILE       注入环境变量 → 读取密钥    Chrome/CEF/curl     高       1-2 周
D3        进程内 SSL Hook     Hook SSL_read/write       OpenSSL/BoringSSL   高       3-4 周
D4        .NET Profiler       ICorProfilerCallback      .NET 应用           极高     3-4 周
D5        Java Agent          Instrumentation          Java 应用           高       4-6 周
D6        内存扫描 MasterKey  读进程内存 → 扫描密钥结构  任意 TLS 库         中       研究阶段
D7        Frida Hook（移动）   Frida 脚本注入            移动端 App          高       4-6 周
```

### 6.2 解密方案选择策略

```
ADE 解密选择逻辑：

IF 目标进程是浏览器 (Chrome/Edge/Firefox):
  IF 浏览器启动参数可控:
    方案 D2 (SSLKEYLOGFILE) → ✅ 首选，零干扰
  ELSE:
    方案 D1 (CA MITM) → ✅ 足够

ELIF 目标进程是 .NET 应用:
  方案 D4 (.NET Profiler) → ✅ 最干净，完全绕过 TLS

ELIF 目标进程是 Java 应用:
  方案 D5 (Java Agent) → ✅

ELIF 目标进程是原生 C/C++:
  IF 使用 OpenSSL:
    方案 D3 (OpenSSL Hook) → ✅
  ELIF 使用 SChannel:
    方案 D1 (CA MITM) → ⚠️ 可能触发 pinning
    + 方案 D6 (内存扫描) → 备选

ELIF 目标是移动端 App:
  IF 有 root/越狱:
    方案 D7 (Frida Hook) → ✅
  ELSE:
    方案 D1 但需安装 CA → ⚠️ Android 11+ 不可系统级安装

ELIF 目标是游戏:
  IF 无反作弊:
    方案 D3 (SSL Hook) → ✅
  ELIF 有反作弊:
    方案 D2 (keylog，如果目标用 CEF) → ⚠️ 部分可行
    或方案 D6 (内存扫描) → ⚠️ 可能被阻断
    或 Passive 模式 → ✅ 保底
```

### 6.3 OpenSSL Hook 技术方案

```
这是突破证书锁定的关键方案。

原理:
  ┌─ 目标进程 ──────────────────────────┐
  │  HTTPS 请求 → SSL_write("POST ...")  │
  │                ↓                     │
  │           OpenSSL 库                 │
  │                ↓                     │
  │          TCP → 加密数据到网络         │
  └──────────────────────────────────────┘

  ┌─ 注入 DLL 后 ────────────────────────┐
  │  HTTPS 请求 → SSL_write("POST ...")  │
  │                ↓                     │
  │           Hook → 拦截明文            │
  │                ↓                     │
  │           OpenSSL 库                 │
  │                ↓                     │
  │          TCP → 加密数据到网络         │
  └──────────────────────────────────────┘

实现步骤:

1. DLL 注入目标进程
   ├─ CreateRemoteThread + LoadLibrary
   └─ 或 SetWindowsHookEx（更隐蔽）

2. 定位 OpenSSL 函数地址
   ├─ 扫描进程模块 → 找到 libssl-*.dll
   ├─ 解析导出表 → SSL_write / SSL_read / SSL_new / SSL_free
   └─ 地址随机化绕过 → 不要硬编码偏移

3. 安装 Hook（使用 Detours / MinHook）
   ├─ DetourAttach(&Real_SSL_write, Hooked_SSL_write)
   └─ DetourAttach(&Real_SSL_read, Hooked_SSL_read)

4. Hook 函数实现
   int Hooked_SSL_write(SSL* ssl, const void* buf, int num) {
       // buf 指向明文数据（HTTP 请求）
       SendToDataProbe(ssl, buf, num, DIRECTION_REQUEST);
       return Real_SSL_write(ssl, buf, num);
   }
   
   int Hooked_SSL_read(SSL* ssl, void* buf, int num) {
       int result = Real_SSL_read(ssl, buf, num);
       // buf 现在包含解密后的明文（HTTP 响应）
       SendToDataProbe(ssl, buf, result, DIRECTION_RESPONSE);
       return result;
   }

5. 数据回传（IPC）
   ├─ Named Pipe → DataProbe Engine 读取
   ├─ 或 Shared Memory → 低延迟
   └─ 数据格式: {ssl_ptr, direction, data, timestamp}

关键难点:
  ├─ OpenSSL 1.1 和 3.x 的 ABI 差异
  ├─ 多线程安全（SSL 对象可能被多线程使用）
  ├─ 32/64 位兼容
  └─ 反作弊检测（ACE 扫描 LoadLibrary 调用）
```

---

## 7. 协议解析栈

### 7.1 协议解析器接口

```csharp
/// <summary>
/// 协议解析器接口 — 每个协议实现一个。
/// 可解析的协议不限于 HTTP 族。
/// 输出统一为 NormalizedTransaction 或其子类。
/// </summary>
public interface IProtocolParser
{
    string ProtocolName { get; }
    string[] Aliases { get; }               // 别名，用于启发式检测
    
    /// <summary>判断原始字节是否匹配此协议</summary>
    bool CanParse(ReadOnlySpan<byte> data);
    
    /// <summary>解析请求方向数据</summary>
    ParseResult? ParseRequest(ReadOnlySpan<byte> data);
    
    /// <summary>解析响应方向数据</summary>
    ParseResult? ParseResponse(ReadOnlySpan<byte> data);
    
    /// <summary>返回此协议特有的元数据（如 WebSocket 的 OpCode）</summary>
    Dictionary<string,object>? GetProtocolMetadata(ReadOnlySpan<byte> data);
}
```

### 7.2 协议覆盖路线

```
Phase 1（已有 + 短期可补完）:
  ├─ HTTP/1.1       ✅ 已有，需完善 chunked/keep-alive
  ├─ HTTP/2         🔴 nghttp2 P/Invoke → 完整 HPACK + 帧解析
  ├─ WebSocket      🔴 帧解析（mask/unmask, fragmentation）
  └─ DNS            ✅ 已有（劫持需要）

Phase 2（中短期）:
  ├─ TLS            ✅ 已有（作为协议提取 SNI/指纹）
  ├─ QUIC Initial   🔴 仅检测 SNI + DCID，不解密
  └─ WebSocket      完成（与 Phase 1 合并）

Phase 3（中长期）:
  ├─ gRPC           🔴 基于 HTTP/2 + Protobuf
  ├─ Protobuf       推断或用户提供 .proto
  ├─ MQTT           🟡 IoT 协议
  ├─ RTMP/HLS       🟡 流媒体
  └─ WebRTC         🔴 SDP + SRTP/SCTP

Phase 4（持续）:
  └─ 启发式协议检测 → 未知协议的自动结构分析
```

### 7.3 HTTP/2 工程方案（优先实现）

```
实现路径: nghttp2 P/Invoke

原理:
  nghttp2 是最成熟的开源 HTTP/2 实现
  C 语言编写，性能极高
  通过 P/Invoke 在 .NET 中调用

核心 API:
  ├─ nghttp2_session_client_new    → 创建客户端会话
  ├─ nghttp2_submit_request        → 提交请求
  ├─ nghttp2_session_mem_recv      → 接收响应
  ├─ nghttp2_session_mem_send      → 发送帧
  └─ nghttp2_hd_inflate_hd        → HPACK 解压缩

集成方式:
  ┌─ DataProbe 解析层 ──────────────────────────────────┐
  │  TLS 解密后的字节流                                    │
  │       ↓                                               │
  │  ProtocolRegistry.SelectParser(data)                  │
  │       ↓                                               │
  │  Http2Parser (检测 PRI preface 或 SETTINGS 帧)        │
  │       ↓                                               │
  │  nghttp2_session_mem_recv → 解析帧                    │
  │       ↓                                               │
  │  帧类型判断:                                          │
  │  ├─ HEADERS 帧 → HPACK 解压 → URL/Headers →
  │  ├─ DATA 帧 → body 提取 →                             │
  │  ├─ SETTINGS 帧 → 配置协商 →                          │
  │  └─ GOAWAY 帧 → 连接关闭 →                           │
  │       ↓                                               │
  │  NormalizedTransaction → SessionSnapshot              │
  └──────────────────────────────────────────────────────┘
```

---

## 8. 仿真模拟层

### 8.1 TLS 指纹伪造

```
问题:
  DataProbe 的 TlsProxy 使用 SChannel（Windows 原生 TLS 库）
  SChannel 的 TLS ClientHello 有独特的 JA3 指纹
  目标服务器（特别是 Cloudflare/Akamai）能识别这不是标准浏览器

JA3 指纹 = TLS 版本 + 密码套件 + 扩展列表 + 椭圆曲线 + 椭圆曲线格式

当前 SChannel JA3 示例:
  771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
  0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0

Chrome 122 JA3 示例:
  771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
  0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513,29-23-24,0

差异点:
  ├─ Chrome 有 17513 扩展（application_settings）
  ├─ SChannel 密码套件顺序与 Chrome 不同
  └─ 扩展顺序不同

解决方案:
  替换 SChannel 为 OpenSSL 1.1.1+

  实现:
  ┌─ TlsFingerprintEngine ──────────────────────────────┐
  │                                                       │
  │  ① 加载指纹模板库（JSON）                              │
  │  {                                                     │
  │    "chrome_122": {                                     │
  │      "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:...",     │
  │      "curves": "prime256v1:secp384r1:secp521r1",       │
  │      "extensions": "0-23-65281-10-11-35-16-5-13-..."   │
  │    },                                                   │
  │    "okhttp_4": { ... },                                 │
  │    "safari_17": { ... }                                 │
  │  }                                                      │
  │                                                       │
  │  ② SSL_CTX_set_ciphersuites(ctx, chrome_ciphers)      │
  │    SSL_CTX_set1_curves_list(ctx, chrome_curves)         │
  │    → 生成的 ClientHello 与 Chrome 完全一致             │
  │                                                       │
  │  ③ 建立 TLS 连接到上游服务器                           │
  │    服务器看到的是 Chrome 指纹                          │
  │    → 不会被识别为代理工具                              │
  │                                                       │
  │  ④ 监控 JA3 黑名单更新                                 │
  │    某些服务商维护已知代理工具的 JA3 黑名单              │
  │    → 定期更新指纹模板                                   │
  └───────────────────────────────────────────────────────┘

  ⚠️ 注意: OpenSSL 替换 SChannel 后，将失去 Windows 证书存储集成
        需要手动管理 CA 证书链
```

### 8.2 设备指纹仿真

```
适用场景: 移动端 App 分析
目标: 让 App 的 SDK（友盟/TalkingData/AppsFlyer）认为这是真实设备

┌─ DeviceFingerprintFactory ────────────────────────────┐
│                                                         │
│  指纹模板（50+ 内置）:                                   │
│  ├─ 小米 14 (xiaomi14.json)                              │
│  │  { "brand": "Xiaomi", "model": "23127PN0CC",         │
│  │    "build": "xiaomi/fuxi/fuxi:14/UP1A.231005...",    │
│  │    "resolution": "1440x3200",                        │
│  │    "sensors": ["accel","gyro","mag","proximity"],    │
│  │    "ttl": 64 }                                       │
│  ├─ iPhone 15 Pro                                       │
│  └─ Samsung Galaxy S24 Ultra                            │
│                                                         │
│  生成规则:                                               │
│  ├─ Build 属性全部使用真实设备的 dump                     │
│  ├─ 传感器列表匹配真实设备的硬件配置                       │
│  ├─ TTL 匹配 OS 默认值                                    │
│  ├─ WiFi BSSID 模拟真实路由器前缀                         │
│  └─ 电池状态、充电状态、屏幕亮度随机生成                   │
│                                                         │
│  一致性校验（关键）:                                       │
│  ├─ model="SM-S928B" → brand must be "Samsung"          │
│  ├─ model="SM-S928B" → resolution=1440x3120             │
│  ├─ TTL=64 → Android (macOS=64, Windows=128)            │
│  └─ 指纹一旦生成 → 全操作流保持一致                       │
└─────────────────────────────────────────────────────────┘
```

### 8.3 行为仿真

```
适用场景: 有风控检测的目标（reCAPTCHA v3、极验行为检测）
目标: 让流量特征看起来像人在操作

┌─ BehaviorSimulationEngine ────────────────────────────┐
│                                                         │
│  ① 操作时序                                             │
│  ├─ 点击间隔: 正态分布 µ=1200ms, σ=400ms               │
│  ├─ 页面停留: lognormal(µ=8s, σ=3s)                     │
│  ├─ 输入速度: 80-160ms/字符，每 5-8 字符停顿 200-400ms │
│  └─ 夜间静默: 01:00-06:00 不操作                         │
│                                                         │
│  ② 鼠标轨迹（桌面端浏览器）                               │
│  ├─ 路径: 贝塞尔曲线（非直线）                           │
│  ├─ 速度: 起始加速 → 中间匀速 → 末端减速                │
│  ├─ Overshoot: 目标位置 ±5px → 修正                     │
│  └─ 双击: 间隔 100-400ms，位置偏差 ±3px                │
│                                                         │
│  ③ 触摸轨迹（移动端）                                   │
│  ├─ 滑动: 带弧形曲率                                    │
│  ├─ 缩放: 双指角度随机 ±15°                             │
│  └─ 长按: 接触面积 20-30mm² → 压力变化                  │
│                                                         │
│  ④ 背景流量                                             │
│  ├─ 每 5-15 分钟: 一次系统更新检查                       │
│  ├─ 每 30-60 分钟: 一次 NTP 同步                        │
│  ├─ 目标 App 外: 随机访问 2-3 个主流网站                │
│  └─ DNS 缓存: 模拟真实设备的查询模式                     │
└─────────────────────────────────────────────────────────┘
```

---

## 9. 逆向工程中心

### 9.1 自动化逆向流水线

```
输入: 目标文件（.apk / .ipa / .exe / .dll / .so）

┌─ 逆向流水线 ─────────────────────────────────────────────┐
│                                                            │
│  ┌─ 阶段 1: 解包与识别 ─────────────────────────────┐     │
│  │  文件格式检测 → APKTool / ILSpy / PE 解析          │     │
│  │  保护检测 → 是否加壳/混淆                          │     │
│  │  SDK 识别 → 支付/统计/风控 SDK 版本检测            │     │
│  └────────────────────────────────────────────────────┘     │
│                                                            │
│  ┌─ 阶段 2: 静态分析 ───────────────────────────────┐     │
│  │  ├─ 字符串提取 → URL / IP / Token / 加密 Key      │     │
│  │  ├─ 证书锁定检测 → OkHttp / TrustManager / ATS    │     │
│  │  ├─ 反模拟器检测 → Build / proc / sensor 校验      │     │
│  │  ├─ 反调试检测 → ptrace / Debug.isDebuggerConnected │    │
│  │  ├─ 加密算法识别 → AES S-box / Base64 / 自定义 XOR │     │
│  │  └─ API 端点提取 → URL 模式聚合                    │     │
│  └────────────────────────────────────────────────────┘     │
│                                                            │
│  ┌─ 阶段 3: 动态分析 ───────────────────────────────┐     │
│  │  Hook 点自动发现:                                   │     │
│  │  ├─ 扫描 SSL 库函数引用                              │     │
│  │  ├─ 扫描加密函数调用链                               │     │
│  │  └─ 自动生成 Frida / Detours 脚本                    │     │
│  └────────────────────────────────────────────────────┘     │
│                                                            │
└─────────────────────────────────────────────────────────────┘

输出: TargetProfile（已在前文定义）
```

### 9.2 自动 Hook 脚本生成

```
当逆向引擎检测到特定模式时，自动生成对应的 Hook 脚本：

检测到 OkHttp 证书锁定:
  ┌─ 自动生成 Frida 脚本 ──────────────────────────────┐
  │  Java.perform(function() {                            │
  │      var CertificatePinner = Java.use(                │
  │          "okhttp3.CertificatePinner");                │
  │      CertificatePinner.check.overload(                │
  │          'java.lang.String',                          │
  │          'java.util.List'                             │
  │      ).implementation = function(hostname, pins) {    │
  │          console.log("[DP] Pinning bypass: " + hostname);
  │          return;  // 跳过证书校验                      │
  │      };                                                │
  │  });                                                   │
  └──────────────────────────────────────────────────────┘

检测到 OpenSSL 加密:
  ┌─ 自动生成 Detours C++ ─────────────────────────────┐
  │  // hook_openssl.cpp                                 │
  │  #include <minhook.h>                                 │
  │                                                       │
  │  int (WINAPI *Real_SSL_write)(SSL*, void*, int);      │
  │                                                       │
  │  int Hooked_SSL_write(SSL* ssl, void* buf, int num) { │
  │      // buf = 明文数据                                 │
  │      SendToPipe(ssl, buf, num);                       │
  │      return Real_SSL_write(ssl, buf, num);             │
  │  }                                                      │
  │                                                       │
  │  void InstallHook() {                                  │
  │      HMODULE lib = GetModuleHandle("libssl-3.dll");    │
  │      void* func = GetProcAddress(lib, "SSL_write");    │
  │      MH_CreateHook(func, Hooked_SSL_write,             │
  │          (void**)&Real_SSL_write);                     │
  │      MH_EnableHook(func);                              │
  │  }                                                      │
  └──────────────────────────────────────────────────────┘
```

---

## 10. 验证对抗引擎

### 10.1 验证码处理流水线

```
检测到验证码 → 识别类型 → 选择解法 → 回填结果

┌─ Captcha Detection ───────────────────────────────────┐
│  触发条件:                                              │
│  ├─ 响应包含 "captcha" / "verify" / "geetest"          │
│  ├─ 状态码 419 / 429 / 423                              │
│  ├─ 响应 HTML 含 <script src="gt.js"> 或 hcaptcha      │
│  └─ 302 跳转到验证页面                                   │
└────────────────────────────────────────────────────────┘

┌─ Captcha Solver ──────────────────────────────────────┐
│  类型识别 → 解法选择                                      │
│                                                          │
│  ┌─ 简单数字字母 ─────────────────────────────────┐     │
│  │  OCR: Tesseract / ddddocr（中文优化）           │     │
│  │  成功率: 90%+                                     │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─ 极验 Geetest ─────────────────────────────────┐     │
│  │  ├─ 滑块: YOLO 识别缺口位置 → 计算滑动距离         │     │
│  │  ├─ 轨迹: 贝塞尔曲线模拟                    │     │
│  │  ├─ 数据集: 预训练的缺口检测模型                     │     │
│  │  └─ 成功率: 85%+（配合行为仿真）                    │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─ reCAPTCHA v2 ────────────────────────────────┐     │
│  │  ├─ 图像选择: 第三方服务 (2Captcha/... )       │     │
│  │  └─ 成功率: 90%+ (第三方)                     │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─ reCAPTCHA v3 ────────────────────────────────┐     │
│  │  ⚠️ 无自动化解法                                  │     │
│  │  策略: 行为仿真降低分数 + IP 轮换 + 限速          │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─ 未知/复杂验证码 ─────────────────────────────┐     │
│  │  人工介入: WebSocket 推送到操作员 → 手动输入回填   │     │
│  │  延迟: 3-10 秒                                    │     │
│  └─────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────┘
```

### 10.2 SMS / 电话验证桥

```
┌─ SMS Verification Bridge ────────────────────────────┐
│                                                        │
│  场景: 目标 App 需要短信验证码登录/确认                  │
│                                                        │
│  ① 虚拟号池:                                           │
│  ├─ 集成 Twilio / 国内虚拟运营商 API                    │
│  ├─ 自动申请临时号码                                    │
│  └─ 绑定到当前调查                                     │
│                                                        │
│  ② SMS 接收:                                           │
│  ├─ 轮询 API 检查短信                                   │
│  ├─ 正则提取验证码（6位数字 / 4位数字）                  │
│  ├─ 自动回填到登录流程                                  │
│  └─ 超时处理: 3 分钟无短信 → 换号                       │
│                                                        │
│  ③ 备用: 人工介入                                       │
│  ├─ 推送到操作员手机                                    │
│  ├─ 操作员查看短信 → 输入验证码                         │
│  └─ 延迟: 5-15 秒                                      │
└────────────────────────────────────────────────────────┘
```

---

## 11. 反作弊感知与规避

### 11.1 反作弊检测

```
┌─ AntiCheat Detector ─────────────────────────────────┐
│                                                         │
│  检测范围:                                               │
│  ┌─ 进程扫描 ──────────────────────────────────────┐   │
│  │  遍历系统进程 → 匹配已知反作弊进程名:              │   │
│  │  ├─ ace.sys / ACE-Core / ACE-Guard               │   │
│  │  ├─ TenSLX / TenProtect / TP3Helper               │   │
│  │  ├─ npggNT.sys / nProtect / GameGuard             │   │
│  │  ├─ eac.sys / EasyAntiCheat                       │   │
│  │  ├─ beservice.sys / BattlEye                      │   │
│  │  └─ mhyprot.sys / miHoYoProtect                   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ 驱动扫描 ──────────────────────────────────────┐   │
│  │  遍历系统驱动 → 匹配已知反作弊驱动:               │   │
│  │  ├─ \\.\ACE-BASE / \\.\ACEDS                      │   │
│  │  └─ \\.\mhyprot2 / \\.\TenProtect                 │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  输出反作弊等级:                                         │
│  ├─ NONE    = 无反作弊                                  │
│  ├─ USER    = 用户态反作弊（有限检测能力）                │
│  ├─ KERNEL  = 内核态反作弊（驱动级别，如 ACE）           │
│  └─ HYPER   = 硬件级（VBS / 虚拟化检测，极少见）        │
└─────────────────────────────────────────────────────────┘
```

### 11.2 反作弊规避策略

```
检测到反作弊后的通道策略调整:

┌─ 无 (NONE) ─────────────────────────────────────────────┐
│  全通道可用 ✅                                             │
│  ├─ WinDivert + DNS + TLS MITM                            │
│  ├─ 进程注入 (SSL Hook / 内存读取)                         │
│  └─ TUN 网卡                                              │
└──────────────────────────────────────────────────────────┘

┌─ 用户态 (USER) ──────────────────────────────────────────┐
│  限制: ❌ 进程注入                                        │
│  可用: ✅ 内核通道 (WinDivert/TUN)                        │
│  ├─ WinDivert 拦截 TCP/443                                │
│  ├─ DNS 劫持重定向                                        │
│  ├─ TUN 全流量（包括 UDP）                                │
│  └─ TLS MITM（如果无证书锁定）                             │
│  ⚠️ 提示: 不解密也可做包大小/时序分析                     │
└──────────────────────────────────────────────────────────┘

┌─ 内核态 (KERNEL) ────────────────────────────────────────┐
│  限制: ❌ 进程注入 ❌ 内存读取 ⚠️ 可能检测 TLS Hook       │
│  可用: ✅ 纯外部位移                                      │
│  ├─ WinDivert 内核拦截（反作弊不扫描网络层）              │
│  ├─ DNS 劫持（同上理由）                                 │
│  └─ ⚠️ 不要修改目标进程的任何内存/线程                    │
│  保底: Passive 模式                                       │
└──────────────────────────────────────────────────────────┘

┌─ 硬件级 (HYPER) ─────────────────────────────────────────┐
│  仅 Passive 模式                                          │
│  ├─ SNI 提取                                              │
│  ├─ 包大小分析                                            │
│  ├─ 请求时序分析                                          │
│  └─ 无解密能力                                            │
└──────────────────────────────────────────────────────────┘
```

---

## 12. 规则引擎与提取体系

### 12.1 规则定义（扩展后的 PlatformRule）

```json
{
  "name": "wechat_payment_link",
  "description": "提取微信支付链接",
  "enabled": true,
  "priority": 100,

  "context": {
    "requires_operation": ["order", "pay", "checkout"],
    "min_confidence": 0.7
  },

  "scan_locations": [
    "request.url",
    "request.header.location",
    "request.body",
    "response.body",
    "response.header.location",
    "websocket.message",
    "url_scheme",
    "dom.text",
    "hook.function_return"
  ],

  "matchers": [
    {
      "type": "regex",
      "location": "response.body",
      "pattern": "weixin://[^\\s\"'<>)]+",
      "output": "value"
    },
    {
      "type": "jsonpath",
      "location": "response.body.json",
      "path": "$.data.pay_url",
      "output": "value"
    },
    {
      "type": "semantic",
      "location": "any",
      "detect": "high_entropy_base64",
      "verify": "jwt_decode_contains('wxpay')",
      "output": "value"
    }
  ],

  "extractors": [
    {
      "name": "payment_url",
      "output_field": "value",
      "data_type": "url"
    }
  ]
}
```

### 12.2 预设规则包

```
预设规则包 = 针对特定场景的规则集合

┌─ 规则包目录 ──────────────────────────────────────────┐
│                                                          │
│  📦 支付数据提取包 (v2)                                  │
│  ├─ wechat_payment_link                                  │
│  ├─ alipay_payment_link                                  │
│  ├─ order_id                                             │
│  ├─ payment_amount                                       │
│  └─ transaction_id                                       │
│                                                          │
│  📦 登录凭证提取包 (v3)                                  │
│  ├─ jwt_token                                            │
│  ├─ session_cookie                                       │
│  ├── basic_auth                                          │
│  └─ oauth_token                                          │
│                                                          │
│  📦 用户信息提取包 (v1)                                  │
│  ├─ phone_number                                         │
│  ├─ email_address                                        │
│  └─ user_id                                              │
│                                                          │
│  📦 API 结构发现包 (v2)                                  │
│  ├─ rest_endpoint                                        │
│  ├─ graphql_query                                        │
│  └─ websocket_endpoint                                   │
│                                                          │
│  📦 电商数据提取包 (v1)                                  │
│  ├─ product_name                                         │
│  ├─ product_price                                        │
│  └─ inventory_count                                      │
│                                                          │
│  📦 游戏数据提取包 (v1)                                  │
│  ├─ player_info                                          │
│  ├─ equipment_list                                       │
│  └─ virtual_currency                                     │
└─────────────────────────────────────────────────────────┘
```

### 12.3 启发式提取

不需要预设规则也能自动发现高价值数据：

```
① 高熵值检测:
  ├─ 扫描所有响应体 → 计算 Shannon 熵
  ├─ 熵 > 4.5 + 长度 > 20 → 可能是 Token/Key
  ├─ 熵 > 6.0 + 固定前缀 (eyJ/sk-/pk-) → 极有可能是 JWT
  └─ 标记为 PotentialSecret

② 结构推断:
  ├─ JSON 响应 → 递归遍历字段名
  ├─ token/access_token/secret/key/password → 标记为敏感字段
  ├─ 自动提取该字段的值
  └─ 标记为 AutoDiscoveredField

③ 跨请求关联:
  ├─ 同一值出现在多个请求中
  ├─ 位置 1: POST /login 响应体 {"token":"xxx"}
  ├─ 位置 2-47: 所有请求头 Authorization: Bearer xxx
  └─ 自动关联 → "此 Token 在 47 个请求中被复用"

④ 差异分析:
  ├─ 发送相同请求: 一次带认证, 一次不带
  ├─ 响应体 diff → 差异部分 = 受保护的高价值数据
  └─ 标记为 ProtectedData
```

---

## 13. 技术壁垒总图

### 13.1 壁垒等级矩阵

```
壁垒                          Fiddler  Wireshark  VPN      DataProbe  独创性
══════════════════════════════════════════════════════════════════════════
L4 内核态 TCP 拦截              🟡(附加) ❌        ❌      🟢         🟡
L3 TUN 全流量隧道               ❌       ❌        🟢      🟢         🟡
L2 ARP 局域网拦截               ❌       ❌        ❌      🟢         🟡
HTTP/1.1 解析                  🟢      🟢        ❌      🟢         🟢
HTTP/2 + HPACK 解析             🟢      🟢        ❌      🟢         🟢
WebSocket 帧解析                🟢      🟢        ❌      🟢         🟢
QUIC/HTTP3 MITM                ❌       ❌        ❌      🟡(研究)  🔴
3000+ 协议解析                 ❌       🟢        ❌      🟡(50个)  🟢
══════════════════════════════════════════════════════════════════════
CA 证书 MITM                   🟢      ❌        ❌      🟢         🟢
SSLKEYLOGFILE 解密              ❌      🟢        ❌      🟢         🟡
进程内 SSL Hook                ❌       ❌        ❌      🔴         🔴
.NET Profiler 明文提取          ❌       ❌        ❌      🔴         🔴
Java Agent 明文提取             ❌       ❌        ❌      🔴         🔴
多 TLS 库统一 Hook 矩阵         ❌       ❌        ❌      🔴         🔴
══════════════════════════════════════════════════════════════════════
TLS JA3 指纹伪造               ❌       ❌        ❌      🔴         🔴
TCP/IP 栈指纹伪造               ❌       ❌        ❌      🔴         🔴
设备指纹仿真                   ❌       ❌        ❌      🔴         🔴
行为仿真                       ❌       ❌        ❌      🔴         🔴
══════════════════════════════════════════════════════════════════════
反作弊检测与规避                ❌       ❌        ❌      🔴         🔴
证书锁定自动检测                ❌       ❌        ❌      🔴         🔴
自动逆向 Hook 脚本生成          ❌       ❌        ❌      🔴         🔴
验证码自动处理                  ❌       ❌        ❌      🔴         🔴
SMS 验证自动填                  ❌       ❌        ❌      🔴         🔴
══════════════════════════════════════════════════════════════════════
操作流 Session 提取            ❌       ❌        ❌      🔴         🔴
全位置规则扫描                  ❌       ❌        ❌      🔴         🔴
启发式自动数据发现              ❌       ❌        ❌      🔴         🔴
不解密情报提取                  ❌       ❌        ❌      🔴         🔴
规则热加载                     🟡(脚本) ❌        ❌      🟢         🟡
预设规则包                     ❌       ❌        ❌      🔴         🔴
══════════════════════════════════════════════════════════════════════

图例:
  🟢 = 具备能力
  🟡 = 部分具备 / 附加能力
  🔴 = 完全不具备
  🔴(标红) = 独创壁垒（竞品完全无法触及）
```

### 13.2 12 项绝对独创壁垒

```
这 12 项是任何现有竞品（包括 Fiddler/Charles/mitmproxy/Burp/Wireshark/WireGuard）都无法实现的：

  1. 进程内 SSL Hook → 突破证书锁定，在加密前获取明文
  2. .NET Profiler 明文提取 → .NET 应用完全绕过 TLS 层
  3. Java Agent 明文提取 → Java 应用同理
  4. 多 TLS 库统一 Hook 矩阵 → 覆盖 Schannel/OpenSSL/BoringSSL/NSS
  5. TLS JA3 指纹伪造 → 不被目标服务器识别为代理工具
  6. 设备指纹仿真 → 通过 App 的 SDK 设备信任检测
  7. 行为仿真 → 不被风控系统标记为自动化
  8. 反作弊检测与规避 → 在 ACE/TenSafe 等下依然能工作
  9. 自动逆向 Hook 脚本生成 → 从 APK/DLL 自动生成 Frida/Detours 代码
  10. 操作流 Session 提取 → 跨请求/跨协议/跨位置聚合
  11. 全位置规则扫描 → 不只在 response_body，在所有数据位置查找
  12. 不解密情报提取 → TLS 解不了密也能从大小/时序/SNI 获取情报
```

---

## 14. 实施路线图

### 14.1 阶段划分

```
V1.0 (当前) → V1.1 (基础可用) → V1.5 (能力扩展) → V2.0 (完全体)
```

### 14.2 V1.1 — "基础可用"（6-8 周）

```
目标: 核心技术栈落地，面向技术用户可用

Phase 0 — 紧急修复（1 周）
  ├─ 修复 /status 永远返回 "running" 的 bug
  ├─ 修复 config.json 反序列化结果未赋值的 bug
  ├─ 修复 RuleEngine Source 硬编码 "oracle"
  └─ 修复 ParseDataType 残留支付枚举名

Phase 1 — HTTP/2 + Session 模型（2 周）
  ├─ nghttp2 P/Invoke 包装 → 完整 HTTP/2 帧解析
  ├─ HPACK 解压缩
  ├─ SessionSnapshot 模型实现
  ├─ HttpTransaction 扩展（6 个数据位置）
  └─ SessionBuilder（从通道输出流构建 Session）

Phase 2 — 全位置规则扫描（1 周）
  ├─ RuleEngine 升级为 Session 级
  ├─ 扫描位置扩展（6 个 HTTP 位置 + WebSocket + Schema）
  ├─ 规则上下文条件
  └─ 启发式熵值检测 V1

Phase 3 — 系统代理通道 + 简易调度（2 周）
  ├─ SystemProxyChannel（自动设置/恢复系统代理）
  ├─ ADE V1（简单的 IF-ELSE 规则选择）
  ├─ 修复 TlsProxy 的 status 逻辑
  └─ Dashboard 简易版（目标输入 + 结果展示）

V1.1 交付标准:
  ┌────────────────────────────────────────────────────┐
  │  ✅ HTTP/2 网站流量完全解析                          │
  │  ✅ 规则在 6 个位置同时扫描                          │
  │  ✅ 非技术人员可"输入 URL → 选规则包 → 开始 → 看报告"│
  │  ✅ 10 个预设规则                                    │
  │  ❌ 证书锁定目标不适用（下一阶段）                    │
  └────────────────────────────────────────────────────┘
```

### 14.3 V1.5 — "能力扩展"（10-12 周）

```
目标: 突破证书锁定，覆盖移动端和端游

Phase 4 — 进程 SSL Hook 矩阵（4 周）
  ├─ OpenSSL Hook (MinHook/Detours)
  ├─ SSL_write/SSL_read 拦截 → 明文提取
  ├─ IPC (Named Pipe) → 数据回传
  ├─ 目标进程检测（32/64 位自动适配）
  └─ 自动生成 Hook DLL

Phase 5 — 逆向工程中心 V1（3 周）
  ├─ APK 解包 + DEX 字符串提取
  ├─ 证书锁定检测（OkHttp/TrustManager）
  ├─ 反模拟器检测
  ├─ API 端点自动提取
  └─ 自动 Frida 脚本生成

Phase 6 — TUN 通道（3 周）
  ├─ WinTUN 集成
  ├─ IP 包分类 (TCP/UDP/ICMP 分流)
  ├─ UDP/443 → QUIC Initial 检测 → SNI 提取
  ├─ TCP/443 → TlsProxy 转发
  └─ TUN + 协议感知（智能管道）

Phase 7 — WebSocket + 验证码（2 周）
  ├─ WebSocket 帧解析（mask/unmask, OpCode, 分片）
  ├─ 验证码检测 + OCR (ddddocr)
  └─ 2Captcha API 集成

V1.5 交付标准:
  ┌────────────────────────────────────────────────────┐
  │  ✅ 突破 OpenSSL 证书锁定                           │
  │  ✅ 自动分析 APK → 检测防护 → 生成 Hook 脚本       │
  │  ✅ 自动证书锁定绕过（配合 Frida 注入）              │
  │  ✅ TUN 通道全流量捕获（含 UDP）                    │
  │  ✅ WebSocket 消息提取                              │
  │  ✅ 简单验证码自动处理                              │
  │  ❌ ACE 反作弊 + 锁定组合无法突破                   │
  └────────────────────────────────────────────────────┘
```

### 14.4 V2.0 — "完全体"（12-16 周）

```
目标: 全维度覆盖，非技术人员也能操作

Phase 8 — TLS 指纹伪造（4 周）
  ├─ OpenSSL 替换 SChannel 作为 TLS 客户端
  ├─ JA3 指纹模板库（20+ 模板）
  ├─ 自动选择匹配目标的指纹
  └─ HTTP 头顺序模拟

Phase 9 — 仿真工厂（4 周）
  ├─ 设备指纹模板（50+ 手机型号）
  ├─ 自洽性校验引擎
  ├─ 行为仿真引擎（时序/轨迹/背景噪音）
  ├─ 环境仿真（GPS/WiFi/传感器）
  └─ 指纹持久化（同一目标保持一致性）

Phase 10 — 反作弊感知（3 周）
  ├─ 反作弊检测（进程/驱动/TTL 特征）
  ├─ 策略自动降级
  ├─ 纯 Passive 通道（不解密）
  └─ 不解密情报提取（大小/时序/SNI）

Phase 11 — 验证对抗完全体（3 周）
  ├─ Geetest 滑块求解（YOLO + 轨迹模拟）
  ├─ SMS 验证桥
  ├─ 人工介入通道
  └─ 风控规避策略（IP 轮换/指纹切换/限速）

Phase 12 — 报告系统 + 规则市场（2 周）
  ├─ 证据链报告（可交互）
  ├─ 报告导出（PDF/JSON/CSV）
  ├─ 规则包导入/导出
  └─ 规则市场（社区共享）

V2.0 交付标准:
  ┌────────────────────────────────────────────────────┐
  │  ✅ JA3 指纹伪装 + 设备仿真 + 行为仿真              │
  │  ✅ 反作弊检测 + 自动策略降级                        │
  │  ✅ 验证码全自动处理（滑块/图片/SMS）                │
  │  ✅ 不解密情报提取（最后防线）                      │
  │  ✅ 全维度报告 + 证据链                              │
  │  ✅ 非技术人员端到端可用                             │
  │  ⚠️ QUIC Full MITM / 分布式架构 → V3.0             │
  └────────────────────────────────────────────────────┘
```

### 14.5 里程碑总图

```
完成度
  ▲
  │
  │                                       ⬟ V2.0 完全体
  │                                   ╱    ✅ 12 项独创壁垒
  │                                 ╱      全自动化
  │                            ⬟ V1.5
  │                        ╱     ✅ 突破证书锁定
  │                      ╱        ✅ APK 自动分析
  │                 ⬟ V1.1        ✅ TUN 全流量
  │             ╱    ✅ HTTP/2     ✅ 验证码处理
  │           ╱       ✅ Session 模型
  │     ⬟ V1.0        ✅ 全位置扫描
  │   ╱  ✅ 现有通道
  │ ╱     ✅ 基础 MITM
  └────────────────────────────────────────────────────► 时间
     现在      6-8 周          16-20 周        28-36 周
```

---

## 15. 风险与边界

### 15.1 技术风险

```
风险 1: QUIC/HTTP3 MITM 实现难度远超预期
  ├─ 影响: Phase 6 (TUN) 完成但 QUIC 不能 MITM
  ├─ 缓解: V1/V2 阶段用 Alt-Svc 降级 HTTP/2
  └─ 长期: 持续研究，不在早期投入过多

风险 2: 反作弊系统检测到 DataProbe 的 Hook
  ├─ 影响: Phase 4 (进程 Hook) 在 ACE 保护游戏中无效
  ├─ 缓解: 反作弊检测 → 自动禁用注入 → 降级被动模式
  └─ 这不是 DataProbe 的缺陷，是整个行业的共同边界

风险 3: 目标应用使用 mTLS（双向 TLS）
  ├─ 影响: 即使 MITM 也无法冒充客户端证书
  ├─ 缓解: 需用户提供客户端证书 (P12/PEM)
  └─ 高级功能，V2.0 再考虑

风险 4: Windows 安全软件报毒
  ├─ 影响: WinDivert 驱动 + DLL 注入触发杀软告警
  ├─ 缓解: 代码签名证书 / 提交白名单
  └─ 持续维护
```

### 15.2 法律与道德边界

```
DataProbe 是一个技术能力极强的工具。
能力越强，责任越大。必须内置以下设计：

1. 透明开关（必须实现）
  ├─ 首次运行 → 明确告知工具能力 + 法律边界
  ├─ 用户必须点击同意才能使用
  └─ 同意记录保存在本地日志

2. 目标白名单（必须实现）
  ├─ 默认不捕获任何流量
  ├─ 用户必须显式输入目标
  └─ 空列表 → 引擎不工作

3. 审计日志（必须实现）
  ├─ 记录每次调查的目标、时间、提取类型
  ├─ 日志不可删除（只可导出）
  └─ 用于合规追溯

4. 数据本地化（默认）
  ├─ BackendUrl 默认为空 → 数据只留在本地
  ├─ 开启远程发送需要显式确认
  └─ 本地存储加密（DPAPI）

5. 能力边界声明
  ├─ 在 UI 中明确展示工具的"能"和"不能"
  └─ 避免用户产生不切实际的期望
```

### 15.3 已知做不到的场景

```
以下场景 DataProbe 无法处理（整个行业都做不到）：

🔴 硬件级安全芯片保护的数据
  ├─ iPhone SEP (Secure Enclave) 中的生物特征
  ├─ Android TEE 中的密钥材料
  └─ 可信执行环境中的处理数据

🔴 端到端加密通信
  ├─ WhatsApp / Signal / iMessage 消息内容
  ├─ 除非在发送端 Hook → 移动端需要 root/越狱
  └─ 服务端无法解密

🔴 实时人脸/指纹验证
  ├─ App 调用系统生物识别 API
  ├─ 验证结果在 TEE 中处理
  └─ 无法拦截/伪造

🔴 物理隔离网络
  ├─ 目标不与外部通信
  ├─ 无网络流量可捕获
  └─ 需要物理接触
```

---

## 附录：设计变更对照

```
对比 V1.0（当前代码）与 V2.0（设计目标）

维度                V1.0 当前                      V2.0 目标
══════════════════════════════════════════════════════════════════════════
数据模型            NormalizedTransaction（单请求）  SessionSnapshot（操作流）
规则引擎            单请求 + response_body 仅限       全 Session + 全位置扫描
通道数              3（WinDivert/DNS/TLS）           8+（含TUN/系统代理/ARP/移动端）
解密方案            仅 CA MITM                        5 种（MITM/Keylog/Hook/Profiler/Agent）
TLS 指纹            暴露 SChannel 指纹                可伪造任意浏览器/App 指纹
设备仿真            无                                50+ 模板 + 自洽性校验
行为仿真            无                                时序/轨迹/背景噪音
逆向工程            无                                APK/DLL 自动分析 + Hook 生成
反作弊感知           无                                3 级检测 + 自动降级
验证码              无                                OCR/AI/人工三级

架构复杂度          约 6 个项目 / 5,000 行           约 15 个模块 / 30,000+ 行
团队需求            1 人维护                          3-5 人开发
```
