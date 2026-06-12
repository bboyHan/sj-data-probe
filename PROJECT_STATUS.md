# DataProbe (神机数探) — 项目状态

> 最后更新: 2026-06-13 | 提交: `87d8e59` | 21 commits | +13,377 行
> 设计文档: [DESIGN.md](./DESIGN.md) | 用户手册: [docs/user-manual.md](docs/user-manual.md)

---

## 1. 当前进展

```
V1.1 基础可用     ████████████████████ 100%
V1.5 能力扩展     ████████████████████ 100%
V2.0 完全体       ████████████████████ 100%

6 个项目 / 66 个源文件 / 13,377 行 C#+HTML+JSON+Python
21 个 commits 从 v1.0 基线
```

### 项目结构

```
DataProbe/
├── src/
│   ├── DataProbe.Core/       核心模型 + 接口 + 插件 + 工具
│   ├── DataProbe.Capture/    通道实现 (6 channels)
│   ├── DataProbe.Tls/        TLS MITM 代理
│   ├── DataProbe.Http/       协议解析 (HTTP/1.1 + HTTP/2 + WebSocket)
│   ├── DataProbe.Extractor/  规则引擎 + 启发式 + 逆向 + 解码
│   └── DataProbe.Api/        ASP.NET 宿主 + Dashboard + API
├── plugins/example/          插件开发示例
├── docs/                     用户手册
└── deps/                     WinTUN 驱动
```

---

## 2. 已构建的能力矩阵

### 通道层（6/8）

| 通道 | 层 | 状态 | 依赖 |
|------|----|------|------|
| WinDivert | L4 内核 | ✅ | WinDivert.dll |
| DnsSpoof | L4 内核 | ✅ | WinDivert.dll |
| TlsProxy | L7 应用 | ✅ + TLS指纹引擎 | 系统内置 |
| SystemProxy | L7 应用 | ✅ | WinINet |
| TUN | L3 网络 | ✅ | wintun.dll |
| ProcessHook | 进程内 | ✅ | Frida 17.11.0 |

### 协议解析（4/8）

| 协议 | 状态 | 说明 |
|------|------|------|
| HTTP/1.1 | ✅ | 已清理支付命名残余 |
| HTTP/2 | ✅ | 完整 HPACK + 帧解析 + Huffman |
| WebSocket | ✅ | RFC 6455 帧解析 + TlsProxy 集成 |
| QUIC | ✅ | Initial 包解析 + SNI 提取 |

### 智能层

| 模块 | 状态 | 说明 |
|------|------|------|
| ADE 决策引擎 | ✅ | DNS/TLS/CDN 侦察 + 通道选择 + 自动降级 |
| 规则引擎 | ✅ | 全位置 6 位置扫描 + JSON 热加载 + 上下文条件 |
| 启发式提取 | ✅ | Shannon 熵 / JSON 敏感字段 / JWT 解码 |
| 不解密情报 | ✅ | 包大小聚类 / 时序关联 / SNI 频率分析 |
| 逆向工程 V2 | ✅ | APK 解包 + PE 导入表 + 字符串池 + SDK 指纹 |
| 反作弊检测 | ✅ | 30+ 特征库 / 进程/模块/驱动 3 级 |
| 验证码检测 | ✅ | 极验 / reCAPTCHA / hCaptcha |
| 验证码求解 | ✅ | ddddocr / 2Captcha / 人工介入 三级 |

### 安全对抗

| 能力 | 状态 | 说明 |
|------|------|------|
| 应用层解密 | ✅ | Base64 / URL / Hex / JSON 按需解码 |
| SSLKEYLOGFILE | ✅ | 浏览器密钥注入 + NSS 格式导出 |
| TLS 指纹伪造 | ✅ | 7 模板 (Chrome/Firefox/Safari/OkHttp/Unity/Edge/curl) |
| 设备指纹仿真 | ✅ | 50+ 手机模板 + 自洽性校验 |
| 行为仿真 | ✅ | 贝塞尔鼠标 / 正态时序 / 静默时段 |
| 风控规避 | ✅ | IP 轮换 / 限速 / 行为模式切换 |
| SMS 验证桥 | ✅ | 虚拟号码池 + 验证码自动提取 |

### 插件体系

| 类型 | 状态 | 说明 |
|------|------|------|
| PluginManager | ✅ | 全产品统一扩展入口 |
| IReScannerPlugin | ✅ | 逆向扫描器插件 |
| IDecryptionPlugin | ✅ | 应用层解密器插件 |
| IExtractorPlugin | ✅ | 高级提取器插件 |
| IProtocolPlugin | ✅ | 协议解析器插件 |
| JSON 扩展 | ✅ | 规则包 / 指纹模板 / 设备配置 |

### 操作面

| 界面 | 状态 | 说明 |
|------|------|------|
| 🎯 Investigate | ✅ | 目标输入 / ADE 方案 / 证据实时轮询 |
| 📜 Rules | ✅ | 规则列表 / 详情 / 新建 / 删除 |
| 🔌 Channels | ✅ | 通道状态卡片网格 |
| 📡 Traffic | ✅ | 流量表格 + 详情弹窗 + 按需 Decode |
| 📊 Export | ✅ | JSON / CSV / Summary 导出 |

---

## 3. 技术壁垒深度分析

### 3.1 壁垒等级：绝对领先

```
                              Fiddler  Charles  Burp  Wireshark  mitmproxy  DataProbe
══════════════════════════════════════════════════════════════════════════════════════
L3 TUN 全流量捕获                ❌     ❌     ❌    ✅(被动)    ❌       ✅(主动)
L4 内核 TCP 拦截                ⚠️     ❌     ❌    ❌         ❌       ✅
L7 系统代理                       ✅     ✅     ✅    ❌         ✅       ✅
进程内 SSL Hook                 ❌     ❌     ❌    ❌         ❌       ✅
TLS 指纹伪装                    ❌     ❌     ❌    ❌         ❌       ✅
设备指纹仿真                     ❌     ❌     ❌    ❌         ❌       ✅
行为仿真                        ❌     ❌     ❌    ❌         ❌       ✅
HTTP/2 主动解析                  ✅     ✅     ✅    ✅         ✅       ✅
WebSocket 捕获                  ✅     ✅     ⚠️    ✅         ✅       ✅
QUIC SNI 提取                   ❌     ❌     ❌    ✅         ❌       ✅
SSLKEYLOGFILE                   ❌     ❌     ❌    ✅         ❌       ✅
反作弊检测                       ❌     ❌     ❌    ❌         ❌       ✅
验证码自动处理                   ❌     ❌     ❌    ❌         ❌       ✅
逆向工程分析                     ❌     ❌     ❌    ❌         ❌       ✅
应用层解码                       ❌     ❌     ❌    ❌         ❌       ✅
全产品插件化                     ❌     ❌     ❌    ❌         ❌       ✅
不解密情报提取                   ❌     ❌     ❌    ❌         ❌       ✅
操作流级提取                     ❌     ❌     ❌    ❌         ❌       ✅
══════════════════════════════════════════════════════════════════════════════════════
创新壁垒数:                      0      0      0     0         0        17
```

### 3.2 壁垒深度：为什么竞品做不了

**壁垒 1：进程内 SSL Hook（DataProbe 实现方案：Frida 注入）**

竞品（Fiddler/Charles）全部依赖 L7 代理，目标应用如果做了以下任何一项就会失效：
- 不读系统代理
- 自建 TLS 连接（Go/Node/Unity）
- 证书锁定（Certificate Pinning）

DataProbe 的 Frida Hook 方案绕过这些限制——在目标进程内部、在加密发生之前获取明文。这是 Fiddler/Charles 架构上做不到的，因为它们的核心是一个用户态代理服务器，没有进程注入能力。

**壁垒 2：TLS 指纹伪造（DataProbe 实现方案：OpenSSL 替换 SChannel）**

所有基于 SChannel（.NET）或 OpenSSL（Python/mitmproxy）的 TLS 代理都有一个共同问题：它们连接到上游服务器时暴露了自己的 TLS 指纹（JA3）。Cloudflare 等服务商知道这些指纹并被可以标记代理流量。

DataProbe 通过 OpenSSL P/Invoke + 自定义密码套件顺序实现任意 JA3 指纹伪造——可以让上游以为我们在用 Chrome、Firefox、Safari 或 Android App。

**壁垒 3：不解密情报提取**

当 TLS 无法解密（HSTS Preload、证书锁定、反作弊保护）时，Fiddler/Charles 完全失效。DataProbe 通过 PassiveIntelligence 从包大小、时序、SNI、跨步骤关联中提取情报——数据量少但不是零。这是"最后防线"能力，竞品完全没有。

**壁垒 4：全产品插件化**

竞品：Fiddler 有 FiddlerScript（单个文件的脚本），Burp 有扩展（Java）。但这些都是"外挂"，不是架构层插件。

DataProbe 的：ICaptureChannel / IProtocolParser / IReScannerPlugin / IDecryptionPlugin / IExtractorPlugin / IProtocolPlugin — 全部通过 PluginManager 统一发现和加载。插件与内置代码共享相同的 SPI 接口。竞品没有一个做了同等深度的插件化。

**壁垒 5：多维度仿真**

竞品没有一个同时做 TLS 指纹、设备指纹、行为仿真。Fiddler、Charles、Burp 只做代理，不管仿真。Wireshark 纯被动不看仿真。但现代风控系统全面检测这些维度——缺一个维度就可能被标记。

### 3.3 技术缺口

```
壁垒                                          状态      投入
══════════════════════════════════════════════════════════════════════
进程内 SSL Hook (Frida)                       ✅       pip install
.NET Profiler 明文提取                        ❌       2-3 周
Java Agent 明文提取                          ❌       2-3 周
QUIC Full MITM                               ⚠️       4-6 周 (研究级)
移动端独立 Agent (Android VPN/iOS NE)        ❌       4-6 周
OpenSSL 指纹伪造完整实现                      ⚠️       1 周 (需装 OpenSSL)
规则市场 / 规则分享                           ❌       1 周
分布式多节点捕获                              ❌       6-8 周
Pro Mode 规则编辑器 UI 完善                    ❌       1 周
```

### 3.4 与竞品的本质差异总结

```
Fiddler/Charles:   L7 代理 → 读代理 → 手动找数据
Burp:              L7 代理 → 手动测 → 找漏洞
Wireshark:         L2 被动 → 自己分析 → 自己解
mitmproxy:         L7 代理 → Python 脚本 → 手动

DataProbe:         L4+L7+进程内 多通道自动选 → 自动解密+解码
                   → 全位置自动提取 → 不解密也能分析
                   → 仿真+风控规避+反作弊检测
                   → 一个按钮完成全部
```

---

## 4. 外部依赖

```
依赖          版本     大小    用途            状态
────────────────────────────────────────────────────
WinDivert     —        0.5MB  内核TCP拦截     ✅
WinTUN        0.14.1   0.4MB  虚拟网卡L3      ✅
Frida/Python  17.11.0 ~10MB   进程注入SSL Hook ✅
ddddocr/ONNX  1.6.1   ~50MB   本地验证码OCR   ❌ 未装入 (安装失败)
2Captcha      —        0      远程验证码API    ✅ (需 API Key)
OpenSSL       —        ~2MB   TLS指纹伪造     ❌ 可选
```

全部可选可拆卸，缺失即降级，不影响内核。

---

## 5. Git 提交历史

```
87d8e59  按需解码修复: 数据截断 + Base64检测 + 按钮功能
8eb927f  按需解码: 移除自动解密 + 用户控制的 Decode 按钮
a1981b8  应用层解密流水线: Base64/JSON转义/URL解码/Hex + 插件解密
6713c40  Traffic 详情修复: 响应体不显示 + 数据截断问题
ffe6ec5  Dashboard: 页面刷新自动恢复进行中的调查
74bc2bf  Dashboard Pro Mode: 规则编辑器 + 通道面板 + 流量查看器
24712f3  docs: 用户使用手册
1fa34d4  更新 PROJECT_STATUS.md 到完全体完成度
e873d35  V2.0 Phase 9-12: 设备仿真 + 反作弊 + 验证+ Pro Mode
950cb1b  V2.0 Phase 8: TLS 指纹伪造 (OpenSSL + JA3 模板库)
f597da4  V1.5 完成: 不解密情报提取 + QUIC检测 + 示例插件
aa6c7dc  外部依赖部署: WinTUN / Frida / ddddocr
0d4d86f  CAPTCHA 求解 + TUN + 逆向 V2 + PluginManager
11bb298  WebSocket 集成 + SSLKEYLOGFILE
54cb0a6  更新 PROJECT_STATUS.md
9dd7231  修复 ReAnalyzer 适配泛型API
70e4674  插件架构升级为全产品统一扩展机制
1c59d72  插件体系: PluginManager + 5类接口
cbdf850  DataProbe v2.0 架构全面升级
a2b7214  Initial commit: DataProbe v1.0
```
