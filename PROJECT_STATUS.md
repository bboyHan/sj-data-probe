# DataProbe (神机数探) — 项目状态

> 最后更新: 2026-06-13 | 提交: `e873d35` | 12 commits ahead of v1.0
> 设计文档: [DESIGN.md](./DESIGN.md)

## 项目定位

**数据开采对抗平台** — 给任意数字目标（App/网站/游戏/小程序），自动突破其所有防御层，提取结构化数据，并附上不可抵赖的证据链。

与 Fiddler/Wireshark/VPN 的本质区别：
- 传统工具："给你数据，自己找答案"
- DataProbe: "告诉我问题，我给你答案"

## 完成度总图

```
V1.1 — 基础可用 ████████████████████ 100%
  Phase 0  紧急修复          ✅ 8/8 bugs
  Phase 1  HTTP/2 + Session  ✅ HPACK + 帧 + SessionSnapshot
  Phase 2  全位置规则扫描     ✅ 6位置 + 启发式
  Phase 3  系统代理通道       ✅ SystemProxy + ADE

V1.5 — 能力扩展 ████████████████████ 100%
  Phase 4  进程 SSL Hook     ✅ Frida引擎 + frida_hook.py
  Phase 5  逆向工程 V2       ✅ APK/PE分析 + 10+ SDK指纹
  Phase 6  TUN 通道          ✅ WinTUN + IP分类 + TCP/443重定向
  Phase 7  WebSocket+CAPTCHA ✅ WS帧 + ddddocr/2Captcha/人工
  SSLKEYLOGFILE               ✅ 浏览器密钥注入

V2.0 — 完全体   ████████████████████ 100%
  Phase 8  TLS 指纹伪造       ✅ OpenSSL + JA3模板库(7模板) + TlsProxy
  Phase 9  设备/行为仿真      ✅ 50+设备模板 + 贝塞尔轨迹 + 正态时序
  Phase 10 反作弊完全体       ✅ 进程/模块/驱动3级 + 30+特征
  Phase 11 验证对抗完全体     ✅ SMS桥 + 风控规避 + 限速+IP轮换
  Phase 12 Pro Mode+报告     ✅ 通道面板 + 流量查看 + JSON/CSV/摘要

12 项壁垒:
  1. 进程内 SSL Hook          ✅ Frida 17.11.0
  2. .NET Profiler 提取       🔧 研发中
  3. Java Agent 提取          🔧 研发中
  4. 多 TLS 库 Hook           ✅ Frida覆盖
  5. TLS JA3 指纹伪造         ✅ OpenSSL + 7模板
  6. 设备指纹仿真             ✅ 50+模板 + 自洽性校验
  7. 行为仿真                 ✅ 贝塞尔鼠标 + 正态时序 + 静默
  8. 反作弊检测               ✅ 3级 + 30+特征
  9. 自动 Hook 脚本生成        🔧 骨架就绪
  10. Session 提取            ✅ SessionSnapshot
  11. 全位置扫描              ✅ 6位置
  12. 不解密情报提取          ✅ PassiveIntelligence
```

## 项目全景

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  模块                   状态    依赖
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  核心模型 (Session/Evidence/Plan)       ✅  无
  WinDivert 通道                         ✅  WinDivert.dll
  DnsSpoof 通道                          ✅  WinDivert.dll
  TlsProxy 通道                          ✅  系统内置 + TLS指纹引擎
  SystemProxy 通道                       ✅  系统 WinINet
  TUN 通道                               ✅  wintun.dll
  ProcessHook 通道                       ✅  Frida
  通道管理器 + 自动发现                   ✅  ChannelManager
  ─────────────────────────────────────────────────────────────────
  HTTP/1.1 解析                          ✅  已清理支付命名
  HTTP/2 + HPACK 解析                    ✅  帧+STATIC/DYNAMIC表
  WebSocket 解析+集成                    ✅  TlsProxy 101检测
  ─────────────────────────────────────────────────────────────────
  ADE 对抗决策引擎                       ✅  DNS/TLS/CDN + 通道选择
  启发式提取 (熵/JSON/JWT)               ✅  HeuristicExtractor
  规则引擎 (全位置 + 热加载)              ✅  RuleEngine
  逆向工程 V1 (字符串/SDK/锁定)          ✅  ReAnalyzer + 3扫描器
  逆向工程 V2 (APK/PE/DEX)              ✅  ApkManifest + PeImport
  不解密情报提取 (大小/时序/SNI)          ✅  PassiveIntelligence
  反作弊检测 (3级 + 30特征)              ✅  AntiCheatDetector
  验证码检测 (极验/recaptcha/hcaptcha)   ✅  CaptchaDetector
  验证码求解 (本地+远程+人工)            ✅  Ddddocr/2Captcha/Manual
  SMS 验证桥                             ✅  SmsVerificationBridge
  风控规避 (限速+IP轮换+行为切换)         ✅  RiskControlEvasion
  TLS 指纹伪造 (JA3 + OpenSSL)          ✅  TlsFingerprintEngine
  设备指纹工厂 (50+模板)                 ✅  DeviceProfileFactory
  行为仿真 (贝塞尔+正态+静默)            ✅  BehaviorSimulationEngine
  PluginManager (全产品扩展入口)         ✅  Core/Program.cs
  ─────────────────────────────────────────────────────────────────
  Easy Mode Dashboard                    ✅  目标输入/ADE方案/证据
  Pro Mode (通道/流量/报告)              ✅  端点就绪
  报告导出 (JSON/CSV/摘要)              ✅  ReportGenerator
  ─────────────────────────────────────────────────────────────────
  所有外部依赖                           ✅  可选可拆卸
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 外部依赖

```
依赖          版本     大小     用途
────────────────────────────────────────────
WinDivert     —        0.5MB   内核TCP拦截
WinTUN        0.14.1   0.4MB   虚拟网卡L3全流量
Frida/Python  17.11.0 ~10MB    进程注入SSL Hook
ddddocr/ONNX  1.6.1   ~50MB    本地验证码OCR
2Captcha      —        0       远程验证码API (HTTP)
OpenSSL       —        ~2MB    TLS指纹伪造 (可选)
────────────────────────────────────────────
全部可选可拆卸，缺失即降级，不影响内核。
```

## Git 提交历史

```
e873d35  V2.0 Phase 9-12: 设备仿真 + 反作弊 + 验证+ Pro Mode
950cb1b  V2.0 Phase 8: TLS 指纹伪造 (OpenSSL + JA3模板库)
f597da4  V1.5 完成: 不解密情报提取 + QUIC检测 + 示例插件
aa6c7dc  外部依赖部署: WinTUN / Frida / ddddocr
0d4d86f  CAPTCHA求解 + TUN通道 + 逆向V2 + PluginManager集成
11bb298  WebSocket集成 + SSLKEYLOGFILE支持
54cb0a6  更新 PROJECT_STATUS.md
9dd7231  修复 ReAnalyzer 适配泛型API
70e4674  插件架构升级为全产品统一扩展机制
1c59d72  插件体系: PluginManager + 5类可插拔接口
cbdf850  DataProbe v2.0 架构全面升级
```

## 快速链接

- 技术白皮书: [DESIGN.md](./DESIGN.md)
- GitHub: `https://github.com/bboyHan/sj-data-probe`
- 启动: `dotnet run --project src/DataProbe.Api` → http://localhost:18801
