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
16. [插件体系](#16-插件体系)

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
│  │ 插件扫描 │  │ 仿真配置 │  │ 插件解密 │  │ 插件提取 │  │ 报告导出 │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└──────────────────────────────────────────────────────────────────────────────┘
            │                    │                          │
┌───────────▼────────────────────▼──────────────────────────▼──────────────────┐
│                          底 层 引 擎 组 件                                     │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ 通道矩阵  │  │ 解密矩阵  │  │ 协议解析  │  │ 仿真模拟  │  │ 逆向工程  │       │
│  │ 8通道    │  │ 5路解密  │  │ 8协议    │  │ 4维度   │  │ 3阶段   │       │
│  │ 自动调度  │  │ 自动选路  │  │ 可扩展   │  │ 可控    │  │ 插件化  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────────────┐  │
│  │ 验证对抗  │  │ 规则引擎  │  │ 数据模型  │  │ 反作弊感知                   │  │
│  │ 4类处理  │  │ 全位置   │  │ Session  │  │ 3级检测                     │  │
│  │ 人工介入  │  │ 热加载   │  │ 证据链   │  │ 自动降级                    │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────────────────┘  │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────┐│
│  │  插件管理器 (Plugin Manager) ★★★                                          ││
│  │  plugins/ 目录 → 自动发现 .dll → 加载为 IDataProbePlugin                   ││
│  │  支持类型: ReScanner | Decryption | Extractor | Protocol | Challenge       ││
│  │  热加载: 文件变更自动重新加载                                              ││
│  └──────────────────────────────────────────────────────────────────────────┘│
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

原则 5: 插件化是架构层原则（★本设计的核心差异化）
  所有扩展点通过统一的 plugins/ 目录加载。
  插件与内置代码享有完全相同的 SPI 接口。
  Program.cs 不区分"哪些是内置的，哪些是插件来的"。
  热加载：FileSystemWatcher 监听 plugins/ 变更 → 自动重新加载。

  支持的扩展点：
  ├─ 通道 (ICaptureChannel)          → channels/*.dll
  ├─ 协议解析器 (IProtocolParser)    → parsers/*.dll
  ├─ 逆向扫描器                       → scanners/*.dll
  ├─ 应用层解密器                     → decryption/*.dll
  ├─ 高级提取器                       → extractors/*.dll
  ├─ 验证码处理器                     → challenges/*.dll
  ├─ 规则包                           → rules/*.json
  ├─ TLS 指纹模板                     → fingerprints/*.json
  └─ 设备指纹配置                     → devices/*.json

  这确保：
  - 每次攻克一个新目标，不需要改主代码
  - 特定目标的定制逻辑以独立 .dll 存在
  - 社区可分享插件而不暴露主代码
```
...

## 16. 插件体系

### 16.1 为什么要插件

DataProbe 的核心挑战是：**每个目标都有独特的自定义加密、独特的 API 格式、独特的防护手段。** 这些无法在引擎层穷举，必须通过插件机制留给社区和特定目标攻克者。

插件不是"附加功能"，是 DataProbe 对抗能力的自然延伸。

### 16.2 插件类型

```
┌─ 插件类型 ───────────────────────────────────────────┐
│                                                        │
│  🔬 ReScanner（逆向扫描器）                             │
│  针对特定 App 的 APK/IPA/DLL 分析                       │
│  例: "抖音 APK 扫描器" → 提取抖音的 API 端点 + 加密方案 │
│                                                        │
│  🔐 Decryption（应用层解密器）                          │
│  在 TLS 解密之后、规则引擎之前，退掉自定义加密/编码层    │
│  例: "淘宝 MTOP 解密器" → 退掉 Base64+AES  双层加密     │
│                                                        │
│  📦 Extractor（高级提取器）                             │
│  比正则/JSONPath 更复杂的提取逻辑                       │
│  例: "Protobuf 提取器" → 根据 .proto 解码并提取         │
│                                                        │
│  🌐 Protocol（协议解析器）                              │
│  非 HTTP 的二进制协议解析                              │
│  例: "MQTT 协议解析器" → IoT 消息提取                   │
│                                                        │
│  🛡️ Challenge（验证码/挑战处理器）                      │
│  定制验证码求解逻辑                                    │
│  例: "极验滑块破解器" → 轨迹模拟 + 缺口识别             │
└──────────────────────────────────────────────────────────┘
```

### 16.3 统一的扩展发现机制

```
PluginManager 是覆盖全产品扩展点的统一入口。
它不区分"这个是插件接口"和"那个是内置 SPI"——
ICaptureChannel、IProtocolParser、IReScannerPlugin 都在同一个发现流程中。

┌─ 插件目录结构 ───────────────────────────────────────┐
│  plugins/                                              │
│  ├── channels/           ← ICaptureChannel (.dll)      │
│  │   └── MyProtocolChannel.dll                         │
│  ├── parsers/            ← IProtocolParser (.dll)      │
│  │   └── MqttParser.dll                                │
│  ├── scanners/           ← IReScannerPlugin (.dll)     │
│  │   ├── DouyinScanner.dll                             │
│  │   └── WeChatMiniProgram.dll                         │
│  ├── decryption/         ← IDecryptionPlugin (.dll)    │
│  │   └── TaobaoMtopCrypto.dll                          │
│  ├── extractors/         ← IExtractorPlugin (.dll)     │
│  ├── challenges/         ← 验证码处理器 (.dll)         │
│  ├── rules/              ← 提取规则包 (.json)          │
│  ├── fingerprints/       ← TLS 指纹模板 (.json)        │
│  └── devices/            ← 设备指纹配置 (.json)        │
│                                                        │
│  宿主应用通过 PluginManager 的事件回调接收发现结果:     │
│  ┌──────────────────────────────────────────────────┐  │
│  │  PluginManager                                   │  │
│  │  ├─ OnChannelDiscovered       → ChannelManager   │  │
│  │  ├─ OnParserDiscovered        → ProtocolRegistry │  │
│  │  ├─ OnPluginDiscovered        → ADE              │  │
│  │  ├─ OnRuleDiscovered          → RuleEngine       │  │
│  │  └─ OnFingerprintDiscovered   → FingerprintEngine│  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘

┌─ 插件生命周期 ────────────────────────────────────────┐
│                                                        │
│  启动时 → PluginManager 扫描 plugins/ 所有子目录        │
│       → .dll: Assembly.LoadFrom → 反射发现              │
│         ├─ ICaptureChannel  → OnChannelDiscovered      │
│         ├─ IProtocolParser  → OnParserDiscovered       │
│         └─ IDataProbePlugin → OnPluginDiscovered       │
│       → .json: 按目录规则解析                           │
│         ├─ rules/*.json     → OnRuleDiscovered         │
│         └─ fingerprints/*.json→ OnFingerprintDiscovered│
│                                                        │
│  运行时 → FileSystemWatcher 监听 plugins/ 变更          │
│       → 新增/变更 → 自动重新加载                       │
│                                                        │
│  使用方 → 不关心扩展是内置的还是插件的                   │
│         → ChannelManager / ProtocolRegistry / ADE       │
│           统一管理所有来源的扩展                          │
└──────────────────────────────────────────────────────────┘
```

### 16.4 插件接口一览

```
根接口:
  IDataProbePlugin
  ├─ Id          — 唯一标识 "com.example.shop.decrypt"
  ├─ Name        — 显示名称
  ├─ Version     — 语义化版本 "1.2.0"
  ├─ SupportedTargets — ["com.example.shop", "*.taobao.com"]
  └─ InitializeAsync() — 初始化

子接口:
  IReScannerPlugin     → CanAnalyze() + Scan()
  IDecryptionPlugin    → CanDecrypt() + DecryptAsync()
  IExtractorPlugin     → CanExtract() + ExtractAsync()
  IProtocolPlugin      → CanParse() + ParseRequest/Response()

非 IDataProbePlugin 接口（通过 PluginManager 统一发现）:
  ICaptureChannel      → Name + Capability + Start/Stop
  IProtocolParser      → ProtocolName + CanParse + ParseRequest/Response
```

### 16.5 插件开发规范

```
插件项目 .csproj:
  ┌──────────────────────────────────────────────────┐
  │  <Project Sdk="Microsoft.NET.Sdk">                │
  │    <PropertyGroup>                                │
  │      <TargetFramework>net8.0</TargetFramework>    │
  │    </PropertyGroup>                               │
  │    <ItemGroup>                                    │
  │      <Reference Include="DataProbe.Core.dll" />   │
  │      <Reference Include="DataProbe.Extractor.dll"/>│
  │    </ItemGroup>                                   │
  │  </Project>                                       │
  └──────────────────────────────────────────────────┘

插件实现示例（解密器）：
  ┌──────────────────────────────────────────────────┐
  │  public class ShopAppDecryptor                    │
  │      : IDecryptionPlugin                         │
  │  {                                                │
  │      public string Id => "com.shop.decrypt";      │
  │      public string[] SupportedTargets             │
  │          => ["com.example.shop"];                 │
  │                                                   │
  │      public bool CanDecrypt(NormalizedTransaction tx) │
  │          => tx.ResponseBody                       │
  │             .Contains("encrypted_data");          │
  │                                                   │
  │      public Task<DecryptionResult> DecryptAsync(  │
  │          NormalizedTransaction tx, ...)           │
  │      {                                            │
  │          // 退掉 App 的自定义加密                  │
  │          var raw = tx.ResponseBody;                │
  │          var decoded = Base64Decode(raw);          │
  │          var plain = AesDecrypt(decoded, key);     │
  │          return new DecryptionResult              │
  │          {                                        │
  │              Success = true,                       │
  │              DecryptedBody = plain                 │
  │          };                                       │
  │      }                                            │
  │  }                                                │
  └──────────────────────────────────────────────────┘
```

### 16.6 内置 vs 插件

```
内置扫描器（ReAnalyzer 自带，对所有目标有效）:
  ├─ StringScanner       — 通用字符串提取
  ├─ CertPinningDetector — 证书锁定检测
  └─ AntiEmulatorDetector— 反模拟器检测

插件扫描器（针对特定目标编写）:
  ├─ DouyinScanner       — 抖音 API 端点 + 加密识别
  ├─ TaobaoMtopCrypto    — 淘宝 MTOP 协议的解密
  └─ WeChatPayExtractor  — 微信支付二维码提取

内置的不需要额外分发，随引擎发布。
插件的按需编写，编译为 .dll 放到 plugins/ 目录。
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
逆向工程            无                                APK/DLL 自动分析 + 插件扫描
反作弊感知           无                                3 级检测 + 自动降级
验证码              无                                OCR/AI/人工三级
插件体系            无                                5 类插件 + 热加载 + 生命周期

架构复杂度          约 6 个项目 / 5,000 行           约 15 个模块 / 30,000+ 行
团队需求            1 人维护                          3-5 人开发
```
