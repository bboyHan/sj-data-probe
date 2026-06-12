# DataProbe (神机数探) — 项目状态

> 最后更新: 2026-06-12 | 提交: `11bb298` | 5 commits ahead of v1.0
> 设计文档: [DESIGN.md](./DESIGN.md)

## 项目定位

**数据开采对抗平台** — 给任意数字目标（App/网站/游戏/小程序），自动突破其所有防御层，提取结构化数据，并附上不可抵赖的证据链。

与 Fiddler/Wireshark/VPN 的本质区别：
- 传统工具："给你数据，自己找答案"
- DataProbe: "告诉我问题，我给你答案"

## 核心设计文档

完整的技术白皮书：[DESIGN.md](./DESIGN.md)，包含：

- **产品定义与定位** — 目标用户、竞品区别
- **总体架构** — 五阶段调查流水线、对抗决策引擎
- **核心数据模型** — SessionSnapshot、DataEvidence 统一模型
- **通道矩阵** — 8 通道（现有+规划）、自动调度策略
- **TLS 解密矩阵** — 5 路解密方案（MITM/Keylog/Hook/Profiler/Agent）
- **协议解析栈** — HTTP/2 + WebSocket + QUIC 路线
- **仿真模拟层** — TLS 指纹伪造、设备仿真、行为仿真
- **逆向工程中心** — APK/DLL 自动分析、Hook 脚本自动生成
- **验证对抗引擎** — 验证码/SMS/人工三级处理
- **反作弊感知与规避** — 4 级检测 + 自动通道降级
- **规则引擎与提取体系** — 全位置扫描、预设规则包、启发式发现
- **技术壁垒总图** — 12 项绝对独创壁垒（竞品完全无法触及）
- **实施路线图** — V1.1 → V1.5 → V2.0 三阶段路线

## 绝对技术壁垒（12 项独创）

```
1. 进程内 SSL Hook             — 突破证书锁定
2. .NET Profiler 明文提取       — 绕过 TLS 层
3. Java Agent 明文提取          — Java 应用同
4. 多 TLS 库统一 Hook 矩阵      — 覆盖所有常见 SSL 库
5. TLS JA3 指纹伪造             — 不被服务器识别为代理
6. 设备指纹仿真                 — 通过 SDK 信任检测
7. 行为仿真                     — 不被风控标记
8. 反作弊检测与规避              — ACE/TenSafe 下工作
9. 自动逆向 Hook 脚本生成       — APK→Frida 脚本
10. 操作流 Session 提取          — 跨请求/跨协议聚合
11. 全位置规则扫描               — 所有数据位置查找
12. 不解密情报提取               — 大小/时序/SNI 分析
```

## 当前代码状态（v2.0）

| 模块 | 状态 | 说明 |
|------|------|------|
| 核心数据模型 | ✅ 完成 | SessionSnapshot / DataEvidence / CaptureTarget / SessionBuilder |
| ICaptureChannel + 4 通道 | ✅ 完成 | WinDivert / DnsSpoof / TlsProxy / SystemProxy（4 通道） |
| TUN 通道 | 🔧 骨架 | TunChannel.cs 分类器完整，缺 WinTUN P/Invoke |
| 进程 Hook | 🔧 骨架 | ProcessHookChannel.cs 架构完整，缺 C++ DLL + 注入 |
| HTTP/1.1 解析 | ✅ 已清理 | 移除支付命名残余 |
| HTTP/2 + HPACK | ✅ 完整实现 | nghttp2 帧解析 + Huffman 解码 + 静态/动态表 |
| WebSocket 解析 | ✅ 完整实现 | RFC 6455 帧解析 + TlsProxy 集成 |
| SSLKEYLOGFILE | ✅ 新增 | 浏览器密钥注入 + 文件监控 + NSS 导出 |
| 规则引擎 | ✅ Session 级 | 全位置扫描 + 热加载 + 启发式提取集成 |
| 启发式提取 | ✅ V1 | 熵检测 / JSON 字段 / JWT 解码 |
| 验证码检测 | ✅ 实现 | 极验/reCAPTCHA/hCaptcha/自定义类型识别 |
| 验证码求解 | 🔧 骨架 | 缺 ddddocr/2Captcha API 实际调用 |
| 逆向工程 V1 | ✅ 实现 | 字符串扫描 / SDK 指纹 / 证书锁定 / 反模拟器检测 |
| 逆向工程 V2 | 🔧 骨架 | APK 解包 / PE 导入表 / 加密常数分析（未实装） |
| 反作弊检测 | ✅ V1 | ACE/TenSafe/EAC/BattlEye 模块扫描 |
| 仿真模拟 | ❌ 未开始 | TLS 指纹伪造 / 设备仿真 / 行为仿真 |
| ADE V1 | ✅ 完成 | 目标侦察(DNS/TLS/CDN) + 通道选择 + 自动降级 |
| 插件体系 | ✅ 完成 | PluginManager 全产品扩展入口 + 5 类插件接口 |
| Easy Mode Dashboard | ✅ 全新 | 目标输入 / ADE 方案 / 证据卡片 / 3s 轮询 |
| Pro Mode | ❌ 未开始 | 通道面板 / 规则编辑器 / 流量查看器 |
| 报告系统 | ❌ 未开始 | 证据链导出 / PDF/JSON/CSV |

## 紧急修复项（已完成 ✅）

| 修复项 | 状态 |
|--------|------|
| `/status` 硬编码 bug | ✅ 已修复 |
| `config.json` 反序列化未赋值 | ✅ 已修复 |
| RuleEngine Source 硬编码 "oracle" | ✅ 已移除 |
| ParseDataType 残留支付枚举名 | ✅ 已清理 |
| CapturedDataType 扩展 | ✅ 新增 Account/Payment |
| HttpParser 支付命名 | ✅ 已清理 |
| Tls 项目缺少引用 | ✅ 已修复 |
| MatchType 命名空间冲突 | ✅ 已修复 |

## 实施路线（更新）

| 版本 | 当前状态 | 剩余工作 |
|------|----------|----------|
| V1.1 — 基础可用 | ✅ 100% | HTTP/2 / Session 模型 / 全位置扫描 / 系统代理 |
| V1.5 — 能力扩展 | 完成 40% | ✅ WebSocket / SSLKEYLOGFILE / 反作弊 / 启发式 |
| | | 🔧 进程 Hook / TUN / 逆向 V2 / 验证码求解 |
| V2.0 — 完全体 | 0% | TLS 指纹伪造 / 仿真 / 报告 / Pro Mode |

## 快速链接

- 技术白皮书: [DESIGN.md](./DESIGN.md)
- README: [README.md](./README.md)
