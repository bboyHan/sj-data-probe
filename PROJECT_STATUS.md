# DataProbe (神机数探) — 项目状态

> 最后更新: 2026-06-12
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

## 当前代码状态

| 模块 | 状态 | 说明 |
|------|------|------|
| ICaptureChannel + 3 通道 | ✅ | 基础通道架构完成，需扩展 |
| TlsProxy (SChannel MITM) | ✅ | 需 OpenSSL 替换实现指纹伪造 |
| HTTP/1.1 解析 | ✅ | 需完善 chunked/keep-alive |
| HTTP/2 解析 | ❌ 仅检测 | 需 nghttp2 P/Invoke 实现 |
| 规则引擎 | ⚠️ 基础版 | 需重写为 Session 级 + 全位置 |
| SessionSnapshot | ❌ | 全新核心模型，未实现 |
| 逆向工程中心 | ❌ | 全新模块 |
| 仿真模拟层 | ❌ | 全新模块 |
| 验证对抗引擎 | ❌ | 全新模块 |
| 反作弊感知 | ❌ | 全新模块 |
| Easy Mode UI | ❌ | 全新（现有 Dashboard 简陋） |

## 紧急修复项

1. `/status` 永远返回 "running" — `true ? "running" : "stopped"` 硬编码
2. `config.json` 反序列化结果未赋值 — `JsonSerializer.Deserialize<DataProbeConfig>(json)` 行
3. RuleEngine Source 硬编码 "oracle"
4. ParseDataType 残留支付枚举名映射

## 实施路线

| 版本 | 时间 | 核心交付 |
|------|------|----------|
| V1.1 | 6-8 周 | HTTP/2 解析、Session 模型、全位置扫描、系统代理通道 |
| V1.5 | 10-12 周 | 进程 SSL Hook、逆向工程、TUN 通道、WebSocket |
| V2.0 | 12-16 周 | TLS 指纹伪造、设备仿真、反作弊感知、验证对抗、报告系统 |

## 快速链接

- 技术白皮书: [DESIGN.md](./DESIGN.md)
- README: [README.md](./README.md)
