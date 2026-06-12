# DataProbe (神机数探) — 项目状态

> 最后更新: 2026-06-12 | 提交: `aa6c7dc` | 8 commits ahead of v1.0
> 设计文档: [DESIGN.md](./DESIGN.md)

## 项目定位

**数据开采对抗平台** — 给任意数字目标（App/网站/游戏/小程序），自动突破其所有防御层，提取结构化数据，并附上不可抵赖的证据链。

与 Fiddler/Wireshark/VPN 的本质区别：
- 传统工具："给你数据，自己找答案"
- DataProbe: "告诉我问题，我给你答案"

## 核心设计文档

完整技术白皮书：[DESIGN.md](./DESIGN.md)

## 当前完成度总图

```
V1.1 (基础可用) ——————————————————————————— ██████████ 100%
  Phase 0  紧急修复          ✅ 8/8 bugs fixed
  Phase 1  HTTP/2 + Session  ✅ HPACK + 帧解析 + SessionSnapshot
  Phase 2  全位置规则扫描     ✅ 6位置 + 启发式 + 热加载
  Phase 3  系统代理通道       ✅ SystemProxy + ADE通道选择

V1.5 (能力扩展) ——————————————————————————— ████████░░  80%
  Phase 4  进程 SSL Hook     ✅ Frida引擎 (17.11.0) + frida_hook.py
                             代替了原C++ DLL方案 → 零编译器依赖
  Phase 5  逆向工程 V2       ✅ APK解包 + AXML解析 + DEX字符串池
                             ✅ PE导入表 + 反作弊/SSL库检测
  Phase 6  TUN 通道          ✅ WinTUN驱动(0.14.1) + P/Invoke
                             ✅ PacketReadLoop + IP分类 + TCP/443重定向
  Phase 7  WebSocket         ✅ RFC 6455帧解析 + TlsProxy集成
           验证码求解         ✅ ddddocr(本地) + 2Captcha(远程) + 人工
                             ✅ CaptchaSolverOrchestrator自动编排
  SSLKEYLOGFILE               ✅ 浏览器密钥注入 + NSS导出

V2.0 (完全体) ——————————————————————————— ░░░░░░░░░░   0%
  Phase 8  TLS指纹伪造         ❌
  Phase 9  设备/行为仿真       ❌
  Phase 10 反作弊完全体         ❌
  Phase 11 验证对抗完全体       ❌
  Phase 12 报告 + Pro Mode     ❌
```

## 模块级状态

```
  模块                状态    外部依赖
  ─────────────────────────────────────────────────
  核心模型              ✅    (无)
  WinDivert 通道        ✅    WinDivert.dll(内核驱动)
  DnsSpoof 通道         ✅    WinDivert.dll
  TlsProxy 通道         ✅    SChannel(系统内置)
  SystemProxy 通道      ✅    WinINet(系统内置)
  TUN 通道              ✅    wintun.dll (428KB ✅)
  ProcessHook 通道      ✅    Frida 17.11.0 + frida_hook.py
  ─────────────────────────────────────────────────
  HTTP/1.1 解析         ✅
  HTTP/2 + HPACK        ✅
  WebSocket 解析        ✅+TlsProxy集成
  ─────────────────────────────────────────────────
  目标侦察(DNS/TLS/CDN) ✅
  规则引擎(全位置)      ✅  +启发式提取
  ADE通道选择+降级      ✅
  PluginManager插件系统  ✅  已接入Program.cs回调
  ─────────────────────────────────────────────────
  SSLKEYLOGFILE          ✅  浏览器密钥注入
  逆向V2(APK/PE分析)    ✅  ApkManifest + PeImportScanner
  反作弊检测             ✅  ACE/TenSafe/EAC/BattlEye
  验证码检测             ✅  极验/reCAPTCHA/hCaptcha
  验证码求解             ✅  ddddocr/2Captcha/人工三级
  ─────────────────────────────────────────────────
  Easy Mode Dashboard   ✅  目标输入/方案展示/证据卡片
  ─────────────────────────────────────────────────
  TLS指纹伪造            ❌
  设备/行为仿真          ❌
  Pro Mode面板           ❌
  报告导出系统           ❌
```

## 12 项绝对独创壁垒进展

```
壁垒                                          状态
══════════════════════════════════════════════════════════════
  1. 进程内 SSL Hook (Frida引擎替代)          ✅ Frida 17.11.0
  2. .NET Profiler 明文提取                    ❌
  3. Java Agent 明文提取                       ❌
  4. 多 TLS 库统一 Hook 矩阵                   ✅ Frida支持多库
  5. TLS JA3 指纹伪造                          ❌
  6. 设备指纹仿真                              ❌
  7. 行为仿真                                  ❌
  8. 反作弊检测与规避                           ✅ V1
  9. 自动逆向 Hook 脚本生成                     🔧 APK/PE分析已就绪
 10. 操作流 Session 提取                       ✅ SessionSnapshot
 11. 全位置规则扫描                            ✅ 6位置
 12. 不解密情报提取                            ❌
```

## 外部依赖一览

```
依赖          版本     大小     可拆卸    用途
══════════════════════════════════════════════════════════════
WinDivert      —        0.5MB   ✅可选   内核TCP拦截
WinTUN         0.14.1   0.4MB   ✅可选   虚拟网卡L3全流量
Frida/Python   17.11.0  ~10MB   ✅可选   进程注入SSL Hook
ddddocr/ONNX   1.6.1    ~50MB   ✅可选   本地验证码OCR
2Captcha        —        0      ✅可选   远程验证码API
                               ──────────────
                               ~61MB    全部可选，缺失即降级
```

## 快速链接

- 技术白皮书: [DESIGN.md](./DESIGN.md)
- GitHub: `https://github.com/bboyHan/sj-data-probe`
- 启动: `dotnet run --project src/DataProbe.Api` → http://localhost:18801
