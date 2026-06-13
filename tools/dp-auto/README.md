# DataProbe Auto (dp-auto)

> 浏览器自动化支付捕获引擎 — 与 DataProbe C# 引擎配合使用。

## 安装

```bash
cd tools/dp-auto
pip install -e .
# 或: pip install undetected-chromedriver selenium requests pillow pyzbar
```

## 快速开始

```bash
# 0. 确保 DataProbe 引擎在运行
cd ../..
dotnet run --project src/DataProbe.Api

# 1. 检查环境和连通性
cd tools/dp-auto
python -m dp_auto.cli check

# 2. 启动隐身浏览器（手动模式）
python -m dp_auto.cli launch --url https://www.taobao.com

# 3. 自动捕获支付链接（自动模式）
python -m dp_auto.cli capture https://example.com/pay --auto

# 4. 指定代理区域
python -m dp_auto.cli capture https://example.com/pay --auto --region 杭州
```

## 命令

| 命令 | 功能 |
|------|------|
| `check` | 检查 DataProbe 连通性和环境配置 |
| `launch` | 启动隐身 Chrome 浏览器 |
| `capture` | 自动导航到支付页并捕获支付链接 |

## 架构

```
dp-auto (Python)                      DataProbe (C#)
─────────────────────────             ─────────────────────────
Browser Launcher                      HTTP API
├─ undetected-chromedriver            ├─ /api/captcha/solve
├─ stealth patches                    ├─ /api/behavior/next
├─ proxy manager                      ├─ /api/device/profile
└─ orchestrator                       └─ /api/evidence
       │                                      ↑
       └────────── localhost:18801 ────────────┘
```

## 与 DataProbe 的关系

dp-auto 是 DataProbe 的自动化前端，不是替代品：

| 能力 | DataProbe | dp-auto |
|------|-----------|---------|
| TLS 解密 | ✅ 引擎核心 | ❌ 不需要 |
| 规则提取 | ✅ 引擎核心 | ❌ 不需要 |
| 验证码识别 | ✅ POST /api/captcha | 调 API |
| 行为仿真 | ✅ GET /api/behavior | 调 API |
| 设备指纹 | ✅ GET /api/device | 调 API |
| 浏览器自动化 | ❌ 不实现 | ✅ 核心 |
| 反检测补丁 | ❌ 不实现 | ✅ 核心 |
| IP 代理管理 | ❌ 不实现 | ✅ 核心 |
