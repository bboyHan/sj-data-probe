# 浏览器自动化攻防设计 — 淘宝/腾讯系目标对抗方案

> 版本: v0.1 | 2026-06-13
> 与 DataProbe 引擎配合使用的浏览器自动化方案

---

## 一、问题定义

### 1.1 目标

```
在淘宝/腾讯系网站中，自动完成以下流程:
  ① 以目标身份（Token/Cookie/账号密码）登录
  ② 导航到支付页面
  ③ 找到指定金额的商品
  ④ 触发支付 → 捕获支付二维码/链接

全程不被风控系统识别为自动化操作。
```

### 1.2 防御方（淘宝/腾讯的检测能力）

```
淘宝/腾讯的风控体系是世界级的，检测维度包括:

浏览器层:
  ├─ navigator.webdriver 属性检测
  ├─ Chrome DevTools Protocol 检测
  ├─ window.chrome 对象深度检测
  ├─ canvas fingerprint ≠ 真实 GPU
  ├─ WebGL 渲染器字符串
  ├─ 字体枚举（安装字体列表）
  ├─ AudioContext 指纹
  ├─ 屏幕分辨率/色深/刷新率
  ├─ 时区/语言/输入法
  └─ WebRTC 真实 IP 泄漏

网络层:
  ├─ IP 地理位置的账户注册地一致性
  ├─ IP 是否为机房/代理/VPN 已知段
  ├─ TLS 指纹 (JA3/JA3S)
  ├─ HTTP/2 SETTINGS 帧参数
  ├─ TCP/IP 栈参数 (TTL, MSS, 窗口缩放)
  └─ DNS 解析路径

行为层:
  ├─ 鼠标轨迹（非贝塞尔曲线等机械模式）
  ├─ 点击间隔（非固定间隔）
  ├─ 滚动模式
  ├─ 页面停留时间
  ├─ 操作顺序（正常人类 vs 自动化的路径）
  └─ API 调用顺序和频率

账号层:
  ├─ 同一账号短时间内多地登录
  ├─ 登录设备指纹突变
  ├─ 历史行为模式偏离
  └─ 社交关系图谱异常
```

---

## 二、架构设计

```
┌─────────────────────────────────────────────────────────────────────┐
│  DataProbe Engine (C# / localhost:18801)                            │
│                                                                     │
│  提供的 API:                                                         │
│  ├─ POST /api/captcha/solve      → 验证码识别                      │
│  ├─ POST /api/sms/request        → 短信验证码                      │
│  ├─ GET  /api/device/profile     → 设备指纹                        │
│  ├─ GET  /api/behavior/next      → 人类化操作间隔                  │
│  ├─ GET  /api/proxy/next         → 区域一致的代理 IP               │
│  ├─ GET  /api/evidence           → 提取捕获数据                    │
│  └─ PASSIVE TLS — 自动捕获网络层数据                                │
└────────────────────┬────────────────────────────────────────────────┘
                     │ HTTP REST (localhost, 不经过代理)
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DataProbe Auto (Python 独立工程)                                   │
│                                                                     │
│  Core: undetected-chromedriver + stealth patches                    │
│                                                                     │
│  ① Launcher Layer                                                  │
│  ├─ 启动真实 Chrome（非无头模式）                                   │
│  ├─ 修改 Chrome 启动参数 (--disable-blink-features=AutomationControlled)│
│  ├─ 加载 undetected-chromedriver 补丁                               │
│  ├─ 加载 selenium-stealth 插件                                      │
│  └─ 注入自签名 CA 证书到 Chrome 信任存储                             │
│                                                                     │
│  ② Stealth Layer                                                   │
│  ├─ 覆盖 navigator.webdriver = false/undefined                     │
│  ├─ 覆盖 chrome.runtime 对象                                       │
│  ├─ 注入真实 canvas/WebGL 指纹                                     │
│  ├─ 打乱 screen.availWidth/Height 等                                │
│  ├─ 修改 plugins / mimeTypes 数组                                   │
│  ├─ 设置 accept-language / user-agent 一致                         │
│  ├─ 禁用 WebRTC IP 泄漏                                            │
│  └─ 随机化硬件并发 (navigator.hardwareConcurrency)                 │
│                                                                     │
│  ③ Session Layer                                                   │
│  ├─ Cookie 注入 → add_cookie() 恢复登录态                          │
│  ├─ Token 注入 → localStorage / sessionStorage                     │
│  ├─ 自动登录 → 表单填充 + 验证码处理                                │
│  └─ 验证码截获 → 调 DataProbe CAPTCHA API                          │
│                                                                     │
│  ④ Orchestration Layer                                             │
│  ├─ 页面导航 → 加载等待策略 (不是固定 sleep)                       │
│  ├─ 元素定位 → 混合 CSS + XPath + 可见性检测                       │
│  ├─ 支付触发 → 找到指定金额商品 → 点击下单                          │
│  ├─ 支付码捕获 → 截图/元素提取 → 识别支付二维码                     │
│  └─ 数据回传 → POST 提取结果到 DataProbe                           │
│                                                                     │
│  ⑤ Proxy Layer                                                     │
│  ├─ SOCKS5 代理 → 住宅 IP (Luminati/Proxy-Seller)                  │
│  ├─ 区域一致性 → 代理 IP 与账户注册地同城市                        │
│  ├─ DNS 防泄漏 → 通过代理解析 DNS                                  │
│  └─ WebRTC 防泄漏 → 禁用或绑定代理                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 三、Stealth 技术深度分析

### 3.1 检测与绕过对照表

```
检测维度                  淘宝/腾讯检测方式         绕过方案                   难度
══════════════════════════════════════════════════════════════════════════════
navigator.webdriver       检查是否为 true           undetected-chromedriver 自动  🟢
                                                                              补丁覆盖

window.chrome             检查 chrome 对象完整性   puppeteer-extra 补丁         🟢

Chrome DevTools Protocol  检查 "devtools" 标志     --remote-debugging-port=0    🟢
                                                  启动时不暴露调试端口

canvas fingerprint       生成 canvas 指纹与       用真实 GPU 渲染替代          🟡
                          已知自动化对比           模拟指纹

WebGL renderer           检查渲染器字符串          return "ANGLE (NVIDIA..."   🟡
                                                  (改成真实 GPU 型号)

Font detection           枚举已安装字体           用 Chrome 默认字体列表        🟢

WebDriver 命令行参数      检查 --enable-automation  启动时移除该参数             🟢

permissions.query        检查 navigator.permissions 覆盖权限查询返回值          🟢

User-Agent + 浏览器版本  检查一致性               使用与 Chrome 版本匹配的 UA   🟢

TLS 指纹 (JA3)           检查 TLS ClientHello      用真实的 Chrome TLS 参数      🔴
                          密码套件顺序             需要中间人代理 (DataProbe
                                                  已有 TLS 指纹引擎)

HTTP/2 SETTINGS 帧       检查 SETTINGS 参数       使用真实 Chrome 的参数        🔴
                          是否与 Chrome 一致       需要改 HTTP/2 协议栈

IP 属性                  是否机房/代理 IP         住宅代理 (非机房)             🟡
                                                  验证 IP 的 ASN 类型

鼠标轨迹                 是否为贝塞尔曲线         加入随机噪声 + 停顿           🟡
                                                  多段贝塞尔拼接

操作间隔                 是否正态分布             用 DataProbe 行为仿真引擎     🟢
                                                  的真实随机分布

同 IP 多地登录           短期内不同 IP 登录        固定代理 IP + 区域一致        🟢
                                                  代理通道

证书固定                 客户端证书验证            Frida Hook / 自签名 CA       🔴
                                                  需要 DataProbe 的 Hook 能力
```

### 3.2 最难突破的两个点

```
① TLS 指纹（JA3）
  淘宝/腾讯可能使用 JA3 指纹来识别非浏览器流量。
  
  DataProbe 的 TlsFingerprintEngine 已经实现了 JA3 伪造，
  但当前回退到 SChannel 因为 OpenSSL DLL 没装。
  装上 OpenSSL 后，上游连接可以用 Chrome 的 JA3 指纹。

  解决: 用户装 OpenSSL → DataProbe 自动启用 JA3 伪装
       → 浏览器自动化发出的请求通过 TlsProxy 代理
       → TlsProxy 用 Chrome 指纹连接淘宝/腾讯服务器
       → 服务器看到的 JA3 指纹 = 真实 Chrome

② 住宅 IP
  机房 IP 在淘宝/腾讯的风控中几乎没有不被标记的。
  
  方案:
  ├─ 轻量: SOCKS5 隧道代理（Proxy-Seller/ip2world 等）
  │  月费 ~¥50，提供静态住宅 IP
  ├─ 中等: 自建代理池（云服务器 + 住宅 IP 接口）
  │  月费 ~¥200，更灵活
  └─ 重量: 专线 IP（真正的固定公网 IP）
      月费 ~¥500+，最干净但最贵
```

---

## 四、支付链路捕获流程

```
┌─ 用户操作流程 ─────────────────────────────────────────────────────┐
│                                                                      │
│  ① 自动化脚本启动                                                    │
│     ├─ 从 DataProbe 获取设备指纹 + 行为参数                          │
│     ├─ 从配置加载 IP 代理                                            │
│     └─ 启动 Chrome + 加载 stealth 补丁                                │
│                                                                      │
│  ② 登录 (三种方式)                                                   │
│     A: Cookie 注入（最快，登录态已知）                                 │
│        → 从 DataProbe 已捕获的 Cookie 中提取                         │
│        → 直接注入浏览器                                              │
│        → 刷新 → 已登录状态                                           │
│                                                                      │
│     B: Token 注入                                                    │
│        → localStorage.setItem("token", "...")                        │
│        → API 请求中自动附带 Token                                    │
│                                                                      │
│     C: 账号密码登录                                                   │
│        → 填充表单 → 遇到验证码 → 调 DataProbe CAPTCHA API           │
│        → 需要短信 → 调 DataProbe SMS API                             │
│        → 登录成功 → 提取 Token/Cookie                                │
│                                                                      │
│  ③ 导航到支付目标                                                    │
│     ├─ 打开目标页面（如：商品详情）                                   │
│     ├─ 等待页面完全加载（检测特定 DOM 元素）                          │
│     └─ 重定向/弹窗处理                                                │
│                                                                      │
│  ④ 找到指定金额商品                                                  │
│     ├─ 搜索商品页面中的价格字段                                       │
│     ├─ 价格匹配（金额范围 / 精确值匹配）                              │
│     ├─ 点击对应商品                                                  │
│     └─ 等待支付页面/二维码加载                                        │
│                                                                      │
│  ⑤ 触发支付 ← ⭐ 关键步骤                                            │
│     ├─ 页面中查找支付按钮/下单按钮                                    │
│     ├─ 点击触发支付                                                  │
│     └─ 等待支付二维码/支付链接出现                                    │
│                                                                      │
│  ⑥ 捕获支付数据 ← ⭐ DataProbe 介入                                  │
│     ├─ 方案 A: 页面 DOM 提取                                         │
│     │  ├─ 支付二维码 → 截图 → 传输到 DataProbe                      │
│     │  └─ 支付链接 → element.getAttribute("href")                    │
│     ├─ 方案 B: DataProbe TlsProxy 捕获                               │
│     │  ├─ 浏览器通过 SystemProxy → 流量走 DataProbe                 │
│     │  ├─ 支付链路的 HTTPS 请求被解密                                │
│     │  └─ 规则引擎自动提取 sign/order_id/pay_url                     │
│     └─ 方案 C: 双保险                                                │
│         ├─ DOM 提取 + TlsProxy 捕获同时进行                          │
│         ├─ 任一方案成功即可                                           │
│         └─ 可对比两个来源确保正确性                                   │
│                                                                      │
│  ⑦ 结果回传                                                          │
│     ├─ 捕获到的支付数据通过 DataProbe API 存入 Session               │
│     └─ Dashboard 即时展示                                             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 五、IP 代理与区域一致性方案

### 5.1 代理方案选择

```
方案          费用       IP 类型     区域控制    速率     抗检测
══════════════════════════════════════════════════════════════════════
静态住宅代理   ~¥200/月  真实住宅     城市级     ✅      ✅✅✅
动态住宅代理   ~¥100/月  真实住宅     国家/省    ⚠️     ✅✅
机房代理       ~¥30/月    数据中心     ❌       ✅✅    ❌❌
专线代理       ~¥500/月   固定 IP     城市级     ✅✅    ✅✅✅
Tor          免费       出口节点      ❌       ❌     ❌❌❌

推荐: 静态住宅代理 (Proxy-Seller / ip2world / 922S5)
```

### 5.2 DataProbe 代理集成

```python
# 自动化脚本中的代理配置
proxy_config = {
    "type": "socks5",
    "host": "住宅代理 IP",
    "port": 1080,
    "username": "xxx",     # 如果代理需要认证
    "password": "xxx"
}

# Chrome 启动时加载代理
options = uc.ChromeOptions()
options.add_argument(f'--proxy-server=socks5://{proxy_config["host"]}:{proxy_config["port"]}')

# DataProbe Proxy API（预留接口）
# GET /api/proxy/next?region=杭州
# → 返回杭州区域的住宅代理 IP
```

### 5.3 防 IP 关联策略

```
同一账号的所有操作 → 走同一个静态 IP（不变）
不同账号 → 不同 IP（但同一城市段）
不发生 "账号 A 在北京登录 10 分钟后账号 B 在杭州登录"
  → 会给淘宝/腾讯的关联账户检测提供信号

每次操作前:
  ① 调 DataProbe /api/proxy/next → 获取区域一致的 IP
  ② 配置代理
  ③ 启动浏览器
  ④ 通过 WebRTC 检测确认 IP 未泄漏
  ⑤ 开始操作
```

---

## 六、实现路线

```
V1 — 基础自动化框架（2-3 周，Python 独立项目）
  ├─ undetected-chromedriver + stealth patches
  ├─ Cookie/Token 注入
  ├─ 基本页面导航和元素定位
  ├─ DataProbe API 调用（验证码/行为）
  ├─ 代理配置
  └─ 支付链接 DOM 提取

V2 — 深度对抗（4-6 周）
  ├─ TLS 指纹伪装（装 OpenSSL + DataProbe TlsProxy 代理）
  ├─ canvas/WebGL 指纹自定义
  ├─ HTTP/2 SETTINGS 参数模拟
  ├─ 鼠标轨迹随机化（多层噪声叠加）
  ├─ 住宅代理自动轮换
  └─ 自动登录（含短信验证码）

V3 — 全自动支付链路（6-8 周）
  ├─ 指定金额商品自动匹配
  ├─ 支付触发 + 二维码/链接捕获
  ├─ 多渠道捕获融合（DOM + TLS MITM）
  ├─ 区域 IP 一致性保障
  └─ 风控异常检测与自动规避
```

---

## 七、DataProbe 需要新增的 API

```
当前已有的:
  ✅ POST /api/captcha/solve
  ✅ POST /api/sms/request
  ✅ GET  /api/behavior/next
  ✅ GET  /api/device/profile
  ✅ GET  /api/evidence

需要新增的:
  🔲 GET  /api/proxy/next?region=城市名 → 返回区域代理
  🔲 POST /api/session/token          → 将自动化捕获的数据注入 Session
```

**两个新增 API 都很轻量（各 ~20 行），需要时再加。**

---

## 八、关键结论

```
最难的三个问题:
 ① TLS 指纹伪装 — DataProbe 已有方案（装 OpenSSL 即可激活）
 ② 住宅 IP 一致性 — 需要购买代理服务，技术上是标准配置
 ③ 浏览器自动化检测绕过 — undetected-chromedriver 可解决 80%
    剩下 20%（TLS/HTTP2/IP）需要 DataProbe + 代理配合

整体判断:
  可行。但浏览器自动化本身不适合塞进 C# 内核。
  
  推荐架构:
    DataProbe (C#)     = 智能后端（验证码/短信/指纹/IP/解密）
    DataProbe-Auto (Python) = 浏览器自动化前端（Playwright + stealth）
    
  两个进程通过 localhost REST API 通信。
  不影响 DataProbe 内核的轻量和可拆卸性。
```
