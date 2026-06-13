#!/usr/bin/env python3
"""
DataProbe Auto — 浏览器自动化支付捕获脚本 (示例/骨架)
=======================================================

依赖: pip install undetected-chromedriver selenium requests

这个脚本展示了:
  1. 启动隐身 Chrome
  2. Cookie 注入登录
  3. 导航到支付页
  4. 捕获支付链接/二维码

实际使用时需要根据目标网站的具体 DOM 结构调整选择器。
"""

import json
import time
import requests
import logging

logging.basicConfig(level=logging.INFO, format="[DP-Auto] %(message)s")
log = logging.getLogger(__name__)

# ═══════════════════════ DataProbe API 地址 ═══════════════════════
DP_API = "http://localhost:18801"


# ═══════════════════════ 辅助函数 ═══════════════════════

def dp_get(path):
    """调用 DataProbe API"""
    r = requests.get(f"{DP_API}{path}", timeout=10)
    return r.json()

def dp_post(path, data):
    r = requests.post(f"{DP_API}{path}", json=data, timeout=30)
    return r.json()


# ═══════════════════════ 浏览器自动化 ═══════════════════════

def create_driver(proxy: dict = None):
    """
    创建隐身 Chrome 实例
    需要: pip install undetected-chromedriver
    """
    import undetected_chromedriver as uc

    options = uc.ChromeOptions()

    # 基本隐身选项
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--disable-infobars")
    options.add_argument("--window-size=1920,1080")

    # 禁用自动化标志
    options.add_argument("--disable-automation")

    # 代理配置
    if proxy:
        proxy_str = f'socks5://{proxy["host"]}:{proxy["port"]}'
        if proxy.get("username"):
            proxy_str = f'socks5://{proxy["username"]}:{proxy["password"]}@{proxy["host"]}:{proxy["port"]}'
        options.add_argument(f'--proxy-server={proxy_str}')
        log.info(f"Proxy: {proxy['host']}:{proxy['port']}")

    # 启动 Chrome（有界面模式，非无头）
    driver = uc.Chrome(options=options, headless=False, version_main=125)

    # 注入 stealth 补丁
    driver.execute_script("""
        // 覆盖 navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', { get: () => false });

        // 覆盖 chrome.runtime
        window.chrome = {
            runtime: { connect: () => {} }
        };

        // 修改 permissions
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (params) => (
            params.name === 'notifications'
                ? Promise.resolve({ state: 'prompt' })
                : originalQuery(params)
        );
    """)

    return driver


def inject_cookies(driver, cookies: list):
    """注入 Cookie 恢复登录态"""
    for cookie in cookies:
        driver.add_cookie(cookie)
    log.info(f"Injected {len(cookies)} cookies")


def wait_and_find(driver, selector: str, timeout: int = 10):
    """等待元素出现并返回"""
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.by import By
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
    )


def get_human_delay():
    """从 DataProbe 获取人类化操作延迟"""
    behavior = dp_get("/api/behavior/next")
    return behavior.get("delay_ms", 800) / 1000


def human_delay():
    """等待一个人类化的自然间隔"""
    time.sleep(get_human_delay())


# ═══════════════════════ 支付捕获核心流程 ═══════════════════════

def capture_payment_flow(
    target_url: str,
    product_selector: str,
    price_keyword: str,
    pay_button_selector: str,
    payment_output_selector: str,
    cookies: list = None,
    proxy: dict = None,
):
    """
    自动化支付捕获通用流程

    参数:
        target_url: 目标页面 URL
        product_selector: 商品列表选择器
        price_keyword: 价格过滤关键词
        pay_button_selector: 支付按钮选择器
        payment_output_selector: 支付码/链接显示元素选择器
        cookies: 登录 Cookie 列表
        proxy: 代理配置
    """
    driver = create_driver(proxy)

    try:
        # ── 第 1 步: 打开目标页 ──
        log.info(f"Navigating to {target_url}")
        driver.get(target_url)
        human_delay()

        # ── 第 2 步: 注入 Cookie（如提供）──
        if cookies:
            inject_cookies(driver, cookies)
            driver.get(target_url)  # 刷新使 Cookie 生效
            human_delay()

        # ── 第 3 步: 找到指定金额的商品 ──
        log.info(f"Looking for products matching: {price_keyword}")
        products = driver.find_elements("css selector", product_selector)
        for product in products:
            text = product.text
            if price_keyword in text:
                log.info(f"Found target product: {text[:60]}...")
                product.click()
                break
        human_delay()

        # ── 第 4 步: 点击支付按钮 ──
        log.info("Looking for payment button...")
        pay_btn = wait_and_find(driver, pay_button_selector)
        pay_btn.click()
        human_delay()

        # ── 第 5 步: 捕获支付链接/二维码 ──
        log.info("Capturing payment output...")

        # 方案 A: DOM 提取
        payment_el = wait_and_find(driver, payment_output_selector, timeout=15)
        payment_data = payment_el.get_attribute("href") or payment_el.text or payment_el.get_attribute("src")

        # 方案 B: 截图备用
        screenshot = driver.get_screenshot_as_png()

        # 方案 C: DataProbe TlsProxy 捕获的数据
        dp_evidence = dp_get("/api/evidence")

        result = {
            "payment_data": payment_data,
            "screenshot_size": len(screenshot),
            "dp_evidence_count": dp_evidence.get("total", 0),
            "dp_evidence": dp_evidence.get("items", []),
        }

        log.info(f"✅ Payment captured!")
        log.info(f"   DOM data: {payment_data}")
        log.info(f"   DP evidence: {dp_evidence.get('total', 0)} items")

        return result

    finally:
        # 保留浏览器窗口方便用户查看
        input("\n按 Enter 关闭浏览器...")
        driver.quit()


# ═══════════════════════ 示例: 淘宝支付 ═══════════════════════

def taobao_payment_example():
    """淘宝支付捕获示例"""

    # 配置
    config = {
        "target_url": "https://www.taobao.com",
        "product_selector": ".item-card",
        "price_keyword": "¥99",
        "pay_button_selector": ".pay-btn",
        "payment_output_selector": ".qrcode-img, .payment-link",
        "cookies": None,  # 需要提供登录 Cookie
        "proxy": {
            "host": "your-residential-proxy.com",
            "port": 1080,
        }
    }

    return capture_payment_flow(**config)


# ═══════════════════════ 主入口 ═══════════════════════

if __name__ == "__main__":
    print("=== DataProbe Auto — 支付捕获脚本 ===")
    print(f"DataProbe API: {DP_API}")

    # 测试 DataProbe 连通性
    try:
        status = dp_get("/status")
        print(f"DataProbe status: {status.get('status')}")
    except Exception as e:
        print(f"Cannot connect to DataProbe: {e}")
        print("Start DataProbe first: dotnet run --project src/DataProbe.Api")
        exit(1)

    print("\n这个脚本是框架示例，需要针对具体目标调整选择器。")
    print("参考 docs/browser-automation-design.md 了解完整架构。")
