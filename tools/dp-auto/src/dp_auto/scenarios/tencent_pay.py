"""腾讯支付登录 + 支付链路捕获场景。"""

from __future__ import annotations

import logging
import time
import os
import sys

# 确保能找到 dp-auto 包
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dp_auto.dp_client import DataProbeClient
from dp_auto.launcher import BrowserLauncher, BrowserConfig
from dp_auto.orchestrator import Orchestrator

log = logging.getLogger("dp-auto.tencent")


def run(launcher: BrowserLauncher, orch: Orchestrator, dp: DataProbeClient):
    """腾讯支付链路捕获流程"""

    # ── 第 1 步: 打开 pay.qq.com ──
    log.info("=== Step 1: Opening pay.qq.com ===")
    orch.goto("https://pay.qq.com/", timeout=20)
    time.sleep(3)

    # 截图确认页面加载状态
    screenshot = launcher.driver.get_screenshot_as_png()
    log.info("Page loaded, screenshot: %d bytes", len(screenshot))

    # ── 第 2 步: 点击登录入口 ──
    log.info("=== Step 2: Looking for login button ===")
    login_selectors = [
        "a[href*='login']",
        "a[class*='login']",
        "button[class*='login']",
        ".login-btn",
        "#login",
        "//a[contains(text(), '登录')]",
        "//span[contains(text(), '登录')]",
    ]
    clicked = False
    for selector in login_selectors:
        try:
            if selector.startswith("//"):
                from selenium.webdriver.common.by import By
                el = launcher.driver.find_element(By.XPATH, selector)
            else:
                el = launcher.driver.find_element("css selector", selector)
            if el and el.is_displayed():
                log.info("Found login element: %s", selector)
                el.click()
                clicked = True
                time.sleep(3)
                break
        except Exception:
            continue

    if not clicked:
        # 如果找不到登录按钮，直接导航到登录页面
        log.info("Login button not found, navigating to login page directly")
        orch.goto("https://pay.qq.com/login/", timeout=15)

    # ── 第 3 步: 等待扫码或账号密码登录 ──
    log.info("=== Step 3: Waiting for login page ===")
    time.sleep(3)

    # 检测页面类型: 扫码 or 密码登录
    page_text = launcher.driver.page_source
    if "qrcode" in page_text or "二维码" in page_text:
        log.info("QR code login page detected")
        # 截图保存二维码
        qr = launcher.driver.get_screenshot_as_png()
        with open("tencent_qr_login.png", "wb") as f:
            f.write(qr)
        log.info("QR code screenshot saved to tencent_qr_login.png")
        log.info(">> Please scan the QR code with your phone to login <<")
    else:
        log.info("Account/password login page detected")
        # 尝试找到账号密码输入框
        try:
            username_input = launcher.driver.find_element(
                "css selector", "input[type='text'], input[name='uin'], input[placeholder*='账号'], input[placeholder*='QQ']"
            )
            password_input = launcher.driver.find_element(
                "css selector", "input[type='password'], input[placeholder*='密码']"
            )
            log.info("Found username/password inputs")
            # 由用户手动输入或通过 DataProbe 提供的凭证填充
        except Exception:
            log.info("Could not find login form, please login manually in the browser")

    # ── 第 4 步: 等待登录完成 ──
    log.info("=== Step 4: Waiting for login completion ===")
    log.info("Please complete login in the browser window...")
    log.info("DataProbe SSLKEYLOGFILE is capturing TLS keys in the background")

    # 等待用户完成登录（最多 120 秒）
    for i in range(120):
        time.sleep(1)
        # 检测是否登录成功（URL 变化或页面出现特定元素）
        current_url = launcher.driver.current_url
        if "login" not in current_url.lower() or "passport" not in current_url.lower():
            if "pay.qq.com" in current_url and "login" not in current_url.lower():
                log.info("Login detected! Current URL: %s", current_url)
                break

    # ── 第 5 步: 检查捕获的数据 ──
    log.info("=== Step 5: Checking captured data ===")
    evidence = dp.get_evidence()
    log.info("DataProbe captured %d evidence items", len(evidence))
    for e in evidence[:10]:
        log.info("  [%s] %s", e.get("type", "?"), e.get("value", "")[:80])

    # 检查 SSLKEYLOGFILE
    tls = dp.passive_tls_status()
    log.info("Passive TLS keys captured: %d", tls.get("keys_captured", 0))

    # ── 保持浏览器打开，等待用户探索 ──
    log.info("=== Browser is ready for further operations ===")
    log.info("You can now browse payment pages in the same window.")


def main():
    logging.basicConfig(level=logging.INFO, format="[DP] %(message)s")
    dp = DataProbeClient()

    if not dp.is_healthy():
        log.error("DataProbe not running")
        return 1

    log.info("Starting Tencent Pay flow...")
    launcher = BrowserLauncher(BrowserConfig(window_size="1920,1080"))
    driver = launcher.start()
    orch = Orchestrator(driver, dp)

    try:
        run(launcher, orch, dp)
        log.info("Flow completed. Browser stays open for further use.")
        input("\nPress Enter to close browser...")
    finally:
        launcher.stop()

    return 0


if __name__ == "__main__":
    exit(main())
