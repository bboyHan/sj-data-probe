"""页面编排器 — 导航/交互/支付捕获流程控制。"""

from __future__ import annotations

import logging
from typing import Callable
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from dp_auto.dp_client import DataProbeClient

log = logging.getLogger("dp-auto.orchestrator")


class PaymentCaptureResult:
    """支付捕获结果"""

    def __init__(self):
        self.dom_data: str | None = None
        self.screenshot: bytes | None = None
        self.dp_evidence: list[dict] = []
        self.success: bool = False


class Orchestrator:
    """页面操作编排器"""

    def __init__(self, driver, dp_client: DataProbeClient | None = None):
        self.driver = driver
        self.dp = dp_client or DataProbeClient()

    # ── 导航 ──

    def goto(self, url: str, wait_selector: str | None = None, timeout: int = 15):
        """导航到页面并等待加载完成"""
        log.info("Navigating to: %s", url)
        self.driver.get(url)

        if wait_selector:
            self.wait_for(wait_selector, timeout)

        self.dp.human_delay()

    def wait_for(self, selector: str, timeout: int = 10):
        """等待元素出现"""
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, selector))
        )

    # ── Cookie/Token 注入 ──

    def inject_cookies(self, cookies: list[dict]):
        """注入 Cookie 恢复登录态"""
        for cookie in cookies:
            try:
                self.driver.add_cookie(cookie)
            except Exception as e:
                log.warning("Cookie inject failed: %s", e)
        log.info("Injected %d cookies", len(cookies))

    def inject_local_storage(self, key: str, value: str):
        """注入 localStorage Token"""
        self.driver.execute_script(
            f"window.localStorage.setItem('{key}', '{value}')"
        )

    # ── 交互 ──

    def click(self, selector: str, timeout: int = 10):
        """点击元素，带人类化延迟"""
        el = self.wait_for(selector, timeout)
        self.dp.human_delay()
        el.click()
        log.info("Clicked: %s", selector)

    def fill(self, selector: str, text: str):
        """填充表单字段"""
        el = self.wait_for(selector)
        el.clear()
        # 逐字符输入，模拟真人
        for char in text:
            el.send_keys(char)
            import time
            time.sleep(0.05 + __import__("random").random() * 0.1)

    def scroll_to(self, selector: str):
        """滚动到元素位置"""
        el = self.wait_for(selector)
        self.driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'})", el)
        self.dp.human_delay()

    # ── 支付捕获 ──

    def capture_payment(
        self,
        pay_button_selector: str,
        output_selector: str,
    ) -> PaymentCaptureResult:
        """触发支付并捕获结果"""
        result = PaymentCaptureResult()

        # 点击支付按钮
        log.info("Clicking payment button: %s", pay_button_selector)
        self.click(pay_button_selector)
        self.dp.human_delay()

        # 等待支付码/链接出现
        log.info("Waiting for payment output: %s", output_selector)
        try:
            el = self.wait_for(output_selector, timeout=15)
            # 尝试多种属性获取支付数据
            result.dom_data = (
                el.get_attribute("href")
                or el.get_attribute("src")
                or el.get_attribute("data-url")
                or el.text
            )
            log.info("DOM payment data: %s", result.dom_data[:100] if result.dom_data else "None")
        except Exception as e:
            log.warning("Payment element not found: %s", e)

        # 截图备用
        try:
            result.screenshot = self.driver.get_screenshot_as_png()
            log.info("Screenshot captured: %d bytes", len(result.screenshot))
        except Exception as e:
            log.warning("Screenshot failed: %s", e)

        # 从 DataProbe 获取被动捕获的数据
        result.dp_evidence = self.dp.get_evidence()
        log.info("DP evidence: %d items", len(result.dp_evidence))

        # 判断成功
        result.success = bool(result.dom_data) or bool(result.dp_evidence)

        return result
