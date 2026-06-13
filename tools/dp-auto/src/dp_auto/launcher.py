"""浏览器启动器 — 启动隐身 Chrome 并应用反检测补丁。"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from dp_auto.stealth import apply_stealth

log = logging.getLogger("dp-auto.launcher")


@dataclass
class BrowserConfig:
    """浏览器启动配置"""

    window_size: str = "1920,1080"
    headless: bool = False
    proxy: dict | None = None
    disable_images: bool = False
    data_dir: str | None = None  # 使用固定的用户数据目录（保持 Cookie）
    chrome_version: int | None = None  # 指定 Chrome 主版本
    driver_version: int | None = None  # 指定 chromedriver 版本（不匹配时覆盖）


class BrowserLauncher:
    """隐身 Chrome 启动器"""

    def __init__(self, config: BrowserConfig | None = None):
        self.config = config or BrowserConfig()
        self.driver = None

    @staticmethod
    def _detect_chrome_version() -> int | None:
        """通过 PowerShell 检测 Chrome 主版本号"""
        import subprocess, re
        try:
            script = "(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe').VersionInfo.FileVersion"
            result = subprocess.run(
                ["powershell", "-Command", script],
                capture_output=True, text=True, timeout=5
            )
            ver = result.stdout.strip()
            m = re.search(r"(\d+)\.", ver)
            if m:
                main_ver = int(m.group(1))
                log.info("Detected Chrome version: %s (main: %d)", ver, main_ver)
                return main_ver
        except Exception as e:
            log.warning("Chrome detection failed: %s", e)
        return None

    def start(self) -> Any:
        """启动隐身 Chrome 实例"""
        import undetected_chromedriver as uc

        # 自动检测 Chrome 版本
        chrome_main_ver = self.config.chrome_version or self._detect_chrome_version()
        if chrome_main_ver:
            log.info("Using Chrome main version: %d", chrome_main_ver)

        options = uc.ChromeOptions()
        # 指定 Chrome 二进制路径
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Users\1\AppData\Local\Google\Chrome\Application\chrome.exe",
        ]
        for p in chrome_paths:
            import os
            if os.path.exists(p):
                options.binary_location = p
                log.info("Chrome binary: %s", p)
                break

        # ── 基础隐身选项 ──
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")
        options.add_argument("--disable-infobars")
        options.add_argument(f"--window-size={self.config.window_size}")
        options.add_argument("--disable-sync")

        # ── 禁用自动化标志 ──
        options.add_argument("--disable-automation")

        # ── 使用固定的用户数据目录（保持 Cookie 和登录态）──
        if self.config.data_dir:
            options.add_argument(f"--user-data-dir={self.config.data_dir}")

        # ── 禁用图片加载（加快速度，降低资源消耗）──
        if self.config.disable_images:
            prefs = {"profile.managed_default_content_settings.images": 2}
            options.add_experimental_option("prefs", prefs)

        # ── 代理配置 ──
        if self.config.proxy:
            p = self.config.proxy
            proxy_str = f"{p['type']}://{p['host']}:{p['port']}"
            if p.get("username"):
                proxy_str = (
                    f"{p['type']}://{p['username']}:{p['password']}"
                    f"@{p['host']}:{p['port']}"
                )
            options.add_argument(f"--proxy-server={proxy_str}")
            log.info("Proxy: %s:%s", p["host"], p["port"])

        # ── 启动浏览器 ──
        # 先尝试用 undetected_chromedriver 自动匹配
        driver_args = {"options": options, "headless": self.config.headless}
        if self.config.driver_version:
            # 用户强制指定 chromedriver 版本（绕过 Chrome 自动检测）
            driver_args["version_main"] = self.config.driver_version
        elif chrome_main_ver and chrome_main_ver >= 149:
            # Chrome 149+ (Canary/Dev) 可能没有对应的 chromedriver
            # 降级到 148，让 undetected_chromedriver 的补丁机制处理
            driver_args["version_main"] = chrome_main_ver - 1
            log.info("Chrome %d is very new, trying chromedriver %d", chrome_main_ver, chrome_main_ver - 1)

        try:
            self.driver = uc.Chrome(**driver_args)
        except Exception as e:
            log.warning("undetected_chromedriver failed: %s", e)
            log.info("Falling back to standard selenium + webdriver-manager...")
            self.driver = self._fallback_start(options)
            if not self.driver:
                raise

        # ── 应用 stealth 补丁 ──
        try:
            apply_stealth(self.driver)
            log.info("Stealth patches applied")
        except Exception as e:
            log.warning("Stealth apply failed (page may not be loaded yet): %s", e)

        log.info("Browser started (PID: %s)", self.driver.service.process.pid if hasattr(self.driver.service, 'process') else '?')
        return self.driver

    def _fallback_start(self, options) -> Any | None:
        """回退方案: 用 webdriver-manager（自动匹配 Chrome 版本）"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from webdriver_manager.chrome import ChromeDriverManager
            log.info("Using webdriver-manager to get correct chromedriver...")
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            log.info("Fallback browser started with webdriver-manager")
            return driver
        except Exception as e:
            log.error("Fallback failed: %s", e)
        return None

    def stop(self):
        """关闭浏览器"""
        if self.driver:
            try:
                self.driver.quit()
                log.info("Browser stopped")
            except Exception as e:
                log.warning("Error stopping browser: %s", e)
