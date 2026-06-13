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


class BrowserLauncher:
    """隐身 Chrome 启动器"""

    def __init__(self, config: BrowserConfig | None = None):
        self.config = config or BrowserConfig()
        self.driver = None

    def start(self) -> Any:
        """启动隐身 Chrome 实例"""
        import undetected_chromedriver as uc

        options = uc.ChromeOptions()

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
        version_args = {}
        if self.config.chrome_version:
            version_args["version_main"] = self.config.chrome_version

        self.driver = uc.Chrome(
            options=options,
            headless=self.config.headless,
            **version_args,
        )

        # ── 应用 stealth 补丁 ──
        try:
            apply_stealth(self.driver)
            log.info("Stealth patches applied")
        except Exception as e:
            log.warning("Stealth apply failed (page may not be loaded yet): %s", e)

        log.info("Browser started (PID: %s)", self.driver.service.process.pid if hasattr(self.driver.service, 'process') else '?')
        return self.driver

    def stop(self):
        """关闭浏览器"""
        if self.driver:
            try:
                self.driver.quit()
                log.info("Browser stopped")
            except Exception as e:
                log.warning("Error stopping browser: %s", e)
