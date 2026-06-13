"""IP 代理管理器 — 区域一致的住宅 IP 池。"""

from __future__ import annotations

import json
import random
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("dp-auto.proxy")


@dataclass
class ProxyConfig:
    """代理配置"""
    type: str = "socks5"  # socks5 / http / https
    host: str = ""
    port: int = 1080
    username: str = ""
    password: str = ""
    region: str = ""  # 城市/地区
    provider: str = "manual"


class ProxyManager:
    """代理管理器 — 维护区域一致的 IP 池"""

    def __init__(self, config_file: str | None = None):
        self._proxies: list[ProxyConfig] = []
        self._current: ProxyConfig | None = None
        self._used_regions: set[str] = set()

        if config_file:
            self.load(config_file)

    def load(self, config_file: str):
        """从 JSON 文件加载代理配置"""
        try:
            with open(config_file) as f:
                data = json.load(f)
            for item in data.get("proxies", []):
                self._proxies.append(ProxyConfig(**item))
            log.info("Loaded %d proxies from %s", len(self._proxies), config_file)
        except Exception as e:
            log.error("Failed to load proxies: %s", e)

    def add(self, proxy: ProxyConfig):
        self._proxies.append(proxy)

    def get_for_region(self, region: str) -> ProxyConfig | None:
        """获取指定区域的代理（优先选择之前没用过的 IP）"""
        candidates = [p for p in self._proxies if p.region == region]
        if not candidates:
            log.warning("No proxy for region: %s", region)
            return None

        # 优先从未使用过的
        unused = [p for p in candidates if (p.host, p.port) not in self._used_regions]
        if unused:
            chosen = random.choice(unused)
        else:
            chosen = random.choice(candidates)

        self._current = chosen
        self._used_regions.add((chosen.host, chosen.port))
        log.info("Proxy for %s: %s:%d", region, chosen.host, chosen.port)
        return chosen

    def get_current(self) -> ProxyConfig | None:
        return self._current

    def rotate(self) -> ProxyConfig | None:
        """轮换到同区域的另一个代理"""
        if not self._current:
            return None
        return self.get_for_region(self._current.region)

    def to_selenium_options(self, proxy: ProxyConfig | None = None) -> dict:
        """生成 Selenium 代理配置"""
        p = proxy or self._current
        if not p:
            return {}

        proxy_str = f"{p.host}:{p.port}"
        if p.username:
            proxy_str = f"{p.username}:{p.password}@{proxy_str}"

        return {
            "proxyType": "manual",
            "httpProxy": proxy_str,
            "sslProxy": proxy_str,
            "socksProxy": proxy_str if p.type == "socks5" else None,
            "socksVersion": 5 if p.type == "socks5" else None,
        }
