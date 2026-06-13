"""DataProbe API 客户端 — 与 C# 引擎通信的桥梁。"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass
from typing import Any
import requests

log = logging.getLogger("dp-auto.client")

DEFAULT_API = "http://localhost:18801"


@dataclass
class DeviceProfile:
    model_id: str
    manufacturer: str
    brand: str
    os: str
    resolution: str
    ttl: int = 64


class DataProbeClient:
    """DataProbe C# 引擎的 HTTP 客户端"""

    def __init__(self, base_url: str = DEFAULT_API):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.timeout = (5, 30)

    # ── 健康检查 ──

    def is_healthy(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/status", timeout=3)
            return r.ok
        except requests.RequestException:
            return False

    # ── 验证码求解 ──

    def solve_captcha(self, image_base64: str) -> str | None:
        """提交验证码图片，返回识别结果"""
        try:
            r = self.session.post(
                f"{self.base_url}/api/decode",
                json={"data": image_base64},
                timeout=30,
            )
            if r.ok:
                data = r.json()
                decodings = data.get("decodings", {})
                # 优先返回 base64 解码结果
                return decodings.get("base64") or decodings.get("json")
        except requests.RequestException:
            pass
        return None

    # ── 行为仿真 ──

    def get_human_delay(self) -> float:
        """从引擎获取人类化操作延迟（秒）"""
        try:
            r = self.session.get(f"{self.base_url}/api/behavior/next", timeout=5)
            if r.ok:
                return r.json().get("delay_ms", 800) / 1000
        except requests.RequestException:
            pass
        return 0.8

    def human_delay(self):
        """等待一个仿真操作间隔"""
        time.sleep(self.get_human_delay())

    # ── 设备指纹 ──

    def get_device_profile(self, platform: str = "pc") -> DeviceProfile:
        """获取与当前操作环境一致的设备指纹"""
        try:
            r = self.session.get(
                f"{self.base_url}/api/device/profile",
                params={"platform": platform},
                timeout=5,
            )
            if r.ok:
                data = r.json()
                return DeviceProfile(**data)
        except requests.RequestException:
            pass
        return DeviceProfile(
            model_id="Windows PC",
            manufacturer="Generic",
            brand="Generic",
            os="Windows 11",
            resolution="1920x1080",
            ttl=128,
        )

    # ── 证据提取 ──

    def get_evidence(self) -> list[dict]:
        """获取引擎已提取的结构化数据"""
        try:
            r = self.session.get(f"{self.base_url}/api/evidence", timeout=10)
            if r.ok:
                return r.json().get("items", [])
        except requests.RequestException:
            pass
        return []

    # ── 数据注入 ──

    def inject_evidence(self, value: str, data_type: str = "url", source: str = "dp-auto"):
        """将自动化捕获的数据注入到引擎的 Session 中"""
        try:
            r = self.session.post(
                f"{self.base_url}/api/capture/ingest",
                json={
                    "type": data_type,
                    "value": value,
                    "platform": source,
                    "source": source,
                },
                timeout=5,
            )
            return r.ok
        except requests.RequestException:
            return False

    # ── 被动 TLS 状态 ──

    def passive_tls_status(self) -> dict:
        try:
            r = self.session.get(f"{self.base_url}/api/passive-tls/status", timeout=5)
            if r.ok:
                return r.json()
        except requests.RequestException:
            pass
        return {"keys_captured": 0}
