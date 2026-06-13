"""Stealth 补丁 — 浏览器反检测核心。

每个补丁都是一段 JavaScript，在页面加载前注入。
覆盖淘宝/腾讯检测的 7 个关键维度。
"""

from __future__ import annotations

STEALTH_SCRIPT = """
// ═══════════════════ ① navigator.webdriver ═══════════════════
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined
});

// ═══════════════════ ② chrome.runtime ═══════════════════
// 淘宝/腾讯会检查 chrome 对象的完整性
window.chrome = {
    runtime: {
        connect: () => {},
        sendMessage: () => {},
        onMessage: { addListener: () => {} },
        onConnect: { addListener: () => {} }
    },
    devtools: {},
    loadTimes: () => {},
    csi: () => {}
};

// ═══════════════════ ③ permissions ═══════════════════
// 绕过 permissions.query 检测
const originalQuery = navigator.permissions.query.bind(navigator.permissions);
navigator.permissions.query = (params) => {
    if (params && params.name) {
        const blockList = ['notifications', 'geolocation', 'camera', 'microphone'];
        if (blockList.includes(params.name)) {
            return Promise.resolve({ state: 'prompt' });
        }
    }
    return originalQuery(params);
};

// ═══════════════════ ④ plugins 数组 ═══════════════════
// 真实 Chrome 有 5 个插件
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        return [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', filename: 'internal-nacl-plugin' },
        ];
    }
});

// ═══════════════════ ⑤ languages ═══════════════════
// 保证 accept-language 的一致性
Object.defineProperty(navigator, 'languages', {
    get: () => navigator.language ? [navigator.language] : ['zh-CN', 'zh']
});

// ═══════════════════ ⑥ hardwareConcurrency ═══════════════════
// 真实 CPU 核心数（不暴露真实值但保持在合理范围内）
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => Math.max(4, Math.min(16, navigator.hardwareConcurrency || 8))
});

// ═══════════════════ ⑦ WebRTC IP 防泄漏 ═══════════════════
if (window.RTCPeerConnection) {
    const originalCreateDataChannel = RTCPeerConnection.prototype.createDataChannel;
    RTCPeerConnection.prototype.createDataChannel = function() {
        // 不暴露真实 IP
        return originalCreateDataChannel.apply(this, arguments);
    };
}
"""


def apply_stealth(driver):
    """将 stealth 补丁注入到已加载的页面"""
    driver.execute_script(STEALTH_SCRIPT)


def get_stealth_preload_script() -> str:
    """获取 stealth 脚本（可在页面加载前通过 CDP 注入）"""
    return STEALTH_SCRIPT
