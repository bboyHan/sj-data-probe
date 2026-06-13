"""命令行入口 — dp-auto 的启动和配置。"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from dp_auto.dp_client import DataProbeClient

logging.basicConfig(
    level=logging.INFO,
    format="[DP-Auto] %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("dp-auto")


def cmd_check(args):
    """检查 DataProbe 连通性和环境"""
    dp = DataProbeClient()
    if dp.is_healthy():
        print(f"[OK] DataProbe: {dp.base_url}")
        tls = dp.passive_tls_status()
        print(f"  Passive TLS: {tls.get('keys_captured', 0)} keys, "
              f"providers: {tls.get('providers', [])}")
    else:
        print(f"[FAIL] DataProbe: {dp.base_url} (start DataProbe first)")
        print("  dotnet run --project src/DataProbe.Api")

    try:
        import undetected_chromedriver as uc
        print(f"[OK] undetected-chromedriver: {uc.__version__}")
    except ImportError:
        print("[FAIL] undetected-chromedriver (pip install undetected-chromedriver)")

    import shutil
    chrome = shutil.which("chrome") or shutil.which("chromium")
    if chrome:
        print(f"[OK] Chrome: {chrome}")
    else:
        print("[FAIL] Chrome not found")

    return 0


def cmd_launch(args):
    """启动隐身浏览器并打开目标页面"""
    from dp_auto.launcher import BrowserLauncher, BrowserConfig
    from dp_auto.proxy_manager import ProxyManager
    config = BrowserConfig(
        window_size=args.window_size,
        headless=args.headless,
        data_dir=args.user_data_dir,
        chrome_version=args.chrome_version,
        driver_version=getattr(args, 'driver_version', None),
    )

    if args.proxy_config:
        pm = ProxyManager(args.proxy_config)
        proxy = pm.get_for_region(args.region) if args.region else pm.get_current()
        config.proxy = proxy.to_selenium_options() if proxy else None
        print(proxy, config.proxy)

    launcher = BrowserLauncher(config)
    driver = launcher.start()

    try:
        if args.url:
            driver.get(args.url)
            log.info("Opened: %s", args.url)
            log.info("Stealth applied, browser is ready. Press Ctrl+C to quit.")

        # 保持浏览器打开，等待用户操作
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    finally:
        launcher.stop()

    return 0


def cmd_capture(args):
    """自动捕获支付链接"""
    from dp_auto.launcher import BrowserLauncher, BrowserConfig
    from dp_auto.orchestrator import Orchestrator

    dp = DataProbeClient()
    if not dp.is_healthy():
        log.error("DataProbe not running. Start it first.")
        return 1

    config = BrowserConfig(
        window_size=args.window_size,
        headless=args.headless,
        data_dir=args.user_data_dir,
    )
    launcher = BrowserLauncher(config)
    driver = launcher.start()

    try:
        orch = Orchestrator(driver, dp)

        # 导航到目标页
        orch.goto(args.url, timeout=20)
        log.info("目标页面已加载")

        # 用户手动操作或等待自动化流程
        if args.auto:
            log.info("自动模式: 点击 %s", args.pay_button)
            result = orch.capture_payment(
                pay_button_selector=args.pay_button,
                output_selector=args.payment_output,
            )

            if result.success:
                print(f"\n[OK] 支付链接: {result.dom_data}")
                print(f"   截图: {len(result.screenshot) if result.screenshot else 0} bytes")
                print(f"   DP 证据: {len(result.dp_evidence)} 条")

                # 注入到 DataProbe Session
                if result.dom_data:
                    dp.inject_evidence(result.dom_data, "url", "dp-auto")
            else:
                print("\n[FAIL] 支付捕获失败")
        else:
            log.info("手动模式: 浏览器已打开，请手动操作")

            import time
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    finally:
        launcher.stop()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="DataProbe Auto — 浏览器自动化支付捕获引擎",
    )
    parser.add_argument("--dp-api", default="http://localhost:18801", help="DataProbe API 地址")

    sub = parser.add_subparsers(dest="command", required=True)

    # check 子命令
    p_check = sub.add_parser("check", help="检查环境和连通性")

    # launch 子命令
    p_launch = sub.add_parser("launch", help="启动隐身浏览器")
    p_launch.add_argument("--url", help="要打开的页面 URL")
    p_launch.add_argument("--window-size", default="1920,1080")
    p_launch.add_argument("--headless", action="store_true")
    p_launch.add_argument("--user-data-dir", help="Chrome 用户数据目录")
    p_launch.add_argument("--proxy-config", help="代理配置文件路径")
    p_launch.add_argument("--region", help="代理区域（城市）")
    p_launch.add_argument("--chrome-version", type=int, help="Chrome 主版本号（默认自动检测）")
    p_launch.add_argument("--driver-version", type=int, help="chromedriver 版本号（默认自动匹配 Chrome）")

    # capture 子命令
    p_capture = sub.add_parser("capture", help="捕获支付链接")
    p_capture.add_argument("url", help="目标页面 URL")
    p_capture.add_argument("--auto", action="store_true", help="自动模式（自动点击支付）")
    p_capture.add_argument("--pay-button", default=".pay-btn,.payment-btn,[data-pay]", help="支付按钮选择器")
    p_capture.add_argument("--payment-output", default=".qrcode,.qrcode-img,[class*=qrcode],.payment-link", help="支付码/链接选择器")
    p_capture.add_argument("--window-size", default="1920,1080")
    p_capture.add_argument("--headless", action="store_true")
    p_capture.add_argument("--user-data-dir", help="Chrome 用户数据目录")

    args = parser.parse_args()
    commands = {
        "check": cmd_check,
        "launch": cmd_launch,
        "capture": cmd_capture,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
