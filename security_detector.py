#!/usr/bin/env python3
"""
Universal Security Detector — Python Controller
Drives the Frida JS script and renders a rich terminal dashboard.

Requirements:
    pip install frida frida-tools rich

Usage:
    python3 security_detector.py -p com.target.app
    python3 security_detector.py -p com.target.app --bypass
    python3 security_detector.py -p com.target.app --host 127.0.0.1 --port 27042
    python3 security_detector.py --list-apps
"""

import frida
import json
import sys
import time
import argparse
import signal
import os
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[!] Install 'rich' for beautiful output: pip install rich")

console = Console() if RICH_AVAILABLE else None

SCRIPT_PATH = Path(__file__).parent / "universal_security_detector.js"
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "magenta",
    "LOW":      "cyan",
    "INFO":     "blue",
}
SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️ ",
    "MEDIUM":   "🔔",
    "LOW":      "ℹ️ ",
    "INFO":     "📋",
}

class SecurityDetector:
    def __init__(self, args):
        self.args = args
        self.device = None
        self.session = None
        self.script = None
        self.report = {}
        self.start_time = datetime.now()
        self.message_count = 0

    # ── Device / Session Setup ─────────────────────────────────────────────────

    def get_device(self):
        if self.args.host:
            dm = frida.get_device_manager()
            self.device = dm.add_remote_device(f"{self.args.host}:{self.args.port}")
        elif self.args.usb:
            self.device = frida.get_usb_device(timeout=10)
        else:
            self.device = frida.get_local_device()
        return self.device

    def list_apps(self):
        device = self.get_device()
        apps = device.enumerate_applications()
        if RICH_AVAILABLE:
            table = Table(title="Installed Applications", box=box.ROUNDED)
            table.add_column("PID",        style="cyan",  width=8)
            table.add_column("Package",    style="green", width=50)
            table.add_column("Name",       style="white", width=30)
            table.add_column("Running",    style="yellow",width=10)
            for app in sorted(apps, key=lambda a: a.identifier):
                table.add_row(
                    str(app.pid) if app.pid else "–",
                    app.identifier,
                    app.name,
                    "✓" if app.pid else ""
                )
            console.print(table)
        else:
            for app in apps:
                print(f"  {app.pid or '–':>6}  {app.identifier:<50}  {app.name}")

    def attach_or_spawn(self):
        device = self.get_device()
        pkg = self.args.package

        if self.args.pid:
            print(f"[*] Attaching to PID {self.args.pid}...")
            self.session = device.attach(self.args.pid)
        else:
            # Check if already running
            running = [a for a in device.enumerate_applications() if a.identifier == pkg and a.pid]
            if running and not self.args.spawn:
                print(f"[*] Attaching to running process: {pkg} (PID {running[0].pid})")
                self.session = device.attach(running[0].pid)
            else:
                print(f"[*] Spawning: {pkg}")
                pid = device.spawn([pkg])
                self.session = device.attach(pid)
                device.resume(pid)

    def load_script(self):
        if not SCRIPT_PATH.exists():
            print(f"[!] Script not found: {SCRIPT_PATH}")
            sys.exit(1)
        js_src = SCRIPT_PATH.read_text(encoding="utf-8")

        # Inject config overrides
        js_src = js_src.replace(
            "verbose: true,",
            f"verbose: {str(not self.args.quiet).lower()},"
        ).replace(
            "bypassMode: false,",
            f"bypassMode: {str(self.args.bypass).lower()},"
        ).replace(
            "logToFile: false,",
            f"logToFile: {str(self.args.log_file).lower()},"
        )

        self.script = self.session.create_script(js_src)
        self.script.on("message", self.on_message)
        self.script.load()
        print("[✓] Script loaded successfully\n")

    # ── Message Handler ────────────────────────────────────────────────────────

    def on_message(self, message, data):
        self.message_count += 1
        if message["type"] == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "security_report":
                self.report = payload.get("data", {})
                if not self.args.quiet:
                    self.render_report()
        elif message["type"] == "error":
            if not self.args.quiet:
                print(f"[JS ERROR] {message.get('description', '')}")

    # ── Rich Dashboard ─────────────────────────────────────────────────────────

    def render_report(self):
        if not RICH_AVAILABLE or not self.report:
            return

        checks = self.report.get("checks", {})
        summary = self.report.get("summary", {})
        app_info = self.report.get("appInfo", {})

        detected = {k: v for k, v in checks.items() if v.get("detected")}
        not_detected = {k: v for k, v in checks.items() if not v.get("detected")}

        # ── Header Panel ──────────────────────────────────────────────────────
        risk = summary.get("riskLevel", "UNKNOWN")
        risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "MINIMAL": "bright_black"}.get(risk, "white")

        header_text = (
            f"[bold cyan]Package:[/]  {app_info.get('packageName', 'Unknown')}\n"
            f"[bold cyan]Platform:[/] {self.report.get('platform', 'unknown').upper()}\n"
            f"[bold cyan]Version:[/]  {app_info.get('versionName', '?')}  "
            f"[bold cyan]SDK:[/] {app_info.get('targetSdk', '?')}\n"
            f"[bold cyan]Risk:[/]     [{risk_color}]{risk}[/{risk_color}]  "
            f"[bold cyan]Checks:[/] {summary.get('detectedChecks', 0)}/{summary.get('totalChecks', 0)} detected"
        )
        console.print(Panel(header_text, title="🛡  Universal Security Detector", border_style="cyan"))

        # ── Severity Summary ──────────────────────────────────────────────────
        sev_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        sev_table.add_column("", style="bold")
        sev_table.add_column("", justify="center")
        sev_table.add_row("🚨 Critical", f"[bold red]{summary.get('criticalIssues', 0)}[/]")
        sev_table.add_row("⚠️  High",    f"[bold yellow]{summary.get('highIssues', 0)}[/]")
        sev_table.add_row("🔔 Medium",   f"[magenta]{summary.get('mediumIssues', 0)}[/]")
        sev_table.add_row("ℹ️  Low",     f"[cyan]{summary.get('lowIssues', 0)}[/]")
        console.print(sev_table)

        # ── Detected Checks ───────────────────────────────────────────────────
        if detected:
            det_table = Table(title="🔍 Detected Security Checks", box=box.ROUNDED, border_style="yellow")
            det_table.add_column("Check",    style="bold white", width=28)
            det_table.add_column("Severity", width=12)
            det_table.add_column("Method / Detail", style="dim", width=55)

            for key, check in detected.items():
                sev = check.get("severity", "INFO")
                methods = check.get("methods", [])
                first = methods[0] if methods else {}
                sev_label = f"[{SEVERITY_COLORS.get(sev, 'white')}]{SEVERITY_ICONS.get(sev,'')} {sev}[/]"
                detail = f"{first.get('method', '')} {('• ' + first.get('details','')) if first.get('details') else ''}"
                det_table.add_row(key.replace("_", " ").title(), sev_label, detail)
                # Sub-rows for additional method hits
                for m in methods[1:]:
                    extra = f"  ↳ {m.get('method', '')} {('• ' + m.get('details','')) if m.get('details') else ''}"
                    det_table.add_row("", "", f"[dim]{extra}[/]")

            console.print(det_table)

        # ── Not Detected ──────────────────────────────────────────────────────
        if not_detected:
            nd_text = "  ".join(
                f"[dim]{'✗'} {k.replace('_', ' ').title()}[/]"
                for k in not_detected
            )
            console.print(Panel(nd_text, title="Not Detected", border_style="bright_black"))

        # ── Save JSON ─────────────────────────────────────────────────────────
        if self.args.output:
            out_path = Path(self.args.output)
            out_path.write_text(json.dumps(self.report, indent=2))
            console.print(f"\n[green]✓ Report saved to {out_path}[/]")

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self):
        self.attach_or_spawn()
        self.load_script()

        if self.args.bypass:
            try:
                self.script.exports.enable_bypass()
                print("[✓] Bypass mode ENABLED")
            except Exception as e:
                print(f"[!] Could not enable bypass: {e}")

        print("[*] Monitoring... Press Ctrl+C to stop and print final report\n")
        print("[*] Interact with the app to trigger security checks\n")

        def handler(sig, frame):
            print("\n\n[*] Stopping — generating final report...")
            try:
                report = self.script.exports.get_report()
                self.report = report
                self.render_report()
                if self.args.output:
                    Path(self.args.output).write_text(json.dumps(report, indent=2))
            except Exception as e:
                print(f"[!] {e}")
            sys.exit(0)

        signal.signal(signal.SIGINT, handler)

        while True:
            time.sleep(1)


# ─── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Universal Security Detector — Frida Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-p", "--package",   help="Target package/bundle ID")
    parser.add_argument("--pid",   type=int, help="Attach to PID directly")
    parser.add_argument("--host",            help="Remote Frida server host")
    parser.add_argument("--port", type=int, default=27042, help="Remote Frida server port")
    parser.add_argument("-u", "--usb", action="store_true", default=True, help="Use USB device (default)")
    parser.add_argument("--spawn", action="store_true", help="Force spawn even if already running")
    parser.add_argument("--bypass", action="store_true", help="Auto-bypass detected security checks")
    parser.add_argument("--log-file", action="store_true", help="Log to /data/local/tmp/frida_security_report.json")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress verbose JS hook logs")
    parser.add_argument("--list-apps", action="store_true", help="List installed applications and exit")
    args = parser.parse_args()

    detector = SecurityDetector(args)

    if args.list_apps:
        detector.list_apps()
        return

    if not args.package and not args.pid:
        parser.error("Specify --package or --pid (use --list-apps to see available apps)")

    detector.run()


if __name__ == "__main__":
    main()
