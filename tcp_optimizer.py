#!/usr/bin/env python3
"""
TCP Optimizer for macOS
------------------------
An open-source GUI for inspecting and tuning macOS TCP/IP stack
parameters (sysctl net.inet.tcp.*) that can affect throughput and
latency on high-bandwidth connections.

Honest caveat baked into the app itself (see the Overview tab):
modern macOS already auto-tunes TCP send/receive buffers, so manual
tuning usually yields small, situational gains. The bigger wins on a
MacBook Air are almost always Wi‑Fi band/channel, DNS, or an upstream
bottleneck — the Diagnostics tab exists to help you tell the
difference before you start changing kernel parameters.

Requires: macOS, Python 3 with Tkinter (the python.org installer
bundles Tk; Homebrew's `python-tk` package also works), no third
party dependencies.

Run with:  python3 tcp_optimizer.py
"""

import ipaddress
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

APP_NAME = "TCP Optimizer"
LAUNCH_DAEMON_LABEL = "com.punksm4ck.tcpoptimizer"
LAUNCH_DAEMON_PATH = f"/Library/LaunchDaemons/{LAUNCH_DAEMON_LABEL}.plist"
SCRIPT_INSTALL_PATH = "/usr/local/sbin/tcpoptimizer-apply.sh"

# ---------------------------------------------------------------------------
# The sysctl keys this app understands. `safe_max`/`safe_min` are sanity
# bounds so a typo or slider mistake can't set something pathological.
# ---------------------------------------------------------------------------
TCP_KEYS = {
    "net.inet.tcp.sendspace": {
        "label": "Send buffer (bytes)", "min": 16384, "max": 4194304, "kind": "int",
        "help": "Initial per-socket send buffer. macOS autotunes above this once rfc1323 is on.",
    },
    "net.inet.tcp.recvspace": {
        "label": "Receive buffer (bytes)", "min": 16384, "max": 4194304, "kind": "int",
        "help": "Initial per-socket receive buffer.",
    },
    "net.inet.tcp.autorcvbufmax": {
        "label": "Auto-tune recv buffer max (bytes)", "min": 65536, "max": 16777216, "kind": "int",
        "help": "Ceiling for macOS's automatic receive-window growth on fast/long links.",
    },
    "net.inet.tcp.autosndbufmax": {
        "label": "Auto-tune send buffer max (bytes)", "min": 65536, "max": 16777216, "kind": "int",
        "help": "Ceiling for automatic send-window growth.",
    },
    "net.inet.tcp.win_scale_factor": {
        "label": "Window scale factor", "min": 0, "max": 8, "kind": "int",
        "help": "TCP window scaling exponent (RFC 1323). Higher allows a larger effective window on high-bandwidth-delay links. A nonzero value here means scaling is already on \u2014 recent macOS has no separate rfc1323 on/off knob.",
    },
    "net.inet.tcp.delayed_ack": {
        "label": "Delayed ACK mode", "min": 0, "max": 3, "kind": "int",
        "help": "0 disables delayed ACKs (lower latency, more ACK traffic); 3 is the macOS default heuristic.",
    },
    "net.inet.tcp.mssdflt": {
        "label": "Default MSS (bytes)", "min": 536, "max": 1460, "kind": "int",
        "help": "Default maximum segment size used before path MTU discovery completes.",
    },
}
# Keys that existed on older macOS releases but return "unknown oid" on
# current ones (confirmed via Overview -> unavailable, and via a failed
# sysctl -w). Kept out of TCP_KEYS/PRESETS entirely so they can't silently
# abort an apply chain; noted here for anyone diffing against older forks.
REMOVED_UNSUPPORTED_KEYS = ["net.inet.tcp.rfc1323", "net.inet.tcp.slowstart_flightsize"]

PRESETS = {
    "macOS Default (reset)": None,  # handled specially: reset via reboot-equivalent defaults
    "Balanced Gigabit": {
        "net.inet.tcp.sendspace": 262144,
        "net.inet.tcp.recvspace": 262144,
        "net.inet.tcp.autorcvbufmax": 4194304,
        "net.inet.tcp.autosndbufmax": 4194304,
        "net.inet.tcp.win_scale_factor": 6,
        "net.inet.tcp.delayed_ack": 3,
    },
    "High-Throughput / Large Downloads": {
        "net.inet.tcp.sendspace": 524288,
        "net.inet.tcp.recvspace": 524288,
        "net.inet.tcp.autorcvbufmax": 8388608,
        "net.inet.tcp.autosndbufmax": 8388608,
        "net.inet.tcp.win_scale_factor": 8,
        "net.inet.tcp.delayed_ack": 3,
    },
    "Low-Latency / Gaming": {
        "net.inet.tcp.sendspace": 131072,
        "net.inet.tcp.recvspace": 131072,
        "net.inet.tcp.autorcvbufmax": 2097152,
        "net.inet.tcp.autosndbufmax": 2097152,
        "net.inet.tcp.win_scale_factor": 4,
        "net.inet.tcp.delayed_ack": 0,
    },
}

# macOS's own defaults, used by the reset preset. These are the common
# out-of-the-box values on recent macOS releases; harmless if slightly off
# since they only matter until next reboot anyway.
MACOS_DEFAULTS = {
    "net.inet.tcp.sendspace": 131072,
    "net.inet.tcp.recvspace": 131072,
    "net.inet.tcp.autorcvbufmax": 2097152,
    "net.inet.tcp.autosndbufmax": 2097152,
    "net.inet.tcp.win_scale_factor": 3,
    "net.inet.tcp.delayed_ack": 3,
    "net.inet.tcp.mssdflt": 1460,
}


def is_macos():
    return platform.system() == "Darwin"


def run(cmd, timeout=15):
    """Run a non-privileged command, return (ok, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def run_privileged(shell_command):
    """
    Run a shell command as admin via macOS's native authorization dialog
    (osascript 'with administrator privileges'). No password is ever
    handled by this app directly.
    """
    escaped = shell_command.replace("\\", "\\\\").replace('"', '\\"')
    osa = f'do shell script "{escaped}" with administrator privileges'
    return run(["osascript", "-e", osa], timeout=30)


def apply_sysctl_values(values):
    """
    Apply a dict of {sysctl_key: value} as a single privileged operation,
    but with each key set independently (';' not '&&') so one unknown or
    rejected oid can't silently block the rest from applying. Returns
    (all_ok, applied_list, failed_list, raw_output).
    """
    if not values:
        return True, [], [], ""
    parts = [
        f"(sysctl -w {k}={v} >/dev/null 2>&1 && echo APPLIED:{k}) || echo FAILED:{k}"
        for k, v in values.items()
    ]
    ok, out, err = run_privileged(" ; ".join(parts))
    if not ok and not out:
        # The privileged call itself failed (e.g. auth cancelled) before
        # any of the per-key echoes ran.
        return False, [], list(values.keys()), err or out
    applied, failed = [], []
    for line in out.splitlines():
        if line.startswith("APPLIED:"):
            applied.append(line.split(":", 1)[1])
        elif line.startswith("FAILED:"):
            failed.append(line.split(":", 1)[1])
    return (len(failed) == 0), applied, failed, out


def read_sysctl(key):
    ok, out, err = run(["sysctl", "-n", key])
    if ok:
        return out
    return None


# ---------------------------------------------------------------------------
# Diagnostic Parsers & Bottleneck Detection
# ---------------------------------------------------------------------------
class DiagnosticReport:
    """Structured report extracted from CLI tool diagnostic output."""

    def __init__(
        self,
        title,
        status="INFO",
        summary="",
        findings=None,
        issues=None,
        recommendations=None,
        raw="",
    ):
        self.title = title
        self.status = status  # "OK", "WARNING", "ERROR", "INFO"
        self.summary = summary
        self.findings = findings or []  # list of (key, value) pairs
        self.issues = issues or []  # list of (severity, description) tuples
        self.recommendations = recommendations or []  # list of strings
        self.raw = raw

    def format_text(self, cmd=""):
        lines = []
        lines.append("=" * 76)
        lines.append(f"  DIAGNOSTIC REPORT: {self.title.upper()}")
        lines.append("=" * 76)
        lines.append(f"Status: [{self.status}] {self.summary}")
        lines.append("")

        if self.findings:
            lines.append("Key Findings:")
            for k, v in self.findings:
                lines.append(f"  • {k:22s}: {v}")
            lines.append("")

        lines.append("Issues & Misconfigurations:")
        if self.issues:
            for severity, desc in self.issues:
                icon = "❌" if severity == "ERROR" else ("⚠️" if severity == "WARNING" else "ℹ️")
                lines.append(f"  {icon} [{severity}] {desc}")
        else:
            lines.append("  ✓ No misconfigurations or bottlenecks detected.")
        lines.append("")

        if self.recommendations:
            lines.append("Actionable Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  → {rec}")
            lines.append("")

        cmd_label = f" ({cmd})" if cmd else ""
        lines.append("-" * 76)
        lines.append(f"RAW CLI OUTPUT{cmd_label}")
        lines.append("-" * 76)
        lines.append(self.raw.strip() if self.raw.strip() else "(no output)")
        lines.append("=" * 76)
        lines.append("\n")
        return "\n".join(lines)


def parse_wifi_output(ok, out, err, cmd=""):
    """Parse Wi-Fi CLI output (airport -I or system_profiler SPAirPortDataType)."""
    raw = out if ok else (err or out)
    if not ok:
        return DiagnosticReport(
            title="Wi-Fi Link Info",
            status="ERROR",
            summary="Failed to query Wi-Fi status.",
            issues=[("ERROR", f"Command failed: {err or out}")],
            recommendations=["Verify Wi-Fi hardware is enabled in macOS System Settings."],
            raw=raw,
        )

    findings = []
    issues = []
    recommendations = []

    is_airport = "agrCtlRSSI" in out or "lastTxRate" in out

    ssid = None
    channel_str = None
    channel_num = None
    band = None
    width = None
    phy_mode = None
    rssi = None
    noise = None
    tx_rate = None
    mcs = None
    security = None
    status = None

    if is_airport:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("agrCtlRSSI:"):
                try:
                    rssi = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("agrCtlNoise:"):
                try:
                    noise = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("lastTxRate:"):
                try:
                    tx_rate = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("MCS:"):
                try:
                    mcs = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("link auth:"):
                security = line.split(":", 1)[1].strip()
            elif line.startswith("channel:"):
                channel_str = line.split(":", 1)[1].strip()
                m_ch = re.match(r'(\d+)(?:,(\d+))?', channel_str)
                if m_ch:
                    channel_num = int(m_ch.group(1))
                    width = f"{m_ch.group(2)}MHz" if m_ch.group(2) else None
            elif line.startswith("state:"):
                status = "Connected" if line.split(":", 1)[1].strip() == "running" else "Disconnected"
    else:
        m_status = re.search(r'Status:\s*([^\n\r]+)', out)
        if m_status:
            status = m_status.group(1).strip()

        curr_net_match = re.search(r'Current Network Information:\s*\n\s*([^:\n\r]+):', out)
        if curr_net_match:
            ssid = curr_net_match.group(1).strip()
            status = "Connected"

        m_phy = re.search(r'PHY Mode:\s*([^\n\r]+)', out)
        if m_phy:
            phy_mode = m_phy.group(1).strip()

        m_chan = re.search(r'Channel:\s*([^\n\r]+)', out)
        if m_chan:
            channel_str = m_chan.group(1).strip()
            m_num = re.search(r'(\d+)', channel_str)
            if m_num:
                channel_num = int(m_num.group(1))
            if "2GHz" in channel_str or "2.4GHz" in channel_str:
                band = "2.4 GHz"
            elif "5GHz" in channel_str:
                band = "5 GHz"
            elif "6GHz" in channel_str:
                band = "6 GHz"
            m_w = re.search(r'(\d+MHz)', channel_str)
            if m_w:
                width = m_w.group(1)

        m_sec = re.search(r'Security:\s*([^\n\r]+)', out)
        if m_sec:
            security = m_sec.group(1).strip()

        m_sig = re.search(r'Signal\s*/\s*Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm', out)
        if m_sig:
            rssi = int(m_sig.group(1))
            noise = int(m_sig.group(2))

        m_tx = re.search(r'Transmit Rate:\s*(\d+)', out)
        if m_tx:
            tx_rate = int(m_tx.group(1))

        m_mcs = re.search(r'MCS Index:\s*(\d+)', out)
        if m_mcs:
            mcs = int(m_mcs.group(1))

    # Deduce band from channel number if not explicitly found in string
    if band is None and channel_num is not None:
        if 1 <= channel_num <= 14:
            band = "2.4 GHz"
        elif 32 <= channel_num <= 177:
            band = "5 GHz"
        elif channel_num > 177:
            band = "6 GHz"

    # Evaluate Connection State
    if status != "Connected" and not ssid:
        return DiagnosticReport(
            title="Wi-Fi Link Info",
            status="WARNING" if "Off" in str(status) else "INFO",
            summary=f"Wi-Fi is {status or 'Not Connected'}.",
            findings=[("Wi-Fi Status", status or "Disconnected")],
            issues=[("WARNING", "Wi-Fi is not connected to any network.")],
            recommendations=[
                "If using a wired Ethernet connection, this is expected.",
                "If Wi-Fi is intended, connect to an available network in macOS Settings.",
            ],
            raw=raw,
        )

    # Findings
    findings.append(("Network Name (SSID)", ssid or "Unknown"))
    if band:
        chan_disp = f"{channel_num} ({band}{f', {width}' if width else ''})" if channel_num else band
        findings.append(("Channel & Band", chan_disp))
    elif channel_str:
        findings.append(("Channel", channel_str))

    if phy_mode:
        findings.append(("Wi-Fi Standard", phy_mode))

    if tx_rate is not None:
        eff_tp = int(tx_rate * 0.68)
        findings.append(("Transmit Rate", f"{tx_rate} Mbps (Est. TCP throughput: ~{eff_tp} Mbps)"))

    if rssi is not None and noise is not None:
        snr = rssi - noise
        sig_quality = (
            "Excellent" if rssi >= -60 else ("Good" if rssi >= -70 else ("Fair" if rssi >= -80 else "Poor"))
        )
        findings.append(("Signal Strength", f"{rssi} dBm ({sig_quality}) / Noise: {noise} dBm (SNR: {snr} dB)"))
    elif rssi is not None:
        findings.append(("Signal (RSSI)", f"{rssi} dBm"))

    if mcs is not None:
        findings.append(("MCS Index", str(mcs)))
    if security:
        findings.append(("Security", security))

    # Bottleneck & Misconfiguration Analysis
    report_status = "OK"

    # 1. 2.4 GHz bottleneck
    if band == "2.4 GHz" or (channel_num and channel_num <= 14):
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Connected to 2.4 GHz band (Channel {channel_num or 1}). 2.4 GHz suffers from high interference, "
            "narrow channel width (20 MHz), and typical real-world speeds capped at 50–100 Mbps. "
            "TCP stack tuning cannot overcome this physical wireless bottleneck."
        ))
        recommendations.append(
            "Connect to your router's 5 GHz or 6 GHz Wi-Fi SSID for gigabit-class throughput."
        )

    # 2. Legacy PHY mode
    is_modern_wifi = any(m in (phy_mode or "").lower() for m in ["802.11ac", "802.11ax", "802.11be"])
    is_legacy_wifi = not is_modern_wifi and bool(re.search(r'802\.11[abgn]\b', (phy_mode or "").lower()))
    if is_legacy_wifi:
        if report_status != "ERROR":
            report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Legacy Wi-Fi standard ({phy_mode}). Modern high-speed connections require Wi-Fi 5 (802.11ac) "
            "or Wi-Fi 6/6E (802.11ax) to achieve speeds above 150 Mbps."
        ))

    # 3. Weak signal or low SNR
    if rssi is not None and rssi < -75:
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Weak Wi-Fi signal ({rssi} dBm). Weak reception causes packet retransmissions, frame drops, "
            "and triggers TCP congestion window collapses."
        ))
        recommendations.append(
            "Move closer to your Wi-Fi access point or eliminate physical obstructions."
        )
    elif rssi is not None and noise is not None and (rssi - noise) < 18:
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Low Signal-to-Noise Ratio (SNR: {rssi - noise} dB). RF noise/interference is degrading connection reliability."
        ))

    # 4. Low link rate
    if tx_rate is not None and tx_rate < 150:
        if report_status != "ERROR":
            report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Physical link transmit rate is only {tx_rate} Mbps. Your TCP throughput cannot exceed ~{int(tx_rate * 0.68)} Mbps."
        ))

    # 5. Insecure security
    if security and any(weak in security.lower() for weak in ["none", "open", "wep"]):
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Insecure Wi-Fi security ({security}). Traffic is unencrypted over the air."
        ))
        recommendations.append("Configure WPA2 or WPA3 encryption on your router.")

    if report_status == "OK":
        summary = "Wi-Fi link is healthy with modern standard and good signal."
    else:
        summary = "Wi-Fi bottleneck detected (check frequency band, link rate, or signal)."

    return DiagnosticReport(
        title="Wi-Fi Link Info",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


def _to_mbps(val, unit):
    """Normalize throughput value to Mbps."""
    if val is None or not unit:
        return None
    u = unit.lower()
    if "g" in u:
        return val * 1000.0
    elif "k" in u:
        return val / 1000.0
    return val


def parse_networkquality_output(ok, out, err, cmd=""):
    """Parse networkQuality CLI output."""
    raw = out if ok else (err or out)
    if not ok:
        if "command not found" in (err or out).lower():
            return DiagnosticReport(
                title="Network Quality Test",
                status="INFO",
                summary="networkQuality command not available on this macOS version.",
                issues=[("INFO", "networkQuality requires macOS 12 (Monterey) or later.")],
                recommendations=["Upgrade macOS to Monterey or later to use the built-in responsiveness test."],
                raw=raw,
            )
        return DiagnosticReport(
            title="Network Quality Test",
            status="ERROR",
            summary="Network quality test failed or timed out.",
            issues=[("ERROR", f"Test error: {err or out}")],
            recommendations=["Verify active internet connectivity and test server accessibility."],
            raw=raw,
        )

    findings = []
    issues = []
    recommendations = []

    # Uplink / Downlink capacity
    ul_match = re.search(r'Uplink capacity:\s*([\d\.]+)\s*(\w+ps)', out)
    dl_match = re.search(r'Downlink capacity:\s*([\d\.]+)\s*(\w+ps)', out)
    ul_val = float(ul_match.group(1)) if ul_match else None
    ul_unit = ul_match.group(2) if ul_match else "Mbps"
    dl_val = float(dl_match.group(1)) if dl_match else None
    dl_unit = dl_match.group(2) if dl_match else "Mbps"

    dl_mbps = _to_mbps(dl_val, dl_unit)
    ul_mbps = _to_mbps(ul_val, ul_unit)

    # Responsiveness
    resp_rating = None
    resp_ms = None
    resp_rpm = None
    m_resp1 = re.search(r'Responsiveness:\s*(\w+)\s*\(([\d\.]+)\s*milliseconds\s*\|\s*(\d+)\s*RPM\)', out)
    if m_resp1:
        resp_rating = m_resp1.group(1)
        resp_ms = float(m_resp1.group(2))
        resp_rpm = int(m_resp1.group(3))
    else:
        m_resp2 = re.search(r'Responsiveness:\s*(\w+)\s*\n\s*(\d+)\s*RPM\s*\(([\d\.]+)\s*milliseconds\)', out)
        if m_resp2:
            resp_rating = m_resp2.group(1)
            resp_rpm = int(m_resp2.group(2))
            resp_ms = float(m_resp2.group(3))
        else:
            m_resp3 = re.search(r'Responsiveness:\s*(\w+)', out)
            if m_resp3:
                resp_rating = m_resp3.group(1)

    # Idle Latency
    idle_ms = None
    idle_rpm = None
    m_idle1 = re.search(r'Idle Latency:\s*([\d\.]+)\s*milliseconds(?:\s*\|\s*(\d+)\s*RPM)?', out)
    if m_idle1:
        idle_ms = float(m_idle1.group(1))
        if m_idle1.group(2):
            idle_rpm = int(m_idle1.group(2))
    else:
        m_idle2 = re.search(r'Idle Latency:\s*\n\s*(?:(\d+)\s*RPM\s*\()?([\d\.]+)\s*milliseconds', out)
        if m_idle2:
            idle_ms = float(m_idle2.group(2))
            if m_idle2.group(1):
                idle_rpm = int(m_idle2.group(1))

    # Endpoint & Interface
    ep_match = re.search(r'Test Endpoint:\s*([^\n\r]+)', out)
    test_ep = ep_match.group(1).strip() if ep_match else None
    iface_match = re.search(r'Interface:\s*([^\n\r]+)', out)
    test_iface = iface_match.group(1).strip() if iface_match else None

    # ECN / L4S
    ecn_match = re.search(r'ECN\s*(Disabled|Enabled)', out, re.IGNORECASE)
    ecn_status = ecn_match.group(1) if ecn_match else None

    # Compile findings
    if dl_val is not None:
        findings.append(("Downlink Speed", f"{dl_val:.2f} {dl_unit}"))
    if ul_val is not None:
        findings.append(("Uplink Speed", f"{ul_val:.2f} {ul_unit}"))

    if resp_rating:
        detail = []
        if resp_rpm:
            detail.append(f"{resp_rpm} RPM")
        if resp_ms:
            detail.append(f"{resp_ms:.1f} ms loaded latency")
        resp_str = f"{resp_rating} ({', '.join(detail)})" if detail else resp_rating
        findings.append(("Responsiveness", resp_str))

    if idle_ms is not None:
        findings.append(("Idle Latency", f"{idle_ms:.1f} ms{f' ({idle_rpm} RPM)' if idle_rpm else ''}"))

    if idle_ms is not None and resp_ms is not None:
        bloat_ms = resp_ms - idle_ms
        findings.append(("Bufferbloat Delta", f"+{bloat_ms:.1f} ms additional delay under saturation"))

    if test_ep:
        findings.append(("Test Endpoint", test_ep))
    if test_iface:
        findings.append(("Tested Interface", test_iface))
    if ecn_status:
        findings.append(("ECN Status", ecn_status))

    # Evaluate issues
    report_status = "OK"

    # Bufferbloat evaluation
    if resp_rating == "Low" or (resp_rpm and resp_rpm < 100) or (resp_ms and resp_ms > 250):
        report_status = "WARNING"
        bloat_str = f" (+{resp_ms - idle_ms:.0f} ms bloat)" if (idle_ms and resp_ms) else ""
        issues.append((
            "WARNING",
            f"Severe Bufferbloat Detected: Responsiveness rated Low ({resp_rpm or 'N/A'} RPM, {resp_ms or 'N/A'} ms loaded latency){bloat_str}. "
            "Network queues in your router/modem are filling with packets, causing ping spikes, video call lag, and stuttering during downloads."
        ))
        recommendations.append(
            "Enable Smart Queue Management (SQM, e.g. CAKE or FQ-CoDel) on your home router."
        )
        recommendations.append(
            "In TCP Optimizer, the 'Low-Latency / Gaming' preset sets delayed_ack=0 to prioritize responsiveness."
        )
    elif resp_rating == "Medium":
        issues.append((
            "INFO",
            f"Moderate Bufferbloat: Responsiveness rated Medium ({resp_rpm or 'N/A'} RPM). Noticeable delay may occur during large file transfers."
        ))

    # Low capacity
    if dl_mbps is not None and dl_mbps < 25.0:
        if report_status != "ERROR":
            report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Low Downlink Capacity ({dl_val:.1f} {dl_unit}). If you pay for high-speed broadband, the bottleneck is "
            "likely Wi-Fi band/interference, cable limitations, or ISP congestion rather than TCP window settings."
        ))
        recommendations.append("Check Wi-Fi band (switch to 5 GHz) or test via a direct wired Ethernet cable.")

    # High idle ping
    if idle_ms is not None and idle_ms > 80.0:
        issues.append((
            "WARNING",
            f"High Base Latency ({idle_ms:.1f} ms). Idle ping to test server is elevated, suggesting upstream routing delays or geographic distance."
        ))

    if report_status == "OK":
        summary = "Network capacity and latency responsiveness are optimal."
    else:
        summary = "Network issues detected (bufferbloat or limited throughput)."

    return DiagnosticReport(
        title="Network Quality Test",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


def parse_ifconfig_output(ok, out, err, cmd=""):
    """Parse ifconfig CLI output."""
    raw = out if ok else (err or out)
    if not ok:
        return DiagnosticReport(
            title="Interfaces + MTU",
            status="ERROR",
            summary="Failed to run ifconfig.",
            issues=[("ERROR", f"Command error: {err or out}")],
            recommendations=["Verify network permissions."],
            raw=raw,
        )

    blocks = {}
    current_if = None
    for line in out.splitlines():
        m = re.match(r'^([a-zA-Z0-9]+):\s*flags=\d+<([^>]+)>\s*mtu\s*(\d+)', line)
        if m:
            current_if = m.group(1)
            blocks[current_if] = {
                "name": current_if,
                "flags": m.group(2).split(","),
                "mtu": int(m.group(3)),
                "ipv4": [],
                "ipv6": [],
                "status": None,
                "media": None,
                "mac": None,
            }
        elif current_if:
            s_line = line.strip()
            if s_line.startswith("status:"):
                blocks[current_if]["status"] = s_line.split("status:", 1)[1].strip()
            elif s_line.startswith("media:"):
                blocks[current_if]["media"] = s_line.split("media:", 1)[1].strip()
            elif s_line.startswith("ether "):
                blocks[current_if]["mac"] = s_line.split("ether ", 1)[1].strip()
            elif s_line.startswith("inet "):
                parts = s_line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    netmask = parts[3] if "netmask" in parts and len(parts) > parts.index("netmask") + 1 else None
                    blocks[current_if]["ipv4"].append((ip, netmask))
            elif s_line.startswith("inet6 "):
                parts = s_line.split()
                if len(parts) >= 2:
                    blocks[current_if]["ipv6"].append(parts[1])

    findings = []
    issues = []
    recommendations = []
    report_status = "OK"

    active_physical = []
    active_tunnels = []

    for name, data in blocks.items():
        if name == "lo0":
            continue
        is_active = (data["status"] == "active") or bool(data["ipv4"])
        if is_active:
            if name.startswith("utun"):
                active_tunnels.append(data)
            else:
                active_physical.append(data)

    if not active_physical and not active_tunnels:
        return DiagnosticReport(
            title="Interfaces + MTU",
            status="ERROR",
            summary="No active network interfaces detected.",
            issues=[("ERROR", "All network interfaces are inactive or missing IP addresses.")],
            recommendations=["Check network cable or reconnect to Wi-Fi in macOS System Settings."],
            raw=raw,
        )

    for iface in active_physical:
        name = iface["name"]
        mtu = iface["mtu"]
        ipv4_strs = [f"{ip}" for ip, nm in iface["ipv4"]]
        media_val = iface["media"] or "N/A"

        desc = f"MTU {mtu}"
        if ipv4_strs:
            desc += f", IPv4: {', '.join(ipv4_strs)}"
        if iface["media"]:
            desc += f", Media: {iface['media']}"
        findings.append((f"Interface {name}", desc))

        # Check for APIPA / DHCP failure (169.254.x.x)
        for ip, _ in iface["ipv4"]:
            if ip.startswith("169.254."):
                report_status = "ERROR"
                issues.append((
                    "ERROR",
                    f"Self-assigned IP address ({ip}) on {name}. Device failed to receive a valid DHCP lease from your router."
                ))
                recommendations.append(
                    "Renew DHCP lease in Network Settings, check Wi-Fi password, or reboot your router/modem."
                )

        # Check for 100baseTX Ethernet Bottleneck
        if "100basetx" in media_val.lower():
            report_status = "WARNING"
            issues.append((
                "WARNING",
                f"Wired Ethernet link on {name} negotiated at only 100 Mbps (100baseTX) instead of Gigabit (1000baseT). "
                "This physically caps download/upload speeds to ~94 Mbps! Often caused by a damaged 8-pin Ethernet cable "
                "(missing pairs), poor wall jack termination, or an older 10/100 switch."
            ))
            recommendations.append(
                "Replace Ethernet cable with a Cat5e or Cat6 cable, test another router port, or check USB-C Ethernet adapter."
            )

        # Check for Half-Duplex
        if "half-duplex" in media_val.lower():
            report_status = "ERROR"
            issues.append((
                "ERROR",
                f"Interface {name} is running in half-duplex! Ethernet collisions will cause massive packet loss and throughput collapse."
            ))
            recommendations.append("Force full-duplex negotiation in Network Settings > Hardware or replace cable.")

        # Check MTU anomalies
        if mtu < 1500:
            if report_status != "ERROR":
                report_status = "WARNING"
            issues.append((
                "WARNING",
                f"Sub-standard MTU ({mtu} bytes) on {name} (standard Ethernet is 1500). Packets larger than {mtu} bytes will be "
                "fragmented. If Path MTU Discovery (PMTUD) is blocked by intermediate firewalls, connections may hang or stall."
            ))
            recommendations.append(
                f"Ensure macOS sysctl net.inet.tcp.mssdflt is tuned for this MTU ({mtu - 40} bytes)."
            )
        elif mtu > 1500:
            findings.append((f"Jumbo MTU on {name}", f"{mtu} bytes (Ensure all LAN switches support Jumbo Frames)"))

    if active_tunnels:
        tun_names = [t["name"] for t in active_tunnels]
        tun_mtus = [f"{t['name']}: {t['mtu']}" for t in active_tunnels[:4]]
        findings.append(("Active VPN Tunnels", f"{len(active_tunnels)} tunnel(s) active ({', '.join(tun_names[:4])})"))
        findings.append(("Tunnel MTUs", ", ".join(tun_mtus)))
        issues.append((
            "INFO",
            f"{len(active_tunnels)} active tunnel interface(s) (VPN or iCloud Private Relay). "
            "VPN tunnel encapsulation and encryption overhead can reduce peak throughput."
        ))

    if report_status == "OK":
        summary = f"All {len(active_physical)} active physical interface(s) configured normally."
    else:
        summary = "Interface misconfiguration or physical speed limitation detected."

    return DiagnosticReport(
        title="Interfaces + MTU",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


def parse_dns_output(ok, out, err, cmd=""):
    """Parse DNS CLI output (dig or nslookup)."""
    raw = out if ok else (err or out)
    if not ok:
        return DiagnosticReport(
            title="DNS Lookup",
            status="ERROR",
            summary="DNS resolution failed completely.",
            issues=[("ERROR", f"Lookup failed: {err or out}")],
            recommendations=[
                "Check DNS resolver settings in macOS System Settings > Network.",
                "Configure reliable public DNS servers like Cloudflare (1.1.1.1) or Google (8.8.8.8).",
            ],
            raw=raw,
        )

    findings = []
    issues = []
    recommendations = []
    report_status = "OK"

    is_dig = ";; ->>HEADER<<-" in out or ";; Query time:" in out

    query_time_ms = None
    dns_server = None
    dns_status = None
    resolved_ips = []

    if is_dig:
        m_status = re.search(r'status:\s*([A-Z]+)', out)
        if m_status:
            dns_status = m_status.group(1)

        m_time = re.search(r';;\s*Query time:\s*(\d+)\s*msec', out)
        if m_time:
            query_time_ms = int(m_time.group(1))

        m_srv = re.search(r';;\s*SERVER:\s*([^\n\r]+)', out)
        if m_srv:
            dns_server = m_srv.group(1).strip()

        in_answer = False
        for line in out.splitlines():
            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            elif in_answer and line.startswith(";;"):
                in_answer = False
            elif in_answer and line.strip():
                parts = line.split()
                if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
                    resolved_ips.append(parts[4])
    else:
        m_srv = re.search(r'Server:\s*([^\n\r]+)', out)
        m_addr = re.search(r'Address:\s*([^\n\r]+)', out)
        if m_srv:
            dns_server = m_srv.group(1).strip()
            if m_addr:
                dns_server += f" ({m_addr.group(1).strip()})"
        for m in re.finditer(r'Address:\s*([0-9\.]+)', out):
            ip_found = m.group(1).strip()
            if dns_server and ip_found not in dns_server:
                resolved_ips.append(ip_found)
        if "** server can't find" in out or "connection timed out" in out.lower():
            dns_status = "SERVFAIL"
        else:
            dns_status = "NOERROR"

    if dns_status and dns_status != "NOERROR":
        report_status = "ERROR"
        issues.append((
            "ERROR",
            f"DNS query returned error status: {dns_status}. Hostnames cannot be resolved."
        ))
        recommendations.append("Switch DNS resolver to 1.1.1.1 or 8.8.8.8 in macOS Network Settings.")

    if query_time_ms is not None:
        if query_time_ms < 25:
            speed_rating = "Excellent (Fast)"
        elif query_time_ms < 60:
            speed_rating = "Good (Normal)"
        elif query_time_ms < 150:
            speed_rating = "Moderate / Sluggish"
        else:
            speed_rating = "High Latency (Slow)"
        findings.append(("Query Latency", f"{query_time_ms} ms ({speed_rating})"))

        if query_time_ms > 150:
            report_status = "WARNING"
            issues.append((
                "WARNING",
                f"Slow DNS Resolution ({query_time_ms} ms). High DNS lookup latency adds delay to every new connection "
                "before TCP handshake begins, making web browsing and network apps feel sluggish."
            ))
            recommendations.append(
                "Configure faster DNS resolvers such as Cloudflare (1.1.1.1, 1.0.0.1) or Google (8.8.8.8, 8.8.4.4)."
            )
        elif query_time_ms > 60:
            issues.append((
                "INFO",
                f"Slightly elevated DNS latency ({query_time_ms} ms). Public anycast DNS may offer faster lookups."
            ))

    if dns_server:
        findings.append(("DNS Resolver", dns_server))
        is_private = False
        m_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', dns_server)
        if m_ip:
            try:
                ip_obj = ipaddress.ip_address(m_ip.group(1))
                is_private = ip_obj.is_private
            except ValueError:
                pass
        if is_private and query_time_ms and query_time_ms > 40:
            issues.append((
                "INFO",
                f"DNS queries are relayed through local router ({m_ip.group(1)}). Some consumer routers have weak DNS proxy performance."
            ))

    if dns_status:
        findings.append(("Response Status", dns_status))
    if resolved_ips:
        findings.append(("Resolved Addresses", ", ".join(resolved_ips[:4])))

    if report_status == "OK":
        summary = f"DNS resolution is fast and functional ({query_time_ms or '<25'} ms)."
    elif report_status == "WARNING":
        summary = f"DNS latency is elevated ({query_time_ms} ms)."
    else:
        summary = f"DNS resolution failed ({dns_status or 'Error'})."

    return DiagnosticReport(
        title="DNS Lookup",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


class TCPOptimizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("760x620")
        self.entries = {}

        if not is_macos():
            messagebox.showwarning(
                APP_NAME,
                "This tool reads/writes macOS sysctl parameters and won't "
                "function on this OS. The UI will still load so you can "
                "review it, but Apply/Read actions will fail.",
            )

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_overview = ttk.Frame(nb)
        self.tab_optimize = ttk.Frame(nb)
        self.tab_advanced = ttk.Frame(nb)
        self.tab_diag = ttk.Frame(nb)
        self.tab_persist = ttk.Frame(nb)

        nb.add(self.tab_overview, text="Overview")
        nb.add(self.tab_optimize, text="Presets")
        nb.add(self.tab_advanced, text="Advanced")
        nb.add(self.tab_diag, text="Diagnostics")
        nb.add(self.tab_persist, text="Persistence")

        self._build_overview()
        self._build_optimize()
        self._build_advanced()
        self._build_diagnostics()
        self._build_persistence()

    # ------------------------------------------------------------------ #
    # Overview
    # ------------------------------------------------------------------ #
    def _build_overview(self):
        f = self.tab_overview
        note = (
            "Modern macOS already auto-tunes TCP send/receive windows for "
            "most connections, so manual tuning here usually produces small, "
            "situational gains rather than a jump from, say, 300 Mbps to "
            "900 Mbps. If you're not seeing full 1 Gbps throughput, check "
            "the Diagnostics tab first \u2014 Wi‑Fi band/channel, DNS latency, "
            "and the actual server/link you're testing against are the more "
            "common bottlenecks on a MacBook Air."
        )
        lbl = tk.Label(f, text=note, wraplength=700, justify="left", fg="#444")
        lbl.pack(anchor="w", padx=10, pady=(10, 6))

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", padx=10, pady=4)
        ttk.Button(btn_row, text="Refresh current values", command=self.refresh_overview).pack(side="left")

        self.overview_text = scrolledtext.ScrolledText(f, height=22, font=("Menlo", 11))
        self.overview_text.pack(fill="both", expand=True, padx=10, pady=8)
        self.refresh_overview()

    def refresh_overview(self):
        self.overview_text.delete("1.0", tk.END)
        lines = []
        for key, meta in TCP_KEYS.items():
            val = read_sysctl(key)
            lines.append(f"{key:38s} = {val if val is not None else 'unavailable':>10}   ({meta['label']})")
        self.overview_text.insert(tk.END, "\n".join(lines))

    # ------------------------------------------------------------------ #
    # Presets
    # ------------------------------------------------------------------ #
    def _build_optimize(self):
        f = self.tab_optimize
        tk.Label(
            f, text="Presets apply a known-safe bundle of sysctl values immediately.\n"
                    "They do NOT persist across reboot unless you also install the\n"
                    "LaunchDaemon on the Persistence tab.",
            justify="left", fg="#444"
        ).pack(anchor="w", padx=10, pady=10)

        for name in PRESETS:
            row = ttk.Frame(f)
            row.pack(fill="x", padx=10, pady=4)
            ttk.Button(row, text=f"Apply: {name}", width=32,
                       command=lambda n=name: self.apply_preset(n)).pack(side="left")

        self.preset_status = tk.Label(f, text="", fg="#0a7a0a", wraplength=700, justify="left")
        self.preset_status.pack(anchor="w", padx=10, pady=10)

    def apply_preset(self, name):
        values = PRESETS[name]
        if values is None:
            values = MACOS_DEFAULTS
        all_ok, applied, failed, raw = apply_sysctl_values(values)
        if all_ok:
            self.preset_status.config(
                text=f"Applied '{name}' successfully ({len(applied)} values set).", fg="#0a7a0a"
            )
        elif applied:
            self.preset_status.config(
                text=(f"Applied '{name}' partially: {len(applied)} of {len(values)} values set.\n"
                      f"Skipped (not supported on this macOS): {', '.join(failed)}"),
                fg="#a36a00",
            )
        else:
            self.preset_status.config(text=f"Failed to apply '{name}'.\n{raw}", fg="#a30000")
        self.refresh_overview()

    # ------------------------------------------------------------------ #
    # Advanced (manual per-key editing)
    # ------------------------------------------------------------------ #
    def _build_advanced(self):
        f = self.tab_advanced
        canvas = tk.Canvas(f, borderwidth=0, highlightthickness=0)
        scroll = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y")

        for key, meta in TCP_KEYS.items():
            row = ttk.Frame(inner)
            row.pack(fill="x", pady=6, padx=6)
            tk.Label(row, text=meta["label"], width=32, anchor="w").grid(row=0, column=0, sticky="w")
            var = tk.StringVar(value=read_sysctl(key) or "")
            entry = ttk.Entry(row, textvariable=var, width=12)
            entry.grid(row=0, column=1, padx=6)
            tk.Label(row, text=f"({meta['min']}\u2013{meta['max']})", fg="#777").grid(row=0, column=2, padx=4)
            self.entries[key] = var
            tk.Label(row, text=meta["help"], fg="#666", wraplength=520, justify="left").grid(
                row=1, column=0, columnspan=3, sticky="w", pady=(2, 0)
            )

        btn_row = ttk.Frame(inner)
        btn_row.pack(fill="x", pady=14, padx=6)
        ttk.Button(btn_row, text="Reload current values", command=self.reload_advanced).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Apply all changed values", command=self.apply_advanced).pack(side="left", padx=4)

        self.advanced_status = tk.Label(inner, text="", fg="#0a7a0a", wraplength=650, justify="left")
        self.advanced_status.pack(anchor="w", padx=6, pady=6)

    def reload_advanced(self):
        for key, var in self.entries.items():
            var.set(read_sysctl(key) or "")

    def apply_advanced(self):
        to_apply = {}
        for key, var in self.entries.items():
            raw = var.get().strip()
            if raw == "":
                continue
            meta = TCP_KEYS[key]
            try:
                val = int(raw)
            except ValueError:
                messagebox.showerror(APP_NAME, f"{key}: '{raw}' is not a valid integer.")
                return
            if not (meta["min"] <= val <= meta["max"]):
                messagebox.showerror(
                    APP_NAME,
                    f"{key}: {val} is outside the safe range {meta['min']}\u2013{meta['max']}.",
                )
                return
            to_apply[key] = val

        if not to_apply:
            self.advanced_status.config(text="Nothing to apply.", fg="#777")
            return

        all_ok, applied, failed, raw = apply_sysctl_values(to_apply)
        if all_ok:
            self.advanced_status.config(text=f"Applied: {', '.join(applied)}", fg="#0a7a0a")
        elif applied:
            self.advanced_status.config(
                text=f"Applied: {', '.join(applied)}\nFailed: {', '.join(failed)}", fg="#a36a00"
            )
        else:
            self.advanced_status.config(text=f"Failed: {raw}", fg="#a30000")
        self.refresh_overview()

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #
    def _build_diagnostics(self):
        f = self.tab_diag
        tk.Label(
            f, text="Run these before assuming TCP tuning is the fix \u2014 they "
                    "separate a real TCP-stack limit from Wi‑Fi, DNS, or "
                    "server-side bottlenecks. Each check analyzes the results "
                    "for bottlenecks and misconfigurations before showing the raw tool output.",
            wraplength=700, justify="left", fg="#444"
        ).pack(anchor="w", padx=10, pady=10)

        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=10)
        ttk.Button(btns, text="Wi-Fi link info", command=self.diag_wifi).pack(side="left", padx=4)
        ttk.Button(btns, text="Network Quality Test", command=self.diag_networkquality).pack(side="left", padx=4)
        ttk.Button(btns, text="Interface + MTU", command=self.diag_ifconfig).pack(side="left", padx=4)
        ttk.Button(btns, text="DNS latency", command=self.diag_dns).pack(side="left", padx=4)
        ttk.Button(btns, text="Run All Checks", command=self.diag_all).pack(side="left", padx=4)
        ttk.Button(btns, text="Clear", command=self.diag_clear).pack(side="right", padx=4)

        self.diag_text = scrolledtext.ScrolledText(f, height=22, font=("Menlo", 11))
        self.diag_text.pack(fill="both", expand=True, padx=10, pady=8)

        # Configure style tags for diagnostic reporting
        self.diag_text.tag_configure("divider", foreground="#888888")
        self.diag_text.tag_configure("diag_title", font=("Menlo", 11, "bold"), foreground="#0044aa")
        self.diag_text.tag_configure("section_head", font=("Menlo", 11, "bold"))
        self.diag_text.tag_configure("status_ok", font=("Menlo", 11, "bold"), foreground="#0a7a0a")
        self.diag_text.tag_configure("status_warning", font=("Menlo", 11, "bold"), foreground="#a36a00")
        self.diag_text.tag_configure("status_error", font=("Menlo", 11, "bold"), foreground="#a30000")
        self.diag_text.tag_configure("status_info", font=("Menlo", 11, "bold"), foreground="#0055aa")
        self.diag_text.tag_configure("finding_key", font=("Menlo", 11, "bold"))
        self.diag_text.tag_configure("finding_val", font=("Menlo", 11))
        self.diag_text.tag_configure("issue_warn", font=("Menlo", 11), foreground="#a36a00")
        self.diag_text.tag_configure("issue_err", font=("Menlo", 11, "bold"), foreground="#a30000")
        self.diag_text.tag_configure("issue_info", font=("Menlo", 11), foreground="#0055aa")
        self.diag_text.tag_configure("rec", font=("Menlo", 11), foreground="#007788")
        self.diag_text.tag_configure("raw_hdr", font=("Menlo", 10, "bold"), foreground="#555555")
        self.diag_text.tag_configure("raw_body", font=("Menlo", 10))

    def _diag_write_report(self, report, cmd=""):
        self.diag_text.insert(tk.END, "=" * 76 + "\n", "divider")
        self.diag_text.insert(tk.END, f"  DIAGNOSTIC REPORT: {report.title.upper()}\n", "diag_title")
        self.diag_text.insert(tk.END, "=" * 76 + "\n", "divider")

        status_tag = f"status_{report.status.lower()}"
        if status_tag not in ("status_ok", "status_warning", "status_error", "status_info"):
            status_tag = "status_info"
        self.diag_text.insert(tk.END, "Status: ", "section_head")
        self.diag_text.insert(tk.END, f"[{report.status}] {report.summary}\n\n", status_tag)

        if report.findings:
            self.diag_text.insert(tk.END, "Key Findings:\n", "section_head")
            for k, v in report.findings:
                self.diag_text.insert(tk.END, f"  • {k:22s}: ", "finding_key")
                self.diag_text.insert(tk.END, f"{v}\n", "finding_val")
            self.diag_text.insert(tk.END, "\n")

        self.diag_text.insert(tk.END, "Issues & Misconfigurations:\n", "section_head")
        if report.issues:
            for sev, desc in report.issues:
                icon = "❌" if sev == "ERROR" else ("⚠️" if sev == "WARNING" else "ℹ️")
                tag = "issue_err" if sev == "ERROR" else ("issue_warn" if sev == "WARNING" else "issue_info")
                self.diag_text.insert(tk.END, f"  {icon} [{sev}] ", tag)
                self.diag_text.insert(tk.END, f"{desc}\n")
        else:
            self.diag_text.insert(tk.END, "  ✓ No misconfigurations or bottlenecks detected.\n", "status_ok")
        self.diag_text.insert(tk.END, "\n")

        if report.recommendations:
            self.diag_text.insert(tk.END, "Actionable Recommendations:\n", "section_head")
            for rec in report.recommendations:
                self.diag_text.insert(tk.END, "  → ", "rec")
                self.diag_text.insert(tk.END, f"{rec}\n", "rec")
            self.diag_text.insert(tk.END, "\n")

        cmd_label = f" ({cmd})" if cmd else ""
        self.diag_text.insert(tk.END, "-" * 76 + "\n", "divider")
        self.diag_text.insert(tk.END, f"RAW CLI OUTPUT{cmd_label}\n", "raw_hdr")
        self.diag_text.insert(tk.END, "-" * 76 + "\n", "divider")
        raw_body = report.raw.strip() if report.raw.strip() else "(no output)"
        self.diag_text.insert(tk.END, f"{raw_body}\n", "raw_body")
        self.diag_text.insert(tk.END, "=" * 76 + "\n\n", "divider")
        self.diag_text.see(tk.END)

    def diag_wifi(self):
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
            "Current/Resources/airport"
        )
        if os.path.exists(airport):
            cmd = f"{airport} -I"
            ok, out, err = run([airport, "-I"])
        else:
            cmd = "system_profiler SPAirPortDataType"
            ok, out, err = run(["system_profiler", "SPAirPortDataType"])
        report = parse_wifi_output(ok, out, err, cmd=cmd)
        self._diag_write_report(report, cmd=cmd)

    def diag_networkquality(self):
        self.diag_text.insert(tk.END, "\nRunning networkQuality \u2014 this can take ~20-30s...\n", "status_info")
        self.diag_text.see(tk.END)
        self.root.update()
        cmd = "networkQuality -v"
        ok, out, err = run(["networkQuality", "-v"], timeout=60)
        report = parse_networkquality_output(ok, out, err, cmd=cmd)
        self._diag_write_report(report, cmd=cmd)

    def diag_ifconfig(self):
        cmd = "ifconfig"
        ok, out, err = run(["ifconfig"])
        report = parse_ifconfig_output(ok, out, err, cmd=cmd)
        self._diag_write_report(report, cmd=cmd)

    def diag_dns(self):
        cmd = "dig example.com"
        ok, out, err = run(["dig", "example.com"])
        if not ok:
            cmd = "nslookup example.com"
            ok, out, err = run(["nslookup", "example.com"])
        report = parse_dns_output(ok, out, err, cmd=cmd)
        self._diag_write_report(report, cmd=cmd)

    def diag_all(self):
        self.diag_wifi()
        self.diag_ifconfig()
        self.diag_dns()
        self.diag_networkquality()

    def diag_clear(self):
        self.diag_text.delete("1.0", tk.END)

    # ------------------------------------------------------------------ #
    # Persistence (LaunchDaemon so presets survive reboot)
    # ------------------------------------------------------------------ #
    def _build_persistence(self):
        f = self.tab_persist
        tk.Label(
            f, text="sysctl -w changes are reset on reboot. Installing this "
                    "LaunchDaemon re-applies your last-applied preset at every "
                    "boot by running a small root-owned script.",
            wraplength=700, justify="left", fg="#444"
        ).pack(anchor="w", padx=10, pady=10)

        self.persist_preset_var = tk.StringVar(value=list(PRESETS.keys())[1])
        row = ttk.Frame(f)
        row.pack(anchor="w", padx=10, pady=4)
        tk.Label(row, text="Preset to persist:").pack(side="left")
        ttk.OptionMenu(row, self.persist_preset_var, self.persist_preset_var.get(), *PRESETS.keys()).pack(side="left", padx=6)

        btns = ttk.Frame(f)
        btns.pack(anchor="w", padx=10, pady=10)
        ttk.Button(btns, text="Install (apply at every boot)", command=self.install_persistence).pack(side="left", padx=4)
        ttk.Button(btns, text="Uninstall", command=self.uninstall_persistence).pack(side="left", padx=4)
        ttk.Button(btns, text="Check status", command=self.check_persistence).pack(side="left", padx=4)

        self.persist_status = tk.Label(f, text="", fg="#0a7a0a", wraplength=700, justify="left")
        self.persist_status.pack(anchor="w", padx=10, pady=10)

    def install_persistence(self):
        name = self.persist_preset_var.get()
        values = PRESETS[name] or MACOS_DEFAULTS
        # '|| true' on each line so one unsupported key at boot can't stop
        # the rest of the script (and can't crash-loop the LaunchDaemon).
        script_lines = ["#!/bin/sh"] + [f"sysctl -w {k}={v} || true" for k, v in values.items()]
        script_content = "\n".join(script_lines) + "\n"

        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_DAEMON_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>{SCRIPT_INSTALL_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        # Write the script + plist to /tmp unprivileged, then move them into
        # place and set ownership/permissions as one privileged operation.
        tmp_script = "/tmp/tcpoptimizer-apply.sh"
        tmp_plist = "/tmp/tcpoptimizer.plist"
        with open(tmp_script, "w") as fh:
            fh.write(script_content)
        with open(tmp_plist, "w") as fh:
            fh.write(plist_content)

        cmd = (
            f"mkdir -p {shlex.quote(os.path.dirname(SCRIPT_INSTALL_PATH))} && "
            f"cp {shlex.quote(tmp_script)} {SCRIPT_INSTALL_PATH} && "
            f"chmod 755 {SCRIPT_INSTALL_PATH} && "
            f"cp {shlex.quote(tmp_plist)} {LAUNCH_DAEMON_PATH} && "
            f"chown root:wheel {LAUNCH_DAEMON_PATH} && "
            f"chmod 644 {LAUNCH_DAEMON_PATH} && "
            f"launchctl load -w {LAUNCH_DAEMON_PATH}"
        )
        ok, out, err = run_privileged(cmd)
        if ok:
            self.persist_status.config(
                text=f"Installed. '{name}' will be re-applied at every boot.\n{out}", fg="#0a7a0a"
            )
        else:
            self.persist_status.config(text=f"Install failed: {err or out}", fg="#a30000")

    def uninstall_persistence(self):
        cmd = (
            f"launchctl unload -w {LAUNCH_DAEMON_PATH} 2>/dev/null; "
            f"rm -f {LAUNCH_DAEMON_PATH} {SCRIPT_INSTALL_PATH}"
        )
        ok, out, err = run_privileged(cmd)
        if ok:
            self.persist_status.config(text="Uninstalled boot-time persistence.", fg="#0a7a0a")
        else:
            self.persist_status.config(text=f"Uninstall failed: {err or out}", fg="#a30000")

    def check_persistence(self):
        exists = os.path.exists(LAUNCH_DAEMON_PATH)
        if exists:
            ok, out, _ = run(["launchctl", "list", LAUNCH_DAEMON_LABEL])
            self.persist_status.config(
                text=f"LaunchDaemon present at {LAUNCH_DAEMON_PATH}.\n{out}", fg="#0a7a0a"
            )
        else:
            self.persist_status.config(text="Not installed.", fg="#777")


def main():
    root = tk.Tk()
    try:
        # Slightly nicer default styling where available.
        ttk.Style().theme_use("aqua" if is_macos() else "clam")
    except tk.TclError:
        pass
    app = TCPOptimizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
