"""
Diagnostic output parsers and bottleneck detectors for macOS TCP Optimizer.

Each parser turns raw CLI tool output into a structured `DiagnosticReport`
highlighting status, key metrics, misconfigurations, bottlenecks, and
actionable recommendations before presenting the raw CLI output.
"""

import ipaddress
import re


def clean_cli_output(text):
    """
    Resolve terminal carriage-return ('\\r') line overwrites (such as
    networkQuality progress updates) while preserving normal newlines.
    """
    if not text:
        return ""
    cleaned_lines = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if "\r" in line:
            parts = [p for p in line.split("\r") if p.strip()]
            if parts:
                cleaned_lines.append(parts[-1])
        else:
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


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

    def format_text(self, cmd="", include_raw=True):
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

        if include_raw:
            cmd_label = f" ({cmd})" if cmd else ""
            lines.append("-" * 76)
            lines.append(f"RAW CLI OUTPUT{cmd_label}")
            lines.append("-" * 76)
            lines.append(self.raw.strip() if self.raw.strip() else "(no output)")
        lines.append("=" * 76)
        lines.append("\n")
        return "\n".join(lines)


def _extract_current_network_block(out):
    """
    Extract only the indented block under `Current Network Information:` from
    `system_profiler SPAirPortDataType`, stopping before `Other Local Wi-Fi
    Networks:` or any sibling section so neighboring APs never leak into
    current connection metrics.
    """
    lines = out.splitlines()
    start_idx = None
    header_indent = 0
    for i, line in enumerate(lines):
        if "Current Network Information:" in line:
            start_idx = i + 1
            header_indent = len(line) - len(line.lstrip())
            break
    if start_idx is None:
        return None, ""

    block_lines = []
    ssid = None
    for line in lines[start_idx:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent:
            break
        if ssid is None:
            stripped = line.strip()
            ssid = stripped[:-1] if stripped.endswith(":") else stripped
        block_lines.append(line)
    return ssid, "\n".join(block_lines)


def parse_wifi_output(ok, out, err, cmd="", sysctls=None):
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
                m_ch = re.match(r"(\d+)(?:,(\d+))?", channel_str)
                if m_ch:
                    channel_num = int(m_ch.group(1))
                    width = f"{m_ch.group(2)}MHz" if m_ch.group(2) else None
            elif line.startswith("state:"):
                status = "Connected" if line.split(":", 1)[1].strip() == "running" else "Disconnected"
    else:
        m_status = re.search(r"Status:\s*([^\n\r]+)", out)
        if m_status:
            status = m_status.group(1).strip()

        parsed_ssid, curr_block = _extract_current_network_block(out)
        if parsed_ssid is not None:
            ssid = parsed_ssid
            status = "Connected"

        search_scope = curr_block if curr_block else ""
        if search_scope:
            m_phy = re.search(r"PHY Mode:\s*([^\n\r]+)", search_scope)
            if m_phy:
                phy_mode = m_phy.group(1).strip()

            m_chan = re.search(r"Channel:\s*([^\n\r]+)", search_scope)
            if m_chan:
                channel_str = m_chan.group(1).strip()
                m_num = re.search(r"(\d+)", channel_str)
                if m_num:
                    channel_num = int(m_num.group(1))
                if "2GHz" in channel_str or "2.4GHz" in channel_str:
                    band = "2.4 GHz"
                elif "5GHz" in channel_str:
                    band = "5 GHz"
                elif "6GHz" in channel_str:
                    band = "6 GHz"
                m_w = re.search(r"(\d+MHz)", channel_str)
                if m_w:
                    width = m_w.group(1)

            m_sec = re.search(r"Security:\s*([^\n\r]+)", search_scope)
            if m_sec:
                security = m_sec.group(1).strip()

            m_sig = re.search(r"Signal\s*/\s*Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", search_scope)
            if m_sig:
                rssi = int(m_sig.group(1))
                noise = int(m_sig.group(2))

            m_tx = re.search(r"Transmit Rate:\s*(\d+)", search_scope)
            if m_tx:
                tx_rate = int(m_tx.group(1))

            m_mcs = re.search(r"MCS Index:\s*(\d+)", search_scope)
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
    if ssid == "<redacted>":
        findings.append(("Network Name (SSID)", "<redacted> (macOS hides SSID without Location Services access)"))
    else:
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
    elif band in ("5 GHz", "6 GHz") and width == "20MHz":
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Narrow 20 MHz channel width on {band} (Channel {channel_num}). High-speed Wi-Fi 5/6 typically "
            "uses 80 MHz or 160 MHz channels; 20 MHz significantly restricts maximum throughput."
        ))
        recommendations.append(
            "Check your router's 5 GHz / 6 GHz channel width setting (80 MHz recommended for throughput)."
        )

    # 2. Legacy PHY mode
    is_modern_wifi = any(m in (phy_mode or "").lower() for m in ["802.11ac", "802.11ax", "802.11be"])
    is_legacy_wifi = not is_modern_wifi and bool(re.search(r"802\.11[abgn]\b", (phy_mode or "").lower()))
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
        summary = "Wi-Fi bottleneck detected (check frequency band, channel width, link rate, or signal)."

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


def parse_networkquality_output(ok, out, err, cmd="", sysctls=None):
    """Parse networkQuality CLI output."""
    cleaned_out = clean_cli_output(out)
    raw = cleaned_out if cleaned_out.strip() else (err or out)

    has_partial_metrics = bool(
        cleaned_out and ("Downlink capacity:" in cleaned_out or "Uplink capacity:" in cleaned_out or "capacity " in cleaned_out)
    )

    if not ok and not has_partial_metrics:
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

    # Uplink / Downlink capacity (supports both summary lines and progress lines on timeout)
    ul_match = re.search(r"Uplink capacity:\s*([\d\.]+)\s*(\w+ps)", cleaned_out)
    if not ul_match:
        ul_match = re.search(r"Uplink:\s*capacity\s*([\d\.]+)\s*(\w+ps)", cleaned_out)
    dl_match = re.search(r"Downlink capacity:\s*([\d\.]+)\s*(\w+ps)", cleaned_out)
    if not dl_match:
        dl_match = re.search(r"Downlink:\s*capacity\s*([\d\.]+)\s*(\w+ps)", cleaned_out)

    ul_val = float(ul_match.group(1)) if ul_match else None
    ul_unit = ul_match.group(2) if ul_match else "Mbps"
    dl_val = float(dl_match.group(1)) if dl_match else None
    dl_unit = dl_match.group(2) if dl_match else "Mbps"

    dl_mbps = _to_mbps(dl_val, dl_unit)

    # Responsiveness
    resp_rating = None
    resp_ms = None
    resp_rpm = None
    m_resp1 = re.search(r"Responsiveness:\s*(\w+)\s*\(([\d\.]+)\s*milliseconds\s*\|\s*(\d+)\s*RPM\)", cleaned_out)
    if m_resp1:
        resp_rating = m_resp1.group(1)
        resp_ms = float(m_resp1.group(2))
        resp_rpm = int(m_resp1.group(3))
    else:
        m_resp2 = re.search(r"Responsiveness:\s*(\w+)\s*\n\s*(\d+)\s*RPM\s*\(([\d\.]+)\s*milliseconds\)", cleaned_out)
        if m_resp2:
            resp_rating = m_resp2.group(1)
            resp_rpm = int(m_resp2.group(2))
            resp_ms = float(m_resp2.group(3))
        else:
            m_resp3 = re.search(r"Responsiveness:\s*(\w+)", cleaned_out)
            if m_resp3:
                resp_rating = m_resp3.group(1)
            else:
                m_prog_rpm = re.search(r"responsiveness\s+(\d+)\s+RPM", cleaned_out)
                if m_prog_rpm:
                    resp_rpm = int(m_prog_rpm.group(1))

    # Idle Latency
    idle_ms = None
    idle_rpm = None
    m_idle1 = re.search(r"Idle Latency:\s*([\d\.]+)\s*milliseconds(?:\s*\|\s*(\d+)\s*RPM)?", cleaned_out)
    if m_idle1:
        idle_ms = float(m_idle1.group(1))
        if m_idle1.group(2):
            idle_rpm = int(m_idle1.group(2))
    else:
        m_idle2 = re.search(r"Idle Latency:\s*\n\s*(?:(\d+)\s*RPM\s*\()?([\d\.]+)\s*milliseconds", cleaned_out)
        if m_idle2:
            idle_ms = float(m_idle2.group(2))
            if m_idle2.group(1):
                idle_rpm = int(m_idle2.group(1))

    # Endpoint & Interface
    ep_match = re.search(r"Test Endpoint:\s*([^\n\r]+)", cleaned_out)
    test_ep = ep_match.group(1).strip() if ep_match else None
    iface_match = re.search(r"Interface:\s*([^\n\r]+)", cleaned_out)
    test_iface = iface_match.group(1).strip() if iface_match else None

    # ECN / L4S
    ecn_match = re.search(r"ECN\s*(Disabled|Enabled)", cleaned_out, re.IGNORECASE)
    ecn_status = ecn_match.group(1) if ecn_match else None

    # Compile findings
    if dl_val is not None:
        findings.append(("Downlink Speed", f"{dl_val:.2f} {dl_unit}"))
    if ul_val is not None:
        findings.append(("Uplink Speed", f"{ul_val:.2f} {ul_unit}"))

    if resp_rating:
        detail = []
        if resp_rpm is not None:
            detail.append(f"{resp_rpm} RPM")
        if resp_ms is not None:
            detail.append(f"{resp_ms:.1f} ms loaded latency")
        resp_str = f"{resp_rating} ({', '.join(detail)})" if detail else resp_rating
        findings.append(("Responsiveness", resp_str))
    elif resp_rpm is not None:
        findings.append(("Responsiveness", f"{resp_rpm} RPM (partial)"))

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

    if not ok and has_partial_metrics:
        report_status = "WARNING"
        issues.append((
            "WARNING",
            f"Test timed out before completion ({err or 'timeout'}); showing partial metrics captured so far."
        ))

    # Bufferbloat evaluation
    if resp_rating == "Low" or (resp_rpm is not None and resp_rpm < 100) or (resp_ms is not None and resp_ms > 250):
        report_status = "WARNING"
        bloat_str = f" (+{resp_ms - idle_ms:.0f} ms bloat)" if (idle_ms is not None and resp_ms is not None) else ""
        issues.append((
            "WARNING",
            f"Severe Bufferbloat Detected: Responsiveness rated Low ({resp_rpm or 'N/A'} RPM, {resp_ms or 'N/A'} ms loaded latency){bloat_str}. "
            "Network queues in your router/modem are filling with packets, causing ping spikes, video call lag, and stuttering during downloads."
        ))
        recommendations.append(
            "Enable Smart Queue Management (SQM, e.g. CAKE or FQ-CoDel) on your home router."
        )
        if sysctls and sysctls.get("net.inet.tcp.delayed_ack") not in (None, "0"):
            recommendations.append(
                f"Current net.inet.tcp.delayed_ack is {sysctls['net.inet.tcp.delayed_ack']}. "
                "Try the 'Low-Latency / Gaming' preset (delayed_ack=0) on the Presets tab to prioritize responsiveness."
            )
        else:
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

    # Cross-tab sysctl correlation
    if sysctls and sysctls.get("net.inet.tcp.win_scale_factor") == "0":
        if report_status != "ERROR":
            report_status = "WARNING"
        issues.append((
            "WARNING",
            "TCP Window Scaling is disabled (net.inet.tcp.win_scale_factor = 0), capping TCP receive windows at 64 KB "
            "and bottlenecking high-bandwidth links."
        ))
        recommendations.append("Apply 'Balanced Gigabit' or reset to macOS Default on the Presets tab.")

    if report_status == "OK":
        summary = "Network capacity and latency responsiveness are optimal."
    else:
        summary = "Network issues detected (bufferbloat, timeout, or limited throughput)."

    return DiagnosticReport(
        title="Network Quality Test",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


def parse_ifconfig_output(ok, out, err, cmd="", sysctls=None):
    """Parse ifconfig CLI output and correlate MTU with sysctl net.inet.tcp.mssdflt."""
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
        m = re.match(r"^([a-zA-Z0-9]+):\s*flags=\d+<([^>]+)>\s*mtu\s*(\d+)", line)
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

    mssdflt_val = None
    if sysctls and sysctls.get("net.inet.tcp.mssdflt"):
        try:
            mssdflt_val = int(sysctls["net.inet.tcp.mssdflt"])
        except ValueError:
            pass

    for iface in active_physical:
        name = iface["name"]
        mtu = iface["mtu"]
        ipv4_strs = [f"{ip}" for ip, _ in iface["ipv4"]]
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
            mss_note = ""
            if mssdflt_val is not None and mssdflt_val > mtu - 40:
                mss_note = f" Currently net.inet.tcp.mssdflt={mssdflt_val} exceeds MTU-40 ({mtu - 40})."
            issues.append((
                "WARNING",
                f"Sub-standard MTU ({mtu} bytes) on {name} (standard Ethernet is 1500). Packets larger than {mtu} bytes will be "
                f"fragmented. If Path MTU Discovery (PMTUD) is blocked by intermediate firewalls, connections may hang or stall.{mss_note}"
            ))
            recommendations.append(
                f"Adjust net.inet.tcp.mssdflt on the Advanced tab to {mtu - 40} bytes (MTU - 40) if connections stall."
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


def _extract_dig_metrics(out):
    """Extract (status, query_time_ms, server, resolved_ips) from dig output."""
    dns_status = None
    query_time_ms = None
    dns_server = None
    resolved_ips = []

    m_status = re.search(r"status:\s*([A-Z]+)", out)
    if m_status:
        dns_status = m_status.group(1)

    m_time = re.search(r";;\s*Query time:\s*(\d+)\s*msec", out)
    if m_time:
        query_time_ms = int(m_time.group(1))

    m_srv = re.search(r";;\s*SERVER:\s*([^\n\r]+)", out)
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

    return dns_status, query_time_ms, dns_server, resolved_ips


def _parse_scutil_dns(scutil_out):
    """Extract primary nameserver(s) and search domains from `scutil --dns`."""
    nameservers = []
    search_domains = []
    for line in scutil_out.splitlines():
        s = line.strip()
        m_ns = re.match(r"nameserver\[\d+\]\s*:\s*(.+)", s)
        if m_ns:
            ns = m_ns.group(1).strip()
            if ns not in nameservers:
                nameservers.append(ns)
        m_sd = re.match(r"search domain\[\d+\]\s*:\s*(.+)", s)
        if m_sd:
            sd = m_sd.group(1).strip()
            if sd not in search_domains:
                search_domains.append(sd)
    return nameservers, search_domains


def parse_dns_output(
    ok,
    out,
    err,
    cmd="",
    elapsed_ms=None,
    comparison_ok=None,
    comparison_out=None,
    scutil_out=None,
):
    """
    Parse DNS CLI output (dig or nslookup), optional elapsed_ms fallback timing,
    optional direct public resolver comparison (e.g. @1.1.1.1), and optional
    `scutil --dns` configuration output.
    """
    raw_sections = [out if ok else (err or out)]
    if comparison_out:
        raw_sections.append("\n--- Direct Public Resolver Comparison (1.1.1.1) ---\n" + comparison_out.strip())
    if scutil_out:
        raw_sections.append("\n--- System DNS Configuration (scutil --dns) ---\n" + scutil_out.strip())
    raw = "\n".join(s for s in raw_sections if s)

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
        dns_status, query_time_ms, dns_server, resolved_ips = _extract_dig_metrics(out)
    else:
        m_srv = re.search(r"Server:\s*([^\n\r]+)", out)
        m_addr = re.search(r"Address:\s*([^\n\r]+)", out)
        if m_srv:
            dns_server = m_srv.group(1).strip()
            if m_addr:
                dns_server += f" ({m_addr.group(1).strip()})"
        for m in re.finditer(r"Address:\s*([0-9\.]+)", out):
            ip_found = m.group(1).strip()
            if dns_server and ip_found not in dns_server:
                resolved_ips.append(ip_found)
        if "** server can't find" in out or "connection timed out" in out.lower():
            dns_status = "SERVFAIL"
        else:
            dns_status = "NOERROR"
        if elapsed_ms is not None:
            query_time_ms = int(round(elapsed_ms))

    if query_time_ms is None and elapsed_ms is not None:
        query_time_ms = int(round(elapsed_ms))

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
        m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", dns_server)
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

    # Direct 1.1.1.1 comparison
    if comparison_ok and comparison_out:
        comp_status, comp_time, _, _ = _extract_dig_metrics(comparison_out)
        if comp_status == "NOERROR" and comp_time is not None:
            findings.append(("Cloudflare 1.1.1.1", f"{comp_time} ms (direct comparison)"))
            if query_time_ms is not None and query_time_ms > 80 and comp_time < 40:
                if report_status != "ERROR":
                    report_status = "WARNING"
                issues.append((
                    "WARNING",
                    f"Configured DNS resolver ({query_time_ms} ms) is significantly slower than direct 1.1.1.1 ({comp_time} ms). "
                    "Your ISP or router DNS forwarder is adding unnecessary latency."
                ))
                recommendations.append("Switch your Mac or router DNS to 1.1.1.1 / 8.8.8.8.")

    # System scutil --dns info
    if scutil_out:
        nameservers, search_domains = _parse_scutil_dns(scutil_out)
        if nameservers:
            findings.append(("Configured Resolvers", ", ".join(nameservers[:4])))
        if search_domains:
            findings.append(("Search Domains", ", ".join(search_domains[:4])))

    if report_status == "OK":
        summary = f"DNS resolution is fast and functional ({query_time_ms if query_time_ms is not None else '<25'} ms)."
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


def extract_default_gateway(route_out):
    """Extract (gateway_ip, interface) from `route -n get default` output."""
    gw = None
    iface = None
    for line in (route_out or "").splitlines():
        s = line.strip()
        if s.startswith("gateway:"):
            gw = s.split(":", 1)[1].strip()
        elif s.startswith("interface:"):
            iface = s.split(":", 1)[1].strip()
    return gw, iface


def _parse_single_ping(out):
    """Parse macOS `ping` output into stats dict."""
    tx = rx = loss = None
    rtt_min = rtt_avg = rtt_max = rtt_stddev = None

    m_pkt = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+packets received,\s+([\d\.]+)%\s+packet loss",
        out,
    )
    if m_pkt:
        tx = int(m_pkt.group(1))
        rx = int(m_pkt.group(2))
        loss = float(m_pkt.group(3))

    m_rtt = re.search(
        r"round-trip min/avg/max/stddev\s*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)\s*ms",
        out,
    )
    if m_rtt:
        rtt_min = float(m_rtt.group(1))
        rtt_avg = float(m_rtt.group(2))
        rtt_max = float(m_rtt.group(3))
        rtt_stddev = float(m_rtt.group(4))

    return {
        "tx": tx,
        "rx": rx,
        "loss": loss,
        "min": rtt_min,
        "avg": rtt_avg,
        "max": rtt_max,
        "stddev": rtt_stddev,
    }


def parse_ping_output(
    gw_ip,
    gw_iface,
    gw_ok,
    gw_out,
    gw_err,
    inet_ok,
    inet_out,
    inet_err,
    inet_target="1.1.1.1",
):
    """
    Parse gateway and internet ICMP ping results to separate local LAN/Wi-Fi
    packet loss & jitter from upstream ISP latency or packet loss.
    """
    sections = []
    if gw_ip:
        sections.append(f"--- Default Gateway ({gw_ip} via {gw_iface or '?'}) ---\n{(gw_out if gw_ok else (gw_err or gw_out)).strip()}")
    else:
        sections.append("--- Default Gateway ---\n(no default gateway found)")
    sections.append(f"--- Internet Target ({inet_target}) ---\n{(inet_out if inet_ok else (inet_err or inet_out)).strip()}")
    raw = "\n\n".join(sections)

    findings = []
    issues = []
    recommendations = []
    report_status = "OK"

    if gw_ip:
        findings.append(("Default Gateway", f"{gw_ip}{f' ({gw_iface})' if gw_iface else ''}"))
        gw_stats = _parse_single_ping(gw_out)
        if gw_stats["loss"] is not None:
            rtt_part = (
                f", avg {gw_stats['avg']:.1f} ms (jitter/stddev {gw_stats['stddev']:.1f} ms, max {gw_stats['max']:.1f} ms)"
                if gw_stats["avg"] is not None
                else ""
            )
            findings.append(("Gateway Ping", f"{gw_stats['loss']:.1f}% loss{rtt_part}"))

            if gw_stats["loss"] > 0:
                report_status = "ERROR" if gw_stats["loss"] >= 25.0 else "WARNING"
                issues.append((
                    "ERROR" if gw_stats["loss"] >= 25.0 else "WARNING",
                    f"Local Packet Loss to Gateway ({gw_stats['loss']:.1f}% loss to {gw_ip}). "
                    "Packets are dropping inside your local Wi-Fi or Ethernet link before even reaching the internet. "
                    "Even small local packet loss causes TCP congestion control to slash throughput."
                ))
                recommendations.append(
                    "Check Wi-Fi signal/band (switch from 2.4 GHz to 5 GHz), or inspect Ethernet cables and switch ports."
                )
            elif gw_stats["stddev"] is not None and gw_stats["stddev"] > 10.0:
                report_status = "WARNING"
                issues.append((
                    "WARNING",
                    f"High Local Network Jitter (stddev {gw_stats['stddev']:.1f} ms, max {gw_stats['max']:.1f} ms to {gw_ip}). "
                    "Indicates wireless interference or AP contention."
                ))
                recommendations.append("Use 5 GHz Wi-Fi on a clean channel or test over wired Ethernet.")
        elif not gw_ok:
            report_status = "WARNING"
            issues.append(("WARNING", f"Gateway {gw_ip} did not respond to ping ({gw_err or 'timeout'})."))
    else:
        report_status = "ERROR"
        issues.append(("ERROR", "No default IPv4 gateway found in routing table."))
        recommendations.append("Verify Wi-Fi or Ethernet connection and DHCP lease in Network Settings.")

    inet_stats = _parse_single_ping(inet_out)
    if inet_stats["loss"] is not None:
        rtt_part = (
            f", avg {inet_stats['avg']:.1f} ms (jitter {inet_stats['stddev']:.1f} ms, max {inet_stats['max']:.1f} ms)"
            if inet_stats["avg"] is not None
            else ""
        )
        findings.append((f"Internet Ping ({inet_target})", f"{inet_stats['loss']:.1f}% loss{rtt_part}"))

        if inet_stats["loss"] > 0:
            gw_clean = gw_ip and _parse_single_ping(gw_out).get("loss") == 0.0
            if gw_clean:
                if report_status != "ERROR":
                    report_status = "WARNING"
                issues.append((
                    "WARNING",
                    f"Upstream Packet Loss ({inet_stats['loss']:.1f}% loss to {inet_target} while local gateway had 0% loss). "
                    "The packet loss is occurring on your ISP/modem line or upstream routing, not on your Mac or LAN."
                ))
                recommendations.append("Check modem signal levels / coax or fiber connections, or contact your ISP.")
            else:
                report_status = "ERROR" if inet_stats["loss"] >= 25.0 else "WARNING"
                issues.append((
                    "ERROR" if inet_stats["loss"] >= 25.0 else "WARNING",
                    f"Internet packet loss detected ({inet_stats['loss']:.1f}% to {inet_target})."
                ))
        elif inet_stats["avg"] is not None and inet_stats["avg"] > 80.0:
            if report_status == "OK":
                report_status = "WARNING"
            issues.append((
                "WARNING",
                f"High Internet Ping ({inet_stats['avg']:.1f} ms avg to {inet_target})."
            ))
    elif not inet_ok:
        report_status = "ERROR"
        issues.append(("ERROR", f"Unable to ping internet target {inet_target}: {inet_err or 'no response'}"))
        recommendations.append("Verify internet connectivity and firewall ICMP rules.")

    if report_status == "OK":
        summary = "Zero packet loss and low latency to both local gateway and internet."
    elif report_status == "WARNING":
        summary = "Packet loss or latency jitter detected on the network path."
    else:
        summary = "Network reachability error or severe packet loss detected."

    return DiagnosticReport(
        title="Gateway + Internet Ping",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )


def parse_tcp_stats_output(
    in_ok,
    in_out,
    in_err,
    s_ok,
    s_out,
    s_err,
    anv_ok,
    anv_out,
    anv_err,
    sysctls=None,
):
    """
    Parse interface error counters (`netstat -in`), TCP stack stats (`netstat -s -p tcp`),
    and active socket queues/windows (`netstat -anv -p tcp`).
    """
    raw_parts = [
        f"--- Interface Packet & Error Counters (netstat -in) ---\n{(in_out if in_ok else (in_err or in_out)).strip()}",
        f"--- TCP Stack Summary (netstat -s -p tcp) ---\n{(s_out if s_ok else (s_err or s_out)).strip()}",
    ]
    if anv_ok and anv_out:
        anv_lines = anv_out.splitlines()
        preview = "\n".join(anv_lines[:40])
        if len(anv_lines) > 40:
            preview += f"\n... ({len(anv_lines) - 40} more socket lines truncated)"
        raw_parts.append(f"--- Active TCP Sockets (netstat -anv -p tcp) ---\n{preview}")
    raw = "\n\n".join(raw_parts)

    findings = []
    issues = []
    recommendations = []
    report_status = "OK"

    # 1. Parse netstat -in link counters
    total_ipkts = 0
    total_opkts = 0
    error_ifaces = []
    if in_ok and in_out:
        for line in in_out.splitlines():
            if "<Link#" not in line:
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            name = parts[0].rstrip("*")
            if name == "lo0":
                continue
            try:
                ipkts = int(parts[-5])
                ierrs = int(parts[-4])
                opkts = int(parts[-3])
                oerrs = int(parts[-2])
                coll = int(parts[-1])
            except ValueError:
                continue
            total_ipkts += ipkts
            total_opkts += opkts
            if ierrs > 0 or oerrs > 0 or coll > 0:
                error_ifaces.append((name, ipkts, ierrs, opkts, oerrs, coll))

        findings.append(("Interface Traffic", f"{total_ipkts:,} pkts in / {total_opkts:,} pkts out (non-loopback)"))
        if error_ifaces:
            report_status = "WARNING"
            for name, ipkts, ierrs, opkts, oerrs, coll in error_ifaces:
                issues.append((
                    "WARNING",
                    f"Hardware/Link Errors on {name}: {ierrs} input errors, {oerrs} output errors, {coll} collisions."
                ))
            recommendations.append("Check Ethernet cables/ports or Wi-Fi interference if interface error counts are growing.")

    # 2. Parse netstat -s -p tcp
    if s_ok and s_out:
        m_open = re.search(r"(\d+)\s+open TCP sockets", s_out)
        if m_open:
            findings.append(("Open TCP Sockets", m_open.group(1)))

        m_data = re.search(r"(\d+)\s+data packets?\s+\(", s_out)
        m_retx = re.search(r"(\d+)\s+data packets?\s+\([^)]+\)\s+retransmitted", s_out)
        m_ooo = re.search(r"(\d+)\s+out-of-order packets?", s_out)
        m_dupack = re.search(r"(\d+)\s+duplicate acks?", s_out)

        data_pkts = int(m_data.group(1)) if m_data else 0
        retx_pkts = int(m_retx.group(1)) if m_retx else 0
        ooo_pkts = int(m_ooo.group(1)) if m_ooo else 0
        dupack_cnt = int(m_dupack.group(1)) if m_dupack else 0

        if data_pkts == 0 and total_opkts > 100:
            findings.append(("Kernel TCP Counters", "Restricted (macOS zeroes per-packet TCP stats unprivileged)"))
        elif data_pkts > 0:
            retx_pct = (retx_pkts / data_pkts) * 100.0
            findings.append(("TCP Retransmissions", f"{retx_pkts:,} of {data_pkts:,} data pkts ({retx_pct:.2f}%)"))
            findings.append(("Out-of-Order / DupACK", f"{ooo_pkts:,} out-of-order, {dupack_cnt:,} dup ACKs"))
            if retx_pct > 2.0:
                report_status = "WARNING"
                issues.append((
                    "WARNING",
                    f"Elevated TCP Retransmission Rate ({retx_pct:.2f}%). Packet loss or severe congestion is forcing frequent resends."
                ))
                recommendations.append("Run the Gateway + Internet Ping check to locate where packets are dropping.")

    # 3. Parse netstat -anv -p tcp
    if anv_ok and anv_out:
        state_counts = {}
        max_rhiwat = 0
        max_shiwat = 0
        queued_sockets = 0
        for line in anv_out.splitlines():
            if not line.startswith("tcp"):
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                recv_q = int(parts[1])
                send_q = int(parts[2])
            except ValueError:
                continue
            state = parts[5]
            state_counts[state] = state_counts.get(state, 0) + 1
            if recv_q > 65536 or send_q > 65536:
                queued_sockets += 1
            try:
                rhiwat = int(parts[8])
                shiwat = int(parts[9])
                if rhiwat > max_rhiwat:
                    max_rhiwat = rhiwat
                if shiwat > max_shiwat:
                    max_shiwat = shiwat
            except ValueError:
                pass

        if state_counts:
            top_states = ", ".join(f"{k}: {v}" for k, v in sorted(state_counts.items(), key=lambda kv: -kv[1])[:4])
            findings.append(("Socket States", top_states))
        if max_rhiwat or max_shiwat:
            findings.append((
                "Observed Auto-Buffers",
                f"max recv high-water: {max_rhiwat:,} B / max send high-water: {max_shiwat:,} B"
            ))
        if queued_sockets > 0:
            if report_status == "OK":
                report_status = "WARNING"
            issues.append((
                "WARNING",
                f"{queued_sockets} TCP socket(s) currently have >64 KB queued in Recv-Q/Send-Q, indicating stalled transfer or backpressure."
            ))

    # 4. Cross-tab sysctl checks
    if sysctls:
        if sysctls.get("net.inet.tcp.win_scale_factor") == "0":
            report_status = "WARNING"
            issues.append((
                "WARNING",
                "TCP window scaling is disabled (net.inet.tcp.win_scale_factor=0), limiting effective receive windows to 64 KB."
            ))
            recommendations.append("Reset or apply 'Balanced Gigabit' on the Presets tab to re-enable window scaling.")

    if not in_ok and not s_ok and not anv_ok:
        return DiagnosticReport(
            title="TCP Stack + Interface Stats",
            status="ERROR",
            summary="Failed to collect netstat diagnostics.",
            issues=[("ERROR", in_err or s_err or anv_err or "netstat failed")],
            raw=raw,
        )

    if report_status == "OK":
        summary = "No interface errors, socket stalls, or TCP stack misconfigurations observed."
    else:
        summary = "Interface errors, socket backpressure, or TCP stack warnings detected."

    return DiagnosticReport(
        title="TCP Stack + Interface Stats",
        status=report_status,
        summary=summary,
        findings=findings,
        issues=issues,
        recommendations=recommendations,
        raw=raw,
    )
