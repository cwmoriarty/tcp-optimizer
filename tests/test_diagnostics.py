#!/usr/bin/env python3
"""
Unit tests for TCP Optimizer's diagnostic output parsers and bottleneck detectors.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path so we can import tcp_optimizer
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from tcp_optimizer import (
    DiagnosticReport,
    parse_wifi_output,
    parse_networkquality_output,
    parse_ifconfig_output,
    parse_dns_output,
)


class TestDiagnosticParsers(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # Wi-Fi Parser Tests
    # ------------------------------------------------------------------ #
    def test_wifi_system_profiler_2ghz_bottleneck(self):
        sample = """
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          MAC Address: 1e:ea:1c:5c:ab:2a
          Status: Connected
          Current Network Information:
            Home_Network_2G:
              PHY Mode: 802.11n
              Channel: 1 (2GHz, 20MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA2/WPA3 Personal
              Signal / Noise: -64 dBm / -96 dBm
              Transmit Rate: 144
              MCS Index: 15
        """
        rep = parse_wifi_output(True, sample, "", "system_profiler SPAirPortDataType")
        self.assertEqual(rep.status, "WARNING")
        # Check findings
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Network Name (SSID)"), "Home_Network_2G")
        self.assertEqual(findings_dict.get("Wi-Fi Standard"), "802.11n")
        self.assertIn("144 Mbps", findings_dict.get("Transmit Rate", ""))
        self.assertIn("-64 dBm", findings_dict.get("Signal Strength", ""))

        # Check issues: should flag 2.4 GHz, legacy 802.11n, and low link rate
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("2.4 GHz band", issue_texts)
        self.assertIn("802.11n", issue_texts)
        self.assertIn("144 Mbps", issue_texts)
        self.assertTrue(any("5 GHz" in r for r in rep.recommendations))

    def test_wifi_system_profiler_5ghz_healthy(self):
        sample = """
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            FastOffice_5G:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Security: WPA3 Personal
              Signal / Noise: -50 dBm / -95 dBm
              Transmit Rate: 1200
              MCS Index: 11
        """
        rep = parse_wifi_output(True, sample, "", "system_profiler SPAirPortDataType")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Network Name (SSID)"), "FastOffice_5G")
        self.assertEqual(findings_dict.get("Wi-Fi Standard"), "802.11ax")
        self.assertIn("1200 Mbps", findings_dict.get("Transmit Rate", ""))

    def test_wifi_airport_legacy_format(self):
        sample = """
agrCtlRSSI: -78
agrCtlNoise: -92
state: running
op mode: station
lastTxRate: 54
maxRate: 54
lastAssocStatus: 0
802.11 auth: open
link auth: none
BSSID: 00:11:22:33:44:55
SSID: Cafe_Guest
MCS: 7
channel: 6,20
        """
        rep = parse_wifi_output(True, sample, "", "airport -I")
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Network Name (SSID)"), "Cafe_Guest")
        self.assertIn("54 Mbps", findings_dict.get("Transmit Rate", ""))

        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("2.4 GHz", issue_texts)
        self.assertIn("Weak Wi-Fi signal", issue_texts)
        self.assertIn("Insecure Wi-Fi", issue_texts)

    def test_wifi_disconnected(self):
        sample = """
      Interfaces:
        en0:
          Card Type: Wi-Fi
          Status: Not Associated
        """
        rep = parse_wifi_output(True, sample, "", "system_profiler SPAirPortDataType")
        self.assertIn(rep.status, ("INFO", "WARNING"))
        self.assertTrue(any("not connected" in desc.lower() for _, desc in rep.issues))

    def test_wifi_command_failure(self):
        rep = parse_wifi_output(False, "", "device not found", "airport -I")
        self.assertEqual(rep.status, "ERROR")
        self.assertTrue(any("device not found" in desc for _, desc in rep.issues))

    # ------------------------------------------------------------------ #
    # Network Quality Parser Tests
    # ------------------------------------------------------------------ #
    def test_networkquality_bufferbloat_and_low_capacity(self):
        sample = """
==== SUMMARY ====
Uplink capacity: 31.836 Mbps
Downlink capacity: 4.424 Mbps
Responsiveness: Low (679.367 milliseconds | 88 RPM)
Idle Latency: 24.318 milliseconds | 2467 RPM
        """
        rep = parse_networkquality_output(True, sample, "", "networkQuality -v")
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Downlink Speed"), "4.42 Mbps")
        self.assertEqual(findings_dict.get("Uplink Speed"), "31.84 Mbps")
        self.assertIn("88 RPM", findings_dict.get("Responsiveness", ""))
        self.assertIn("679.4 ms", findings_dict.get("Responsiveness", ""))
        self.assertIn("+655.0 ms", findings_dict.get("Bufferbloat Delta", ""))

        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Bufferbloat Detected", issue_texts)
        self.assertIn("Low Downlink Capacity", issue_texts)
        self.assertTrue(any("Smart Queue Management" in r for r in rep.recommendations))

    def test_networkquality_optimal_gigabit(self):
        sample = """
==== SUMMARY ====
Uplink capacity: 540.210 Mbps
Downlink capacity: 924.500 Mbps
Responsiveness: High (15.200 milliseconds | 3947 RPM)
Idle Latency: 11.400 milliseconds | 5263 RPM
        """
        rep = parse_networkquality_output(True, sample, "", "networkQuality -v")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Downlink Speed"), "924.50 Mbps")
        self.assertIn("High", findings_dict.get("Responsiveness", ""))

    def test_networkquality_verbose_multiline(self):
        sample = """
==== Verbose Results ====
---
Capacity:
---
   Uplink capacity: 45.120 Mbps
   Downlink capacity: 120.450 Mbps
---
Latency:
---
   Idle Latency:
      2400 RPM (25.000 milliseconds)
   Responsiveness: Low
      85 RPM (705.882 milliseconds)
---
Transport-layer info:
---
    ECN Disabled: 100%, L4S Disabled: 100%
---
Other Info:
---
   Test Endpoint: edge-server.apple.com
   Interface: en0
        """
        rep = parse_networkquality_output(True, sample, "", "networkQuality -v")
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Downlink Speed"), "120.45 Mbps")
        self.assertIn("85 RPM", findings_dict.get("Responsiveness", ""))
        self.assertEqual(findings_dict.get("Test Endpoint"), "edge-server.apple.com")
        self.assertEqual(findings_dict.get("Tested Interface"), "en0")

    def test_networkquality_not_found_old_macos(self):
        rep = parse_networkquality_output(False, "", "networkQuality: command not found", "networkQuality -v")
        self.assertEqual(rep.status, "INFO")
        self.assertTrue(any("Monterey" in desc for _, desc in rep.issues))

    # ------------------------------------------------------------------ #
    # Ifconfig Parser Tests
    # ------------------------------------------------------------------ #
    def test_ifconfig_normal_gigabit(self):
        sample = """
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether a0:b1:c2:d3:e4:f5
	inet 192.168.1.150 netmask 0xffffff00 broadcast 192.168.1.255
	media: autoselect (1000baseT <full-duplex>)
	status: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	media: none
	status: inactive
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)
        findings_dict = dict(rep.findings)
        self.assertIn("Interface en0", findings_dict)
        self.assertIn("1000baseT", findings_dict["Interface en0"])
        self.assertIn("192.168.1.150", findings_dict["Interface en0"])

    def test_ifconfig_100basetx_bottleneck(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.150 netmask 0xffffff00 broadcast 192.168.1.255
	media: autoselect (100baseTX <full-duplex>)
	status: active
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "WARNING")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("100baseTX", issue_texts)
        self.assertIn("94 Mbps", issue_texts)
        self.assertTrue(any("Cat5e" in r or "Cat6" in r for r in rep.recommendations))

    def test_ifconfig_half_duplex_error(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.150 netmask 0xffffff00 broadcast 192.168.1.255
	media: autoselect (1000baseT <half-duplex>)
	status: active
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "ERROR")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("half-duplex", issue_texts.lower())

    def test_ifconfig_apipa_dhcp_failure(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 169.254.42.12 netmask 0xffff0000 broadcast 169.254.255.255
	status: active
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "ERROR")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Self-assigned IP", issue_texts)
        self.assertIn("DHCP", issue_texts)

    def test_ifconfig_substandard_mtu(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1400
	inet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
	media: autoselect
	status: active
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "WARNING")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Sub-standard MTU (1400 bytes)", issue_texts)

    def test_ifconfig_vpn_tunnels(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
	status: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
	inet6 fe80::1%utun1 prefixlen 64
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "OK")
        findings_dict = dict(rep.findings)
        self.assertIn("Active VPN Tunnels", findings_dict)
        self.assertIn("utun0", findings_dict["Active VPN Tunnels"])

    # ------------------------------------------------------------------ #
    # DNS Parser Tests
    # ------------------------------------------------------------------ #
    def test_dns_dig_fast(self):
        sample = """
; <<>> DiG 9.10.6 <<>> example.com
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
example.com.		300	IN	A	93.184.215.14

;; Query time: 8 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
        """
        rep = parse_dns_output(True, sample, "", "dig example.com")
        self.assertEqual(rep.status, "OK")
        findings_dict = dict(rep.findings)
        self.assertIn("8 ms", findings_dict.get("Query Latency", ""))
        self.assertEqual(findings_dict.get("Response Status"), "NOERROR")
        self.assertIn("1.1.1.1", findings_dict.get("DNS Resolver", ""))
        self.assertIn("93.184.215.14", findings_dict.get("Resolved Addresses", ""))

    def test_dns_dig_slow_latency(self):
        sample = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; ANSWER SECTION:
example.com.		300	IN	A	93.184.215.14
;; Query time: 240 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
        """
        rep = parse_dns_output(True, sample, "", "dig example.com")
        self.assertEqual(rep.status, "WARNING")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Slow DNS Resolution (240 ms)", issue_texts)
        self.assertTrue(any("Cloudflare" in r or "Google" in r for r in rep.recommendations))

    def test_dns_dig_servfail(self):
        sample = """
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 12345
;; Query time: 100 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
        """
        rep = parse_dns_output(True, sample, "", "dig example.com")
        self.assertEqual(rep.status, "ERROR")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("SERVFAIL", issue_texts)

    def test_dns_nslookup_fallback(self):
        sample = """
Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
Name:	example.com
Address: 93.184.215.14
        """
        rep = parse_dns_output(True, sample, "", "nslookup example.com")
        self.assertEqual(rep.status, "OK")
        findings_dict = dict(rep.findings)
        self.assertIn("192.168.1.1", findings_dict.get("DNS Resolver", ""))
        self.assertIn("93.184.215.14", findings_dict.get("Resolved Addresses", ""))

    # ------------------------------------------------------------------ #
    # Formatter Test
    # ------------------------------------------------------------------ #
    def test_report_format_text_includes_sections_and_raw(self):
        raw_cmd_output = "raw output line 1\nraw output line 2"
        rep = DiagnosticReport(
            title="Sample Test",
            status="WARNING",
            summary="Potential bottleneck detected.",
            findings=[("Key1", "Val1"), ("Key2", "Val2")],
            issues=[("WARNING", "Bottleneck issue occurred.")],
            recommendations=["Try fixing setting X."],
            raw=raw_cmd_output,
        )
        formatted = rep.format_text(cmd="sample_tool -v")
        self.assertIn("DIAGNOSTIC REPORT: SAMPLE TEST", formatted)
        self.assertIn("Status: [WARNING] Potential bottleneck detected.", formatted)
        self.assertIn("Key1                  : Val1", formatted)
        self.assertIn("⚠️ [WARNING] Bottleneck issue occurred.", formatted)
        self.assertIn("→ Try fixing setting X.", formatted)
        self.assertIn("RAW CLI OUTPUT (sample_tool -v)", formatted)
        self.assertIn(raw_cmd_output, formatted)


if __name__ == "__main__":
    unittest.main()
