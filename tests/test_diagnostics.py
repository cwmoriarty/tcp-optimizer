#!/usr/bin/env python3
"""
Unit tests for TCP Optimizer's diagnostic output parsers and bottleneck detectors.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path so we can import diagnostics directly (no Tk needed)
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from diagnostics import (
    DiagnosticReport,
    clean_cli_output,
    extract_default_gateway,
    parse_dns_output,
    parse_ifconfig_output,
    parse_networkquality_output,
    parse_ping_output,
    parse_tcp_stats_output,
    parse_wifi_output,
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
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Network Name (SSID)"), "Home_Network_2G")
        self.assertEqual(findings_dict.get("Wi-Fi Standard"), "802.11n")
        self.assertIn("144 Mbps", findings_dict.get("Transmit Rate", ""))
        self.assertIn("-64 dBm", findings_dict.get("Signal Strength", ""))

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

    def test_wifi_scopes_to_current_network_and_handles_colons_and_redacted(self):
        sample = """
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            My:Home:Net:
              PHY Mode: 802.11ax
              Channel: 149 (5GHz, 80MHz)
              Security: WPA3 Personal
              Signal / Noise: -55 dBm / -92 dBm
              Transmit Rate: 960
          Other Local Wi-Fi Networks:
            Neighbor_2G:
              PHY Mode: 802.11b/g/n
              Channel: 1 (2GHz, 20MHz)
              Signal / Noise: -88 dBm / -90 dBm
        """
        rep = parse_wifi_output(True, sample, "", "system_profiler SPAirPortDataType")
        self.assertEqual(rep.status, "OK")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Network Name (SSID)"), "My:Home:Net")
        self.assertIn("5 GHz", findings_dict.get("Channel & Band", ""))

        # Verify neighbor AP does not leak when current network lacks optional fields
        sample_redacted = """
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            <redacted>:
              Channel: 36 (5GHz, 20MHz)
              Transmit Rate: 286
          Other Local Wi-Fi Networks:
            Neighbor_Legacy:
              PHY Mode: 802.11b/g/n
              Channel: 6 (2GHz, 20MHz)
        """
        rep_red = parse_wifi_output(True, sample_redacted, "", "system_profiler SPAirPortDataType")
        findings_red = dict(rep_red.findings)
        self.assertIn("Location Services", findings_red.get("Network Name (SSID)", ""))
        self.assertNotIn("Wi-Fi Standard", findings_red)
        # Should warn on narrow 20MHz on 5GHz, NOT on neighbor's 2.4 GHz
        issue_texts = " ".join(desc for _, desc in rep_red.issues)
        self.assertIn("20 MHz channel width on 5 GHz", issue_texts)
        self.assertNotIn("2.4 GHz", issue_texts)

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
    def test_networkquality_bufferbloat_and_low_capacity_with_sysctl_correlation(self):
        sample = (
            "Downlink: capacity 0.000 Mbps\rDownlink: capacity 4.424 Mbps\n"
            "==== SUMMARY ====\n"
            "Uplink capacity: 31.836 Mbps\n"
            "Downlink capacity: 4.424 Mbps\n"
            "Responsiveness: Low (679.367 milliseconds | 88 RPM)\n"
            "Idle Latency: 24.318 milliseconds | 2467 RPM\n"
        )
        rep = parse_networkquality_output(
            True,
            sample,
            "",
            "networkQuality -v",
            sysctls={"net.inet.tcp.delayed_ack": "3", "net.inet.tcp.win_scale_factor": "0"},
        )
        self.assertEqual(rep.status, "WARNING")
        self.assertNotIn("\r", rep.raw)
        self.assertNotIn("0.000 Mbps", rep.raw)

        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Downlink Speed"), "4.42 Mbps")
        self.assertEqual(findings_dict.get("Uplink Speed"), "31.84 Mbps")
        self.assertIn("88 RPM", findings_dict.get("Responsiveness", ""))
        self.assertIn("679.4 ms", findings_dict.get("Responsiveness", ""))
        self.assertIn("+655.0 ms", findings_dict.get("Bufferbloat Delta", ""))

        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Bufferbloat Detected", issue_texts)
        self.assertIn("Low Downlink Capacity", issue_texts)
        self.assertIn("Window Scaling is disabled", issue_texts)
        self.assertTrue(any("Smart Queue Management" in r for r in rep.recommendations))
        self.assertTrue(any("delayed_ack is 3" in r for r in rep.recommendations))

    def test_networkquality_partial_output_on_timeout(self):
        partial = "Downlink: capacity 42.500 Mbps, responsiveness 110 RPM - Uplink: capacity 15.200 Mbps, responsiveness 110 RPM"
        rep = parse_networkquality_output(False, partial, "Command timed out after 60s", "networkQuality -v")
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Downlink Speed"), "42.50 Mbps")
        self.assertEqual(findings_dict.get("Uplink Speed"), "15.20 Mbps")
        self.assertTrue(any("timed out before completion" in desc for _, desc in rep.issues))

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

    def test_ifconfig_substandard_mtu_with_sysctl_correlation(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1400
	inet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
	media: autoselect
	status: active
        """
        rep = parse_ifconfig_output(
            True,
            sample,
            "",
            "ifconfig",
            sysctls={"net.inet.tcp.mssdflt": "1460"},
        )
        self.assertEqual(rep.status, "WARNING")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Sub-standard MTU (1400 bytes)", issue_texts)
        self.assertIn("mssdflt=1460 exceeds MTU-40 (1360)", issue_texts)

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

    def test_dns_dig_slow_latency_and_comparison_and_scutil(self):
        sample = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; ANSWER SECTION:
example.com.		300	IN	A	93.184.215.14
;; Query time: 240 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
        """
        comp_sample = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54321
;; Query time: 11 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
        """
        scutil_sample = """
resolver #1
  search domain[0] : home.arpa
  nameserver[0] : 192.168.1.1
        """
        rep = parse_dns_output(
            True,
            sample,
            "",
            "dig example.com",
            comparison_ok=True,
            comparison_out=comp_sample,
            scutil_out=scutil_sample,
        )
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Cloudflare 1.1.1.1"), "11 ms (direct comparison)")
        self.assertEqual(findings_dict.get("Configured Resolvers"), "192.168.1.1")
        self.assertEqual(findings_dict.get("Search Domains"), "home.arpa")
        issue_texts = " ".join(desc for _, desc in rep.issues)
        self.assertIn("Slow DNS Resolution (240 ms)", issue_texts)
        self.assertIn("significantly slower than direct 1.1.1.1", issue_texts)
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

    def test_dns_nslookup_fallback_with_elapsed_ms(self):
        sample = """
Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
Name:	example.com
Address: 93.184.215.14
        """
        rep = parse_dns_output(True, sample, "", "nslookup example.com", elapsed_ms=18.4)
        self.assertEqual(rep.status, "OK")
        findings_dict = dict(rep.findings)
        self.assertIn("18 ms", findings_dict.get("Query Latency", ""))
        self.assertIn("192.168.1.1", findings_dict.get("DNS Resolver", ""))
        self.assertIn("93.184.215.14", findings_dict.get("Resolved Addresses", ""))

    # ------------------------------------------------------------------ #
    # Gateway + Internet Ping Parser Tests
    # ------------------------------------------------------------------ #
    def test_extract_default_gateway_and_ping_healthy(self):
        route_out = """
   route to: default
destination: default
    gateway: 192.168.8.1
  interface: en0
        """
        gw, iface = extract_default_gateway(route_out)
        self.assertEqual(gw, "192.168.8.1")
        self.assertEqual(iface, "en0")

        gw_ping = """
--- 192.168.8.1 ping statistics ---
6 packets transmitted, 6 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.100/2.300/4.200/1.050 ms
        """
        inet_ping = """
--- 1.1.1.1 ping statistics ---
6 packets transmitted, 6 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.200/14.500/19.800/3.100 ms
        """
        rep = parse_ping_output(gw, iface, True, gw_ping, "", True, inet_ping, "")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)

    def test_ping_local_vs_upstream_loss(self):
        gw_ping_clean = """
--- 192.168.8.1 ping statistics ---
6 packets transmitted, 6 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.0/2.0/3.0/0.5 ms
        """
        inet_ping_loss = """
--- 1.1.1.1 ping statistics ---
6 packets transmitted, 4 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 12.0/18.0/25.0/4.0 ms
        """
        rep_upstream = parse_ping_output("192.168.8.1", "en0", True, gw_ping_clean, "", True, inet_ping_loss, "")
        self.assertEqual(rep_upstream.status, "WARNING")
        self.assertIn("Upstream Packet Loss", " ".join(d for _, d in rep_upstream.issues))

        gw_ping_loss = """
--- 192.168.8.1 ping statistics ---
6 packets transmitted, 4 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 2.0/15.0/40.0/12.0 ms
        """
        rep_local = parse_ping_output("192.168.8.1", "en0", True, gw_ping_loss, "", True, inet_ping_loss, "")
        self.assertEqual(rep_local.status, "ERROR")
        self.assertIn("Local Packet Loss to Gateway", " ".join(d for _, d in rep_local.issues))

    # ------------------------------------------------------------------ #
    # TCP + Socket Stats Parser Tests
    # ------------------------------------------------------------------ #
    def test_tcp_stats_unprivileged_and_interface_errors_and_queue_backpressure(self):
        netstat_in = """
Name       Mtu   Network       Address            Ipkts Ierrs    Opkts Oerrs  Coll
lo0        16384 <Link#1>                         1000     0     1000     0     0
en0        1500  <Link#14>   0e:5f:3a:5c:4f:7f  500000     4   600000     1     2
        """
        netstat_s = """
tcp:
	0 data packet (0 byte)
	91 open TCP sockets
        """
        netstat_anv = """
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat
tcp4       0 131072  192.168.8.187.50000    1.1.1.1.443            ESTABLISHED         1000         2000  262144 1048576
        """
        rep = parse_tcp_stats_output(
            True, netstat_in, "",
            True, netstat_s, "",
            True, netstat_anv, "",
            sysctls={"net.inet.tcp.win_scale_factor": "6"},
        )
        self.assertEqual(rep.status, "WARNING")
        findings_dict = dict(rep.findings)
        self.assertEqual(findings_dict.get("Open TCP Sockets"), "91")
        self.assertIn("Restricted", findings_dict.get("Kernel TCP Counters", ""))
        self.assertIn("1,048,576 B", findings_dict.get("Observed Auto-Buffers", ""))

        issue_texts = " ".join(d for _, d in rep.issues)
        self.assertIn("Hardware/Link Errors on en0", issue_texts)
        self.assertIn("Recv-Q/Send-Q", issue_texts)

    def test_tcp_stats_populated_retransmissions(self):
        netstat_in = """
Name       Mtu   Network       Address            Ipkts Ierrs    Opkts Oerrs  Coll
en0        1500  <Link#14>   0e:5f:3a:5c:4f:7f   10000     0    10000     0     0
        """
        netstat_s = """
tcp:
	1000 data packets (1000000 bytes)
	50 data packets (50000 bytes) retransmitted
	12 out-of-order packets
	30 duplicate acks
	15 open TCP sockets
        """
        rep = parse_tcp_stats_output(True, netstat_in, "", True, netstat_s, "", True, "", "")
        self.assertEqual(rep.status, "WARNING")
        issue_texts = " ".join(d for _, d in rep.issues)
        self.assertIn("5.00%", issue_texts)

    # ------------------------------------------------------------------ #
    # Formatter & Clean Helper Tests
    # ------------------------------------------------------------------ #
    def test_clean_cli_output_resolves_carriage_returns(self):
        raw = "step 1\rstep 2\rfinal step\nnext line"
        self.assertEqual(clean_cli_output(raw), "final step\nnext line")

    def test_report_format_text_includes_sections_and_raw_toggle(self):
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
        formatted = rep.format_text(cmd="sample_tool -v", include_raw=True)
        self.assertIn("DIAGNOSTIC REPORT: SAMPLE TEST", formatted)
        self.assertIn("Status: [WARNING] Potential bottleneck detected.", formatted)
        self.assertIn("Key1                  : Val1", formatted)
        self.assertIn("⚠️ [WARNING] Bottleneck issue occurred.", formatted)
        self.assertIn("→ Try fixing setting X.", formatted)
        self.assertIn("RAW CLI OUTPUT (sample_tool -v)", formatted)
        self.assertIn(raw_cmd_output, formatted)

        no_raw = rep.format_text(cmd="sample_tool -v", include_raw=False)
        self.assertNotIn("RAW CLI OUTPUT", no_raw)
        self.assertNotIn(raw_cmd_output, no_raw)

    # ------------------------------------------------------------------ #
    # Audit Regression Tests
    # ------------------------------------------------------------------ #
    def test_wifi_6ghz_low_channel_not_flagged_as_2ghz(self):
        sample = """
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            Home_6E:
              PHY Mode: 802.11ax
              Channel: 5 (6GHz, 160MHz)
              Security: WPA3 Personal
              Signal / Noise: -52 dBm / -94 dBm
              Transmit Rate: 2400
        """
        rep = parse_wifi_output(True, sample, "", "system_profiler SPAirPortDataType")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)
        self.assertIn("6 GHz", dict(rep.findings).get("Channel & Band", ""))

    def test_wifi_airport_negative_offset_and_connected_empty_block(self):
        sample_airport = """
agrCtlRSSI: -58
agrCtlNoise: -92
state: running
lastTxRate: 866
SSID: Studio_5G
channel: 44,-1
        """
        rep = parse_wifi_output(True, sample_airport, "", "airport -I")
        self.assertEqual(rep.status, "OK")
        self.assertNotIn("-1MHz", dict(rep.findings).get("Channel & Band", ""))

        sample_empty_connected = """
      Interfaces:
        en0:
          Status: Connected
        """
        rep_empty = parse_wifi_output(True, sample_empty_connected, "", "system_profiler SPAirPortDataType")
        self.assertEqual(rep_empty.status, "INFO")

    def test_networkquality_high_idle_latency_sets_warning_status(self):
        sample = """
==== SUMMARY ====
Uplink capacity: 100.000 Mbps
Downlink capacity: 250.000 Mbps
Responsiveness: High (45.000 milliseconds | 1333 RPM)
Idle Latency: 110.500 milliseconds | 543 RPM
        """
        rep = parse_networkquality_output(True, sample, "", "networkQuality -v")
        self.assertEqual(rep.status, "WARNING")
        self.assertTrue(any("High Base Latency" in desc for _, desc in rep.issues))

    def test_ifconfig_separates_apple_p2p_and_detects_ipv6_only_vpn(self):
        sample = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 2600:1234::5 prefixlen 64 autoconf secured
	status: active
awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 fe80::1%awdl0 prefixlen 64 scopeid 0x10
	status: active
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet6 fd00:1234::2 prefixlen 64
        """
        rep = parse_ifconfig_output(True, sample, "", "ifconfig")
        self.assertEqual(rep.status, "OK")
        self.assertIn("1 active primary interface", rep.summary)
        findings_dict = dict(rep.findings)
        self.assertIn("2600:1234::5", findings_dict.get("Interface en0", ""))
        self.assertIn("awdl0", findings_dict.get("Apple P2P/Internal", ""))
        self.assertIn("utun5", findings_dict.get("Active VPN Tunnels", ""))

    def test_dns_failed_primary_still_reports_1111_comparison_and_nslookup_ips(self):
        comp_sample = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; Query time: 12 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
        """
        rep_fail = parse_dns_output(
            False, "", "connection timed out", "dig example.com",
            comparison_ok=True, comparison_out=comp_sample,
        )
        self.assertEqual(rep_fail.status, "ERROR")
        issue_texts = " ".join(d for _, d in rep_fail.issues)
        self.assertIn("direct query to 1.1.1.1 succeeded", issue_texts)

        nslookup_sample = """
Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	example.com
Address: 1.1.1.10
Address: 2606:2800:220:1:248:1893:25c8:1946
        """
        rep_ns = parse_dns_output(True, nslookup_sample, "", "nslookup example.com", elapsed_ms=10.0)
        resolved = dict(rep_ns.findings).get("Resolved Addresses", "")
        self.assertIn("1.1.1.10", resolved)
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", resolved)

    def test_tcp_stats_ignores_listen_socket_backlog_for_backpressure(self):
        netstat_in = """
Name       Mtu   Network       Address            Ipkts Ierrs    Opkts Oerrs  Coll
en0        1500  <Link#14>   0e:5f:3a:5c:4f:7f  100000     0   100000     0     0
        """
        netstat_anv = """
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat
tcp4       0 131072  127.0.0.1.8080         *.*                    LISTEN                 0            0  262144  262144
        """
        rep = parse_tcp_stats_output(True, netstat_in, "", True, "", "", True, netstat_anv, "")
        self.assertEqual(rep.status, "OK")
        self.assertEqual(len(rep.issues), 0)


if __name__ == "__main__":
    unittest.main()
