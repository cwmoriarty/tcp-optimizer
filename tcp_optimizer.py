#!/usr/bin/env python3
"""
TCP Optimizer for macOS
------------------------
An open-source GUI for inspecting and tuning macOS TCP/IP stack
parameters (sysctl net.inet.tcp.*) that can affect throughput and
latency on high-bandwidth connections.

Honest caveat baked into the app itself (see the Overview tab):
modern macOS already auto-tunes TCP send/receive windows, so manual
tuning usually yields small, situational gains. The bigger wins on a
MacBook Air are almost always Wi‑Fi band/channel, DNS, or an upstream
bottleneck — the Diagnostics tab exists to help you tell the
difference before you start changing kernel parameters.

Requires: macOS, Python 3 with Tkinter (the python.org installer
bundles Tk; Homebrew's `python-tk` package also works), no third
party dependencies.

Run with:  python3 tcp_optimizer.py
"""

import os
import platform
import queue
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from diagnostics import (
    extract_default_gateway,
    parse_dns_output,
    parse_ifconfig_output,
    parse_networkquality_output,
    parse_ping_output,
    parse_tcp_stats_output,
    parse_wifi_output,
)

APP_NAME = "TCP Optimizer"
LAUNCH_DAEMON_LABEL = "com.cwmoriarty.tcpoptimizer"
LEGACY_LAUNCH_DAEMON_LABEL = "com.punksm4ck.tcpoptimizer"
LAUNCH_DAEMON_PATH = f"/Library/LaunchDaemons/{LAUNCH_DAEMON_LABEL}.plist"
LEGACY_LAUNCH_DAEMON_PATH = f"/Library/LaunchDaemons/{LEGACY_LAUNCH_DAEMON_LABEL}.plist"
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
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        timeout_msg = f"Command timed out after {timeout}s"
        err_msg = f"{err.strip()}\n{timeout_msg}".strip() if err.strip() else timeout_msg
        return False, out.strip(), err_msg
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
    return run(["osascript", "-e", osa], timeout=90)


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
    ok, out, _ = run(["sysctl", "-n", key])
    if ok:
        return out
    return None


def read_all_tcp_sysctls():
    """Return a dict of current values for all known TCP_KEYS."""
    return {key: read_sysctl(key) for key in TCP_KEYS}


class TCPOptimizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("820x660")
        self.entries = {}
        self._diag_history = []  # list of (DiagnosticReport, cmd_str)
        self._diag_queue = queue.Queue()
        self._diag_running = False
        self._diag_buttons = []

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
        lbl = tk.Label(f, text=note, wraplength=740, justify="left", fg="#444")
        lbl.pack(anchor="w", padx=10, pady=(10, 6))

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", padx=10, pady=4)
        ttk.Button(btn_row, text="Refresh current values", command=self.refresh_overview).pack(side="left")

        self.overview_text = scrolledtext.ScrolledText(f, height=22, font=("Menlo", 11), state="disabled")
        self.overview_text.pack(fill="both", expand=True, padx=10, pady=8)
        self.refresh_overview()

    def refresh_overview(self):
        lines = []
        for key, meta in TCP_KEYS.items():
            val = read_sysctl(key)
            lines.append(f"{key:38s} = {val if val is not None else 'unavailable':>10}   ({meta['label']})")
        self.overview_text.config(state="normal")
        self.overview_text.delete("1.0", tk.END)
        self.overview_text.insert(tk.END, "\n".join(lines))
        self.overview_text.config(state="disabled")

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

        self.preset_status = tk.Label(f, text="", fg="#0a7a0a", wraplength=740, justify="left")
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
        self.reload_advanced()

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
            tk.Label(row, text=meta["help"], fg="#666", wraplength=540, justify="left").grid(
                row=1, column=0, columnspan=3, sticky="w", pady=(2, 0)
            )

        btn_row = ttk.Frame(inner)
        btn_row.pack(fill="x", pady=14, padx=6)
        ttk.Button(btn_row, text="Reload current values", command=self.reload_advanced).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Apply all changed values", command=self.apply_advanced).pack(side="left", padx=4)

        self.advanced_status = tk.Label(inner, text="", fg="#0a7a0a", wraplength=680, justify="left")
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
                    "separate a real TCP-stack limit from Wi‑Fi, DNS, packet loss, or "
                    "server-side bottlenecks. Each check parses the CLI output for "
                    "misconfigurations and bottlenecks before showing the raw output.",
            wraplength=740, justify="left", fg="#444"
        ).pack(anchor="w", padx=10, pady=(10, 6))

        btns_row1 = ttk.Frame(f)
        btns_row1.pack(fill="x", padx=10, pady=(2, 2))
        btn_specs = [
            ("Wi-Fi link info", self.diag_wifi),
            ("Network Quality Test", self.diag_networkquality),
            ("Interface + MTU", self.diag_ifconfig),
            ("DNS latency", self.diag_dns),
            ("Gateway + Ping", self.diag_ping),
            ("TCP + Socket Stats", self.diag_tcp_stats),
        ]
        for label, cmd_fn in btn_specs:
            b = ttk.Button(btns_row1, text=label, command=cmd_fn)
            b.pack(side="left", padx=3)
            self._diag_buttons.append(b)

        btns_row2 = ttk.Frame(f)
        btns_row2.pack(fill="x", padx=10, pady=(2, 4))
        b_all = ttk.Button(btns_row2, text="Run All Checks", command=self.diag_all)
        b_all.pack(side="left", padx=3)
        self._diag_buttons.append(b_all)

        self.show_raw_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            btns_row2,
            text="Show raw CLI output",
            variable=self.show_raw_var,
            command=self._rerender_diag_history,
        ).pack(side="left", padx=10)

        self.diag_status_lbl = tk.Label(btns_row2, text="", fg="#0055aa")
        self.diag_status_lbl.pack(side="left", padx=8)

        b_clear = ttk.Button(btns_row2, text="Clear", command=self.diag_clear)
        b_clear.pack(side="right", padx=3)
        self._diag_buttons.append(b_clear)

        self.diag_text = scrolledtext.ScrolledText(f, height=22, font=("Menlo", 11), state="disabled")
        self.diag_text.pack(fill="both", expand=True, padx=10, pady=6)

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

    def _insert_diag_report_into_widget(self, report, cmd=""):
        """Insert a single DiagnosticReport into `self.diag_text`."""
        include_raw = self.show_raw_var.get()
        self.diag_text.config(state="normal")
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

        if include_raw:
            cmd_label = f" ({cmd})" if cmd else ""
            self.diag_text.insert(tk.END, "-" * 76 + "\n", "divider")
            self.diag_text.insert(tk.END, f"RAW CLI OUTPUT{cmd_label}\n", "raw_hdr")
            self.diag_text.insert(tk.END, "-" * 76 + "\n", "divider")
            raw_body = report.raw.strip() if report.raw.strip() else "(no output)"
            self.diag_text.insert(tk.END, f"{raw_body}\n", "raw_body")
        self.diag_text.insert(tk.END, "=" * 76 + "\n\n", "divider")
        self.diag_text.see(tk.END)
        self.diag_text.config(state="disabled")

    def _diag_write_report(self, report, cmd=""):
        self._diag_history.append((report, cmd))
        self._insert_diag_report_into_widget(report, cmd=cmd)

    def _rerender_diag_history(self):
        self.diag_text.config(state="normal")
        self.diag_text.delete("1.0", tk.END)
        self.diag_text.config(state="disabled")
        for report, cmd in self._diag_history:
            self._insert_diag_report_into_widget(report, cmd=cmd)

    def _set_diag_busy(self, busy, status_text=""):
        self._diag_running = busy
        btn_state = "disabled" if busy else "normal"
        for b in self._diag_buttons:
            b.config(state=btn_state)
        self.diag_status_lbl.config(text=status_text)

    def _poll_diag_queue(self):
        """Drain diagnostic results queued by background worker threads on the UI thread."""
        done = False
        while True:
            try:
                item = self._diag_queue.get_nowait()
            except queue.Empty:
                break
            kind = item[0]
            if kind == "report":
                _, report, cmd = item
                self._diag_write_report(report, cmd=cmd)
            elif kind == "status":
                _, msg = item
                self.diag_status_lbl.config(text=msg)
            elif kind == "done":
                done = True
        if done:
            self._set_diag_busy(False, "")
        elif self._diag_running:
            self.root.after(50, self._poll_diag_queue)

    def _run_diag_async(self, status_text, worker_fn):
        """Run diagnostic collection off the main thread so the UI stays responsive."""
        if self._diag_running:
            return
        while not self._diag_queue.empty():
            try:
                self._diag_queue.get_nowait()
            except queue.Empty:
                break

        self._set_diag_busy(True, status_text)
        self.root.after(50, self._poll_diag_queue)

        def emit(report, cmd=""):
            self._diag_queue.put(("report", report, cmd))

        def update_status(msg):
            self._diag_queue.put(("status", msg))

        def target():
            try:
                worker_fn(emit, update_status)
            except Exception as e:
                from diagnostics import DiagnosticReport
                err_rep = DiagnosticReport(
                    title="Diagnostic Error",
                    status="ERROR",
                    summary=f"Unexpected error: {e}",
                    issues=[("ERROR", str(e))],
                    raw=str(e),
                )
                emit(err_rep, "")
            finally:
                self._diag_queue.put(("done",))

        threading.Thread(target=target, daemon=True).start()

    # --- Diagnostic Collectors (safe to call on worker thread or synchronously) ---
    def _collect_wifi(self):
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
        sysctls = read_all_tcp_sysctls()
        return parse_wifi_output(ok, out, err, cmd=cmd, sysctls=sysctls), cmd

    def _collect_networkquality(self):
        cmd = "networkQuality -v"
        ok, out, err = run(["networkQuality", "-v"], timeout=60)
        sysctls = read_all_tcp_sysctls()
        return parse_networkquality_output(ok, out, err, cmd=cmd, sysctls=sysctls), cmd

    def _collect_ifconfig(self):
        cmd = "ifconfig"
        ok, out, err = run(["ifconfig"])
        sysctls = read_all_tcp_sysctls()
        return parse_ifconfig_output(ok, out, err, cmd=cmd, sysctls=sysctls), cmd

    def _collect_dns(self):
        has_dig = shutil.which("dig") is not None
        if has_dig:
            cmd = "dig +tries=1 +time=3 example.com"
            t0 = time.monotonic()
            ok, out, err = run(["dig", "+tries=1", "+time=3", "example.com"], timeout=8)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
        else:
            cmd = "nslookup example.com"
            t0 = time.monotonic()
            ok, out, err = run(["nslookup", "example.com"], timeout=8)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
        comp_ok, comp_out = False, None
        if has_dig:
            comp_ok, comp_out, _ = run(["dig", "+tries=1", "+time=3", "@1.1.1.1", "example.com"], timeout=5)
        sc_ok, sc_out, _ = run(["scutil", "--dns"], timeout=5)
        report = parse_dns_output(
            ok,
            out,
            err,
            cmd=cmd,
            elapsed_ms=elapsed_ms,
            comparison_ok=comp_ok,
            comparison_out=comp_out if comp_ok else None,
            scutil_out=sc_out if sc_ok else None,
        )
        return report, cmd

    def _collect_ping(self):
        route_ok, route_out, _ = run(["route", "-n", "get", "default"], timeout=5)
        gw_ip, gw_iface = extract_default_gateway(route_out) if route_ok else (None, None)
        if gw_ip:
            ping_bin = "ping6" if ":" in gw_ip else "ping"
            gw_ok, gw_out, gw_err = run([ping_bin, "-c", "6", "-i", "0.2", gw_ip], timeout=10)
        else:
            gw_ok, gw_out, gw_err = False, "", "No default gateway"
        inet_target = "1.1.1.1"
        inet_ok, inet_out, inet_err = run(["ping", "-c", "6", "-i", "0.2", inet_target], timeout=10)
        report = parse_ping_output(
            gw_ip, gw_iface, gw_ok, gw_out, gw_err,
            inet_ok, inet_out, inet_err, inet_target=inet_target,
        )
        cmd = f"{'ping6' if gw_ip and ':' in gw_ip else 'ping'} -c 6 {gw_ip or '<none>'} ; ping -c 6 {inet_target}"
        return report, cmd

    def _collect_tcp_stats(self):
        in_ok, in_out, in_err = run(["netstat", "-in"], timeout=10)
        s_ok, s_out, s_err = run(["netstat", "-s", "-p", "tcp"], timeout=10)
        anv_ok, anv_out, anv_err = run(["netstat", "-anv", "-p", "tcp"], timeout=10)
        sysctls = read_all_tcp_sysctls()
        report = parse_tcp_stats_output(
            in_ok, in_out, in_err,
            s_ok, s_out, s_err,
            anv_ok, anv_out, anv_err,
            sysctls=sysctls,
        )
        return report, "netstat -in ; netstat -s -p tcp ; netstat -anv -p tcp"

    # --- UI Diagnostic Button Handlers ---
    def diag_wifi(self):
        self._run_diag_async("Checking Wi-Fi link...", lambda emit, _: emit(*self._collect_wifi()))

    def diag_networkquality(self):
        self._run_diag_async(
            "Running networkQuality (~20-30s)...",
            lambda emit, _: emit(*self._collect_networkquality()),
        )

    def diag_ifconfig(self):
        self._run_diag_async("Checking interfaces + MTU...", lambda emit, _: emit(*self._collect_ifconfig()))

    def diag_dns(self):
        self._run_diag_async("Checking DNS latency & resolvers...", lambda emit, _: emit(*self._collect_dns()))

    def diag_ping(self):
        self._run_diag_async("Pinging gateway & 1.1.1.1...", lambda emit, _: emit(*self._collect_ping()))

    def diag_tcp_stats(self):
        self._run_diag_async("Collecting TCP & interface counters...", lambda emit, _: emit(*self._collect_tcp_stats()))

    def diag_all(self):
        def worker(emit, update_status):
            steps = [
                ("1/6 Checking Wi-Fi link...", self._collect_wifi),
                ("2/6 Checking interfaces + MTU...", self._collect_ifconfig),
                ("3/6 Checking DNS latency...", self._collect_dns),
                ("4/6 Pinging gateway & 1.1.1.1...", self._collect_ping),
                ("5/6 Collecting TCP & socket stats...", self._collect_tcp_stats),
                ("6/6 Running networkQuality (~20-30s)...", self._collect_networkquality),
            ]
            for label, fn in steps:
                update_status(label)
                emit(*fn())

        self._run_diag_async("Running all diagnostic checks...", worker)

    def diag_clear(self):
        if self._diag_running:
            return
        self._diag_history.clear()
        self.diag_text.config(state="normal")
        self.diag_text.delete("1.0", tk.END)
        self.diag_text.config(state="disabled")

    # ------------------------------------------------------------------ #
    # Persistence (LaunchDaemon so presets survive reboot)
    # ------------------------------------------------------------------ #
    def _build_persistence(self):
        f = self.tab_persist
        tk.Label(
            f, text="sysctl -w changes are reset on reboot. Installing this "
                    "LaunchDaemon re-applies your last-applied preset at every "
                    "boot by running a small root-owned script.",
            wraplength=740, justify="left", fg="#444"
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

        self.persist_status = tk.Label(f, text="", fg="#0a7a0a", wraplength=740, justify="left")
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
        # Stage script + plist inside a private temporary directory, then move
        # into place and set ownership/permissions as one privileged operation.
        with tempfile.TemporaryDirectory(prefix="tcpoptimizer-") as tmpdir:
            tmp_script = os.path.join(tmpdir, "tcpoptimizer-apply.sh")
            tmp_plist = os.path.join(tmpdir, "tcpoptimizer.plist")
            with open(tmp_script, "w") as fh:
                fh.write(script_content)
            with open(tmp_plist, "w") as fh:
                fh.write(plist_content)

            cmd = (
                f"launchctl unload -w {LAUNCH_DAEMON_PATH} 2>/dev/null; "
                f"launchctl unload -w {LEGACY_LAUNCH_DAEMON_PATH} 2>/dev/null; "
                f"rm -f {LEGACY_LAUNCH_DAEMON_PATH} && "
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
            f"launchctl unload -w {LEGACY_LAUNCH_DAEMON_PATH} 2>/dev/null; "
            f"rm -f {LAUNCH_DAEMON_PATH} {LEGACY_LAUNCH_DAEMON_PATH} {SCRIPT_INSTALL_PATH}"
        )
        ok, out, err = run_privileged(cmd)
        if ok:
            self.persist_status.config(text="Uninstalled boot-time persistence.", fg="#0a7a0a")
        else:
            self.persist_status.config(text=f"Uninstall failed: {err or out}", fg="#a30000")

    def check_persistence(self):
        if os.path.exists(LAUNCH_DAEMON_PATH):
            ok, out, _ = run(["launchctl", "list", LAUNCH_DAEMON_LABEL])
            self.persist_status.config(
                text=f"LaunchDaemon present at {LAUNCH_DAEMON_PATH}.\n{out}", fg="#0a7a0a"
            )
        elif os.path.exists(LEGACY_LAUNCH_DAEMON_PATH):
            ok, out, _ = run(["launchctl", "list", LEGACY_LAUNCH_DAEMON_LABEL])
            self.persist_status.config(
                text=f"Legacy LaunchDaemon present at {LEGACY_LAUNCH_DAEMON_PATH}.\n{out}", fg="#a36a00"
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
