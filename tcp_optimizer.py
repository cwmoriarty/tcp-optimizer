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

import json
import os
import platform
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
                    "server-side bottlenecks.",
            wraplength=700, justify="left", fg="#444"
        ).pack(anchor="w", padx=10, pady=10)

        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=10)
        ttk.Button(btns, text="Wi-Fi link info", command=self.diag_wifi).pack(side="left", padx=4)
        ttk.Button(btns, text="Network Quality Test", command=self.diag_networkquality).pack(side="left", padx=4)
        ttk.Button(btns, text="Interface + MTU", command=self.diag_ifconfig).pack(side="left", padx=4)
        ttk.Button(btns, text="DNS latency", command=self.diag_dns).pack(side="left", padx=4)

        self.diag_text = scrolledtext.ScrolledText(f, height=22, font=("Menlo", 11))
        self.diag_text.pack(fill="both", expand=True, padx=10, pady=8)

    def _diag_write(self, title, ok, out, err):
        self.diag_text.insert(tk.END, f"\n=== {title} ===\n")
        self.diag_text.insert(tk.END, out if ok else f"error: {err or out}")
        self.diag_text.insert(tk.END, "\n")
        self.diag_text.see(tk.END)

    def diag_wifi(self):
        # macOS moved the airport utility around across versions; try the
        # common location, fall back to `system_profiler`.
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
            "Current/Resources/airport"
        )
        if os.path.exists(airport):
            ok, out, err = run([airport, "-I"])
        else:
            ok, out, err = run(["system_profiler", "SPAirPortDataType"])
        self._diag_write("Wi-Fi link info", ok, out, err)

    def diag_networkquality(self):
        # Built into macOS 12+. Slow (~20-30s) since it does a real transfer test.
        self.diag_text.insert(tk.END, "\nRunning networkQuality \u2014 this can take ~20-30s...\n")
        self.diag_text.see(tk.END)
        self.root.update()
        ok, out, err = run(["networkQuality", "-v"], timeout=60)
        self._diag_write("Network Quality Test", ok, out, err)

    def diag_ifconfig(self):
        ok, out, err = run(["ifconfig"])
        self._diag_write("Interfaces + MTU", ok, out, err)

    def diag_dns(self):
        ok, out, err = run(["dig", "example.com"])
        if not ok:
            ok, out, err = run(["nslookup", "example.com"])
        self._diag_write("DNS lookup", ok, out, err)

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
