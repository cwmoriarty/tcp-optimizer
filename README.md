# TCP Optimizer (macOS)

An open-source GUI for inspecting and tuning macOS's TCP/IP stack
(`sysctl net.inet.tcp.*`), plus diagnostics to help you find the *real*
bottleneck before you go tweaking kernel parameters.

## Before you tune anything

Modern macOS (10.7+) already auto-tunes TCP send/receive windows for most
connections. Manually changing these values rarely turns a 300 Mbps result
into 900 Mbps. On a MacBook Air, the far more common culprits are:

- **Wi-Fi band/channel** — 2.4 GHz caps out well under 1 Gbps regardless of
  your ISP plan; you need 5 GHz (or 6 GHz on Wi-Fi 6E) with a clean channel.
- **The far end of the test** — a speed test server, or whatever you're
  downloading from, has its own ceiling.
- **DNS / connection setup latency** — matters more for "snappiness" than
  for sustained throughput.
- **Thermal/CPU throttling** on the Air under sustained saturation (no fan).

The app's **Diagnostics** tab runs `networkQuality`, Wi-Fi link info, and
interface/MTU checks so you can rule these out first. If you're on Wi-Fi,
that's almost always worth checking before touching TCP buffers.

## What it does

- **Overview** — read current values for the TCP sysctl keys the app knows
  about.
- **Presets** — one-click bundles (`Balanced Gigabit`, `High-Throughput`,
  `Low-Latency / Gaming`, and a reset to macOS's own defaults).
- **Advanced** — edit each parameter individually, with a documented safe
  range for each.
- **Diagnostics** — Runs Wi-Fi link info (`airport` / `system_profiler`),
  `networkQuality`, `ifconfig`/MTU, and DNS lookup timing (`dig` / `nslookup`).
  Each check automatically parses raw CLI output into a high-level report
  flagging misconfigurations, hardware bottlenecks (e.g. 2.4 GHz band,
  100baseTX Ethernet negotiation caps, bufferbloat, DHCP failure), and
  actionable recommendations before displaying the raw tool output. Includes
  "Run All Checks" and "Clear" controls.
- **Persistence** — `sysctl -w` changes reset on every reboot. This tab can
  install a small root-owned LaunchDaemon (`com.punksm4ck.tcpoptimizer`)
  that re-applies your chosen preset at boot, and an uninstall button to
  remove it again.

All privileged changes go through macOS's native
`osascript ... with administrator privileges` dialog — the app itself never
asks for or stores your password.

## Requirements

- macOS (any modern version; `networkQuality` requires macOS 12 Monterey+).
- Python 3 with Tkinter. macOS's system Python 3 usually doesn't ship Tk;
  easiest fix is one of:
  - Install Python from [python.org](https://www.python.org/downloads/macos/)
    (bundles Tk), or
  - `brew install python-tk`
- No third-party pip packages — everything used is Python's standard library.

## Run it

```bash
python3 tcp_optimizer.py
```

## Optional: package as a real .app

You can wrap it with [`py2app`](https://py2app.readthedocs.io/) on a Mac so
it's double-clickable from Finder:

```bash
pip3 install py2app
python3 setup.py py2app
```

See `setup.py` in this folder. The built app will land in `dist/`.

## Safety notes

- Every value in the Advanced tab has a min/max sanity range enforced
  before it's ever sent to `sysctl`.
- Nothing here modifies firewall rules, routing, or DNS resolvers — it's
  scoped to TCP buffer/window/ack behavior only.
- Uninstalling persistence removes the LaunchDaemon and its script; it does
  *not* revert sysctl values already in effect until your next reboot (use
  the "macOS Default (reset)" preset for that).

## License

MIT — see `LICENSE`. Do whatever you want with it.
