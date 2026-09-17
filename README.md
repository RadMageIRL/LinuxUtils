# LinuxUtils

Small, dependency-free Linux administration tools. Each one solves a problem I
actually hit, does one thing, and does not require installing a runtime beyond
what ships with the distro.

**Design rules for anything in this repo:**

- Standard library only. No pip install, no vendored deps.
- Read-only by default. Anything that mutates system state requires an explicit
  `--apply` and refuses to run without it.
- Every change is revertible, and the tool says how.
- If the tool cannot determine something, it says so instead of guessing. A
  check that could not reach an answer is never reported as a pass.
- Works on a stock kernel. No custom modules, no patched anything.
- `--json` everywhere, from a single gather step, so the machine-readable
  output cannot drift from what you see in the terminal.

**Shared exit-code convention.** All three tools answer the same way, so a cron
job can treat them alike:

| Code | Meaning |
|------|---------|
| `0` | Ran, and there is nothing to act on |
| `1` | A finding to act on |
| `2` | Could not determine (wrong platform, missing hardware, no data, no permission) |

`1` means, and only means, an actionable finding. A run that reached no verdict
never shares a code with one that found a problem.

## Tools

| Tool | Description |
|------|-------------|
| [`logi-rx`](logi-rx/) | Audit and tune a Logitech wireless receiver: USB autosuspend, remote wakeup, ACPI gating, battery, and a link-quality test that calibrates its dropout threshold to the device's own report rate and tells a real dropout from you letting go of the mouse. |
| [`rfscan`](rfscan/) | Map 2.4 GHz channel occupancy weighted by signal strength and recommend a quieter channel for your access point. Read-only, unprivileged, regulatory-domain aware. |
| [`freshcheck`](freshcheck/) | Post-install and post-update audit: running kernel vs installed modules, microcode, TRIM, journal size, swap and zram, CPU scaling, time sync, filesystem headroom, failed units. Reports fixes, never applies them. |
| [`chronicle`](chronicle/) | What changed on this machine, and when. Merges the package log, journal boots and unit failures, and `/etc` mtimes into one timeline. Orders and labels events; never claims one caused another. |
| [`portwatch`](portwatch/) | Snapshot listening sockets and diff against a baseline. Reads `/proc/net` directly, attributes sockets to processes, and reports what changed, including a service moving from loopback to a wildcard address. No risk scoring. |
| [`sleepcheck`](sleepcheck/) | Audit kernel sleep states, systemd policy, live inhibitor locks, firmware wake sources, and recent sleep-service events. Read-only; reports observations without assigning a wake cause. |

## Install

Clone and symlink the tools onto your `PATH`:

```sh
git clone https://github.com/RadMageIRL/LinuxUtils.git
cd LinuxUtils
./install.sh
```

`install.sh` symlinks each tool into `~/.local/bin` without the file extension,
so `logi-rx/logi-rx.py` becomes `logi-rx`. It creates the directory if needed
and will not overwrite an existing file it did not create. Pass `--uninstall`
to remove the symlinks.

Nothing is installed system-wide and nothing is copied - the symlinks point back
at the clone, so `git pull` updates the tools in place.

## Requirements

- Linux, kernel 5.x or newer
- Python 3.8+

Individual tools may need root for specific operations. None of them need root
to run their default read-only checks.

## License

MIT. See [LICENSE](LICENSE).
