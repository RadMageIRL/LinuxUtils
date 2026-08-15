# LinuxUtils

Small, dependency-free Linux administration tools. Each one solves a problem I
actually hit, does one thing, and does not require installing a runtime beyond
what ships with the distro.

**Design rules for anything in this repo:**

- Standard library only. No pip install, no vendored deps.
- Read-only by default. Anything that mutates system state requires an explicit
  `--apply` and refuses to run without it.
- Every change is revertible, and the tool says how.
- If the tool cannot determine something, it says so instead of guessing.
- Works on a stock kernel. No custom modules, no patched anything.

## Tools

| Tool | Description |
|------|-------------|
| [`logi-rx`](logi-rx/) | Audit and tune a Logitech wireless receiver: USB autosuspend, remote wakeup, ACPI gating, battery, and an empirical link-quality test for diagnosing range problems. |

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

Nothing is installed system-wide and nothing is copied — the symlinks point back
at the clone, so `git pull` updates the tools in place.

## Requirements

- Linux, kernel 5.x or newer
- Python 3.8+

Individual tools may need root for specific operations. None of them need root
to run their default read-only checks.

## License

MIT. See [LICENSE](LICENSE).
