#!/usr/bin/env python3
"""
logi-rx.py - Logitech wireless receiver checker/tuner for Linux.

Covers the things that actually matter for a couch-distance HTPC receiver:

  * locates the receiver in sysfs and reports its USB topology
  * checks hid_logitech_dj is loaded (needed for Unifying device passthrough)
  * disables USB autosuspend on the receiver (a real cause of "wakes up slow")
  * enables USB remote wakeup so the keyboard can resume the machine
  * reports the parent xHCI controller's ACPI wakeup state, which gates the above
  * installs a persistent udev rule so both survive reboot and re-plug
  * reads battery level straight from the hidpp power_supply class (no solaar needed)
  * --watch mode: measures input-event gaps so you can A/B test port placement
    and prove whether a given USB port is costing you range

Read-only by default. Nothing is changed unless you pass --apply.

    ./logi-rx.py                 # check everything, change nothing
    sudo ./logi-rx.py --apply    # apply the fixes + install udev rule
    ./logi-rx.py --watch         # empirical dropout test (move the pointer)
    sudo ./logi-rx.py --revert   # remove the udev rule

Tested against sysfs layout on kernel 5.x/6.x. No third-party dependencies.
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

USB_DEVICES = Path("/sys/bus/usb/devices")
POWER_SUPPLY = Path("/sys/class/power_supply")
PROC_INPUT = Path("/proc/bus/input/devices")
PROC_ACPI_WAKEUP = Path("/proc/acpi/wakeup")
UDEV_RULE = Path("/etc/udev/rules.d/90-logitech-receiver.rules")

LOGITECH_VID = "046d"

# Known receiver product IDs. Used to rank candidates; detection does not
# depend on this list being complete, it is a hint only.
KNOWN_RECEIVER_PIDS = {
    "c52b": "Unifying Receiver",
    "c532": "Unifying Receiver",
    "c534": "Unifying Receiver (2nd gen)",
    "c539": "Lightspeed Receiver",
    "c53a": "Lightspeed Receiver",
    "c53d": "Lightspeed Receiver",
    "c53f": "Lightspeed Receiver",
    "c541": "Lightspeed Receiver",
    "c548": "Bolt Receiver",
    "c52e": "Nano Receiver",
    "c542": "Nano Receiver",
    "c517": "Nano Receiver (legacy)",
    "c51b": "Nano Receiver (legacy)",
}

# ---------------------------------------------------------------- formatting


class Out:
    """Tiny console formatter. Colour only when stdout is a terminal."""

    def __init__(self, color=True):
        self.color = color and sys.stdout.isatty()
        self.problems = []
        self.fixes = []

    def _c(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def header(self, text):
        print()
        print(self._c("1;36", text))
        print(self._c("36", "─" * len(text)))

    def ok(self, text):
        print(f"  {self._c('32', '[ ok ]')} {text}")

    def warn(self, text, remedy=None):
        print(f"  {self._c('33', '[warn]')} {text}")
        self.problems.append(text)
        if remedy:
            print(f"         {self._c('90', remedy)}")

    def fail(self, text, remedy=None):
        print(f"  {self._c('31', '[fail]')} {text}")
        self.problems.append(text)
        if remedy:
            print(f"         {self._c('90', remedy)}")

    def info(self, text):
        print(f"  {self._c('90', '[info]')} {text}")

    def changed(self, text):
        print(f"  {self._c('35', '[ >> ]')} {text}")
        self.fixes.append(text)


# ------------------------------------------------------------ sysfs helpers


def read_attr(base, name):
    """Read a sysfs attribute, returning None on any failure."""
    try:
        return (Path(base) / name).read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None


def write_attr(base, name, value):
    """Write a sysfs attribute. Returns (success, error_message)."""
    path = Path(base) / name
    try:
        path.write_text(value)
        return True, None
    except OSError as exc:
        return False, str(exc)


def usb_device_dirs():
    """All real USB device nodes (skips interfaces like '1-3:1.0')."""
    if not USB_DEVICES.is_dir():
        return []
    out = []
    for entry in sorted(USB_DEVICES.iterdir()):
        if ":" in entry.name:  # interface, not a device
            continue
        if read_attr(entry, "idVendor") is None:
            continue
        out.append(entry)
    return out


def find_receivers():
    """Return Logitech USB devices, most-likely-receiver first."""
    found = []
    for dev in usb_device_dirs():
        if read_attr(dev, "idVendor") != LOGITECH_VID:
            continue
        pid = read_attr(dev, "idProduct") or ""
        product = read_attr(dev, "product") or "(no product string)"
        found.append(
            {
                "path": dev,
                "name": dev.name,
                "pid": pid,
                "product": product,
                "known": pid in KNOWN_RECEIVER_PIDS,
                "label": KNOWN_RECEIVER_PIDS.get(pid),
                "busnum": read_attr(dev, "busnum"),
                "devnum": read_attr(dev, "devnum"),
                "speed": read_attr(dev, "speed"),
            }
        )

    def rank(d):
        if d["known"]:
            return 0
        if "receiver" in d["product"].lower():
            return 1
        return 2

    found.sort(key=rank)
    return found


def root_hub_for(dev_path):
    """Walk up the sysfs tree to the root hub (usbN) owning this device."""
    node = Path(dev_path).resolve()
    for _ in range(12):  # depth guard
        if re.fullmatch(r"usb\d+", node.name):
            return node
        parent = node.parent
        if parent == node:
            break
        node = parent
    return None


def pci_controller_for(dev_path):
    """Resolve the PCI address of the host controller behind this device."""
    resolved = str(Path(dev_path).resolve())
    matches = re.findall(r"/(0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])", resolved)
    return matches[-1] if matches else None


# ------------------------------------------------------------------- checks


def check_topology(out, rx):
    """Report bus placement. Be honest about what sysfs can and cannot tell us."""
    out.header("USB topology")

    out.info(f"Receiver: {rx['product']} [{LOGITECH_VID}:{rx['pid']}]")
    if rx["label"]:
        out.info(f"Type:     {rx['label']}")
    out.info(f"Sysfs:    {rx['path']}")
    out.info(f"Address:  bus {rx['busnum']} device {rx['devnum']}")

    hub = root_hub_for(rx["path"])
    hub_speed = read_attr(hub, "speed") if hub else None
    if hub_speed:
        out.info(f"Root hub: {hub.name} @ {hub_speed} Mbps")

    pci = pci_controller_for(rx["path"])
    if pci:
        out.info(f"Host ctlr: {pci}")

    print()
    print("  All USB root hubs on this machine:")
    for dev in usb_device_dirs():
        if not re.fullmatch(r"usb\d+", dev.name):
            continue
        speed = read_attr(dev, "speed") or "?"
        ports = read_attr(dev, "maxchild") or "?"
        marker = "  <-- receiver is here" if hub and dev.name == hub.name else ""
        tag = "USB 2.0" if speed == "480" else "SuperSpeed" if speed and speed.isdigit() and int(speed) >= 5000 else ""
        print(f"    {dev.name:<8} {speed:>6} Mbps  {ports:>2} ports  {tag}{marker}")

    print()
    out.warn(
        "sysfs cannot tell you whether the PHYSICAL port is USB 2 or USB 3.",
        "A full-speed HID device always enumerates on the USB2 companion bus even\n"
        "         when plugged into a blue USB3 port, so both look identical here. Use\n"
        "         --watch to A/B test ports empirically instead of guessing.",
    )


def check_dj_module(out):
    out.header("Kernel module")
    try:
        mods = Path("/proc/modules").read_text()
    except OSError:
        out.warn("Could not read /proc/modules")
        return
    if re.search(r"^hid_logitech_dj\b", mods, re.M):
        out.ok("hid_logitech_dj is loaded")
    elif Path("/sys/module/hid_logitech_dj").exists():
        out.ok("hid_logitech_dj is built in")
    else:
        out.fail(
            "hid_logitech_dj is not loaded",
            "Without it the receiver appears as one generic HID device and per-device\n"
            "         battery reporting and pairing will not work. Try: modprobe hid-logitech-dj",
        )


def check_autosuspend(out, rx, apply_changes):
    """USB autosuspend on an input receiver causes laggy first-input after idle."""
    out.header("USB autosuspend")

    control = read_attr(rx["path"], "power/control")
    delay = read_attr(rx["path"], "power/autosuspend_delay_ms")

    if control is None:
        out.warn("power/control not exposed; skipping")
        return

    out.info(f"power/control = {control}" + (f"  (delay {delay} ms)" if delay else ""))

    if control == "on":
        out.ok("Autosuspend already disabled for this receiver")
        return

    out.warn(
        "Receiver is allowed to autosuspend",
        "This shows up as the pointer ignoring the first flick after the box has\n"
        "         been idle. Harmless on a desk, irritating from the couch.",
    )

    if apply_changes:
        good, err = write_attr(rx["path"], "power/control", "on")
        if good:
            out.changed("Set power/control = on (runtime)")
        else:
            out.fail(f"Could not write power/control: {err}")


def check_wakeup(out, rx, apply_changes):
    out.header("USB remote wakeup")

    wakeup = read_attr(rx["path"], "power/wakeup")
    if wakeup is None:
        out.warn(
            "power/wakeup not exposed for this device",
            "The device did not advertise remote-wakeup capability. It cannot resume\n"
            "         the machine regardless of settings.",
        )
        return

    out.info(f"power/wakeup = {wakeup}")

    if wakeup == "enabled":
        out.ok("Remote wakeup is enabled")
    else:
        out.warn(
            "Remote wakeup is disabled - keyboard will not resume the machine",
            "This is the classic K400 complaint. It is a settings problem, not a\n"
            "         hardware limitation.",
        )
        if apply_changes:
            good, err = write_attr(rx["path"], "power/wakeup", "enabled")
            if good:
                out.changed("Set power/wakeup = enabled (runtime)")
            else:
                out.fail(f"Could not write power/wakeup: {err}")


def check_acpi_wakeup(out, rx):
    """The port setting is useless if the parent controller is masked in ACPI."""
    out.header("ACPI controller wakeup")

    if not PROC_ACPI_WAKEUP.exists():
        out.info("/proc/acpi/wakeup not present (non-ACPI or disabled); skipping")
        return

    pci = pci_controller_for(rx["path"])
    if not pci:
        out.info("Could not resolve host controller PCI address; showing all entries")

    try:
        lines = PROC_ACPI_WAKEUP.read_text().splitlines()
    except OSError as exc:
        out.warn(f"Could not read /proc/acpi/wakeup: {exc}")
        return

    matched = False
    for line in lines:
        if not line.strip() or line.startswith("Device"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name, sstate, status = parts[0], parts[1], parts[2]
        sysfs_node = parts[3] if len(parts) > 3 else ""

        if pci and pci in sysfs_node:
            matched = True
            enabled = "enabled" in status
            if enabled:
                out.ok(f"{name} ({sysfs_node}) is wakeup-enabled, deepest state {sstate}")
            else:
                out.fail(
                    f"{name} ({sysfs_node}) is wakeup-DISABLED",
                    f"The per-port setting cannot work while the parent controller is masked.\n"
                    f"         Enable with:  echo {name} | sudo tee /proc/acpi/wakeup\n"
                    f"         WARNING: that write is a TOGGLE, not a set. Running it twice\n"
                    f"         puts you back where you started. This script will not do it for\n"
                    f"         you precisely because it is not idempotent.",
                )

    if pci and not matched:
        out.info(f"No /proc/acpi/wakeup entry references {pci} - usually fine")


def check_battery(out):
    """hidpp exposes battery natively; no need for solaar just to read a percentage."""
    out.header("Battery")

    if not POWER_SUPPLY.is_dir():
        out.info("No power_supply class; skipping")
        return

    found = False
    for entry in sorted(POWER_SUPPLY.iterdir()):
        if not entry.name.startswith("hidpp_battery"):
            continue
        found = True
        model = read_attr(entry, "model_name") or entry.name
        capacity = read_attr(entry, "capacity")
        level = read_attr(entry, "capacity_level")
        status = read_attr(entry, "status")

        bits = []
        if capacity:
            bits.append(f"{capacity}%")
        if level and level.lower() != "unknown":
            bits.append(level)
        if status and status.lower() != "unknown":
            bits.append(status)
        detail = ", ".join(bits) if bits else "no reading"

        low = (capacity and capacity.isdigit() and int(capacity) <= 20) or (
            level and level.lower() in {"low", "critical"}
        )
        (out.warn if low else out.ok)(f"{model}: {detail}")

    if not found:
        out.info(
            "No hidpp_battery devices. Normal for cheaper devices that do not report "
            "battery over HID++, including some K400 revisions."
        )
        out.info(
            "Falling alkaline voltage cuts transmit power long before any indicator "
            "fires. If range degrades over months, swap cells before debugging RF."
        )


def check_solaar(out):
    out.header("solaar")
    from shutil import which

    if which("solaar"):
        out.ok("solaar is installed")
    else:
        out.info("solaar not found - optional, but handy for pairing and remapping")
        out.info("Arch/CachyOS:  sudo pacman -S solaar")


# --------------------------------------------------------------- udev rule


def build_rule(rx):
    return (
        "# Managed by logi-rx.py - Logitech receiver: keep awake, allow resume.\n"
        "# Disables runtime autosuspend and enables USB remote wakeup.\n"
        'ACTION=="add", SUBSYSTEM=="usb", '
        f'ATTR{{idVendor}}=="{LOGITECH_VID}", ATTR{{idProduct}}=="{rx["pid"]}", '
        'ATTR{power/control}="on", ATTR{power/wakeup}="enabled"\n'
    )


def check_udev(out, rx, apply_changes):
    out.header("Persistent udev rule")

    desired = build_rule(rx)

    if UDEV_RULE.exists():
        current = UDEV_RULE.read_text()
        if current.strip() == desired.strip():
            out.ok(f"{UDEV_RULE} is present and current")
            return
        out.warn(f"{UDEV_RULE} exists but does not match this receiver's PID")
    else:
        out.warn(
            "No persistent rule - runtime settings are lost on reboot or re-plug",
            f"Would install: {UDEV_RULE}",
        )

    if not apply_changes:
        print()
        for line in desired.rstrip().splitlines():
            print(f"    {line}")
        return

    try:
        UDEV_RULE.parent.mkdir(parents=True, exist_ok=True)
        UDEV_RULE.write_text(desired)
        out.changed(f"Wrote {UDEV_RULE}")
    except OSError as exc:
        out.fail(f"Could not write rule: {exc}")
        return

    for cmd in (["udevadm", "control", "--reload"], ["udevadm", "trigger", "--subsystem-match=usb"]):
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            out.changed(" ".join(cmd))
        except FileNotFoundError:
            out.warn("udevadm not found; reboot to apply the rule")
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            out.warn(f"{' '.join(cmd)} failed: {exc}")


def revert(out):
    out.header("Revert")
    if not UDEV_RULE.exists():
        out.info(f"{UDEV_RULE} is not present; nothing to do")
        return
    try:
        UDEV_RULE.unlink()
        out.changed(f"Removed {UDEV_RULE}")
        subprocess.run(["udevadm", "control", "--reload"], check=False, capture_output=True, timeout=30)
        out.info("Runtime sysfs values are unchanged until reboot or re-plug")
    except OSError as exc:
        out.fail(f"Could not remove rule: {exc}")


# ------------------------------------------------------------- watch mode


def find_pointer_event_device():
    """Locate the evdev node for the Logitech pointer via /proc/bus/input/devices."""
    try:
        blob = PROC_INPUT.read_text()
    except OSError:
        return None, None

    for block in blob.split("\n\n"):
        if f"Vendor={LOGITECH_VID}" not in block:
            continue
        handlers = ""
        name = "(unknown)"
        for line in block.splitlines():
            if line.startswith("H: Handlers="):
                handlers = line.split("=", 1)[1]
            elif line.startswith("N: Name="):
                name = line.split("=", 1)[1].strip().strip('"')
        if "mouse" not in handlers:
            continue
        match = re.search(r"\b(event\d+)\b", handlers)
        if match:
            return f"/dev/input/{match.group(1)}", name
    return None, None


# struct input_event: two longs (timeval), then __u16, __u16, __s32
EVENT_FMT = "llHHi"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
EV_REL = 0x02


def watch(out, duration, gap_ms):
    out.header("Dropout watch")

    node, name = find_pointer_event_device()
    if not node:
        out.fail(
            "Could not find a Logitech pointer event device",
            "Is the receiver plugged in and the pointer paired?",
        )
        return 1

    out.info(f"Device: {name}")
    out.info(f"Node:   {node}")
    print()
    print(f"  Move the pointer CONTINUOUSLY for {duration}s. Do not pause - a pause")
    print(f"  is indistinguishable from a dropout. Walk to the couch mid-test and")
    print(f"  compare runs across different USB ports.")
    print()

    try:
        fh = open(node, "rb", buffering=0)
    except PermissionError:
        out.fail(
            f"Permission denied reading {node}",
            "Run with sudo, or add yourself to the 'input' group and re-login.",
        )
        return 1
    except OSError as exc:
        out.fail(f"Could not open {node}: {exc}")
        return 1

    os.set_blocking(fh.fileno(), False)

    threshold = gap_ms / 1000.0
    gaps = []
    dropouts = []
    last = None
    started = time.monotonic()
    total_events = 0

    try:
        while time.monotonic() - started < duration:
            chunk = fh.read(EVENT_SIZE)
            if not chunk or len(chunk) < EVENT_SIZE:
                time.sleep(0.001)
                continue

            _, _, etype, _, _ = struct.unpack(EVENT_FMT, chunk)
            if etype != EV_REL:
                continue

            now = time.monotonic()
            total_events += 1
            if last is not None:
                gap = now - last
                gaps.append(gap)
                if gap > threshold:
                    dropouts.append((now - started, gap))
                    print(f"  {out._c('33', 'gap')} {gap * 1000:7.1f} ms at t+{now - started:5.1f}s")
            last = now
    except KeyboardInterrupt:
        print("\n  interrupted")
    finally:
        fh.close()

    print()
    if not gaps:
        out.warn("No motion recorded - the pointer has to be moving for this to mean anything")
        return 1

    ordered = sorted(gaps)
    median = ordered[len(ordered) // 2] * 1000
    p99 = ordered[int(len(ordered) * 0.99)] * 1000
    worst = ordered[-1] * 1000

    out.info(f"Motion events:  {total_events}")
    out.info(f"Median gap:     {median:.1f} ms")
    out.info(f"p99 gap:        {p99:.1f} ms")
    out.info(f"Worst gap:      {worst:.1f} ms")
    print()

    if not dropouts:
        out.ok(f"No gaps above {gap_ms} ms - this link is healthy at this distance")
        return 0

    out.fail(f"{len(dropouts)} gaps above {gap_ms} ms")
    print()
    print("  Re-run from the same spot with the receiver on a different port. A large")
    print("  drop in the gap count means the old port was the problem (USB 3 emissions")
    print("  sit right on top of the 2.4 GHz band). No change means it is distance,")
    print("  transmit power, or 2.4 GHz congestion from your WiFi.")
    return 1


# ------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="Check and tune a Logitech wireless receiver on Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apply", action="store_true", help="apply fixes (needs root)")
    parser.add_argument("--revert", action="store_true", help="remove the udev rule")
    parser.add_argument("--watch", action="store_true", help="measure input dropouts")
    parser.add_argument("--duration", type=int, default=30, help="watch duration in seconds")
    parser.add_argument("--gap-ms", type=float, default=100.0, help="dropout threshold in ms")
    parser.add_argument("--device", help="force a sysfs device name, e.g. 1-3")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    args = parser.parse_args()

    out = Out(color=not args.no_color)

    if sys.platform != "linux":
        out.fail("This script only works on Linux (it reads sysfs directly)")
        return 2

    if args.watch:
        return watch(out, args.duration, args.gap_ms)

    if args.revert:
        if os.geteuid() != 0:
            out.fail("--revert needs root")
            return 1
        revert(out)
        return 0

    if args.apply and os.geteuid() != 0:
        out.fail("--apply needs root; re-run with sudo")
        return 1

    receivers = find_receivers()
    if not receivers:
        out.fail(
            "No Logitech USB devices found",
            "Is the receiver plugged in? Check with: lsusb -d 046d:",
        )
        return 1

    if args.device:
        picked = [r for r in receivers if r["name"] == args.device]
        if not picked:
            out.fail(f"No Logitech device at sysfs node {args.device}")
            return 1
        rx = picked[0]
    else:
        rx = receivers[0]
        if len(receivers) > 1:
            out.info(f"{len(receivers)} Logitech devices present; using {rx['name']}")
            for other in receivers[1:]:
                out.info(f"  also: {other['name']} {other['product']} [{other['pid']}]")
            out.info("Override with --device NAME")

    check_topology(out, rx)
    check_dj_module(out)
    check_autosuspend(out, rx, args.apply)
    check_wakeup(out, rx, args.apply)
    check_acpi_wakeup(out, rx)
    check_battery(out)
    check_solaar(out)
    check_udev(out, rx, args.apply)

    out.header("Summary")
    if out.fixes:
        for fix in out.fixes:
            out.info(f"changed: {fix}")
    if not out.problems:
        out.ok("Nothing to fix")
    elif not args.apply:
        out.info(f"{len(out.problems)} item(s) flagged. Re-run with sudo --apply to fix.")
        out.info("Then: ./logi-rx.py --watch  to measure the link empirically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
