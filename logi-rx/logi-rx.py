#!/usr/bin/env python3
"""
logi-rx.py - Logitech wireless receiver checker/tuner for Linux.

Covers the things that actually matter for a couch-distance HTPC receiver:

  * locates the receiver in sysfs and reports its USB topology
  * lists other devices on the same host controller, because a SuperSpeed
    neighbour is a real and actionable 2.4 GHz noise source
  * checks hid_logitech_dj is loaded (needed for Unifying device passthrough)
  * disables USB autosuspend on the receiver (a real cause of "wakes up slow")
  * enables USB remote wakeup so the keyboard can resume the machine
  * reports the parent xHCI controller's ACPI wakeup state, which gates the above
  * installs a persistent udev rule so both survive reboot and re-plug
  * reads battery level straight from the hidpp power_supply class (no solaar)
  * --watch mode: measures input-event gaps, calibrates the dropout threshold
    to the device's own report rate, and uses the motion velocity either side
    of each gap to tell a real dropout from you letting go of the mouse

Read-only by default. Nothing is changed unless you pass --apply.

    ./logi-rx.py                 # check everything, change nothing
    ./logi-rx.py --json          # same data, machine-readable
    sudo ./logi-rx.py --apply    # apply the fixes + install udev rule
    ./logi-rx.py --watch         # empirical dropout test
    sudo ./logi-rx.py --revert   # remove the udev rule

Tested against sysfs layout on kernel 5.x/6.x. No third-party dependencies.
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------- test seams
#
# Every system read resolves through sysp() and every external command through
# run(), so the tests point SYSROOT at a synthetic sysfs tree and stub run().
# Same arrangement freshcheck uses, and for the same reason: this tool is the
# only one in the repo that writes to the system, so every branch has to be
# reachable without root and without a real receiver plugged in.

SYSROOT = Path("/")
PLATFORM = None  # tests set "linux"
IS_ROOT = None  # tests set a bool


def sysp(path):
    """Resolve an absolute system path underneath SYSROOT."""
    return SYSROOT / str(path).lstrip("/")


def is_linux():
    return (PLATFORM or sys.platform) == "linux"


def is_root():
    if IS_ROOT is not None:
        return IS_ROOT
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run(cmd, timeout=30):
    """Run a command. Returns (rc, stdout, reason); rc is None if it could not
    be run at all."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, text=True, errors="replace"
        )
    except FileNotFoundError:
        return None, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return None, "", f"{' '.join(cmd)} timed out"
    except OSError as exc:
        return None, "", str(exc)
    return proc.returncode, proc.stdout, (proc.stderr or "").strip() or None


# ----------------------------------------------------------------- constants

USB_DEVICES = "/sys/bus/usb/devices"
POWER_SUPPLY = "/sys/class/power_supply"
PROC_INPUT = "/proc/bus/input/devices"
PROC_ACPI_WAKEUP = "/proc/acpi/wakeup"
PROC_MODULES = "/proc/modules"
SYS_MODULE_DJ = "/sys/module/hid_logitech_dj"
UDEV_RULE = "/etc/udev/rules.d/90-logitech-receiver.rules"

# Written into every generated rule and required before --revert will delete
# anything. A file at that path this tool did not write is not this tool's to
# remove.
MANAGED_MARKER = "# Managed by logi-rx.py"

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

# A device is SuperSpeed at 5 Gbps or above. Those emit broadband noise across
# 2.4 GHz, which is why a neighbour on the same controller is worth reporting.
SUPERSPEED_MBPS = 5000

# --- watch-mode tuning. All of these are pinned by mutation tests.

# A gap counts as a candidate dropout at this multiple of the device's own
# median inter-event interval. Calibrating rather than fixing the threshold is
# the point: a Unifying receiver reports at 125 Hz (8 ms) and a Lightspeed
# mouse at 1000 Hz (1 ms), so one fixed millisecond figure means twelve missed
# reports on one device and a hundred on the other.
GAP_MULTIPLIER = 10.0

# Below this many motion samples the median is not stable enough to calibrate
# against, and a fabricated threshold is worse than admitting the run was too
# short.
MIN_CALIBRATION_EVENTS = 50

# How many samples either side of a gap to average when classifying it. Only
# the samples immediately adjacent matter: a user pause tapers, and a mean over
# a whole window is dominated by the fast samples at the start of the taper,
# which reads a real pause as a dropout.
VELOCITY_EDGE_SAMPLES = 3

# The "was the pointer actually moving" floor, as a fraction of the session's
# own median delta. Relative rather than absolute so the classifier is not
# calibrated to one DPI setting and one user's hand speed.
VELOCITY_FLOOR_FRAC = 0.35

DEFAULT_DURATION = 30

# ------------------------------------------------------------- status model
#
# Same six statuses freshcheck uses, and the same rule: unknown, skipped and
# info never affect the exit code. A check that could not read something for
# want of root is not a finding about the machine.

STATUS_ORDER = ["fail", "warn", "unknown", "info", "skipped", "ok"]
EXIT_STATUSES = {"fail", "warn"}

# Exit codes, matching rfscan and freshcheck. 1 means, and only means, that
# there is a finding to act on. Anything that reached no verdict is 2.
NO_FINDINGS = 0
FINDINGS = 1
COULD_NOT_DETERMINE = 2


def make(check_id, status, summary, detail=None, fix=None, result_id=None):
    return {
        "id": result_id or check_id,
        "check": check_id,
        "status": status,
        "summary": summary,
        "detail": list(detail or []),
        "fix": fix,
    }


CHECKS = []


def register(check_id, title):
    def decorator(fn):
        CHECKS.append({"id": check_id, "title": title, "fn": fn})
        return fn

    return decorator


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
    root = sysp(USB_DEVICES)
    if not root.is_dir():
        return []
    out = []
    for entry in sorted(root.iterdir()):
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
                "path": str(dev),
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

    found.sort(key=lambda d: (rank(d), d["name"]))
    return found


def root_hub_for(dev_path):
    """Walk up the sysfs tree to the root hub (usbN) owning this device."""
    try:
        node = Path(dev_path).resolve()
    except OSError:
        return None
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
    try:
        resolved = str(Path(dev_path).resolve())
    except OSError:
        return None
    # Normalise separators: on a Windows test host resolve() yields backslashes
    # and the address would never match.
    resolved = resolved.replace("\\", "/")
    matches = re.findall(r"/(0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])", resolved)
    return matches[-1] if matches else None


def speed_label(speed):
    if not speed or not speed.replace(".", "").isdigit():
        return ""
    value = float(speed)
    if value >= SUPERSPEED_MBPS:
        return "SuperSpeed"
    if value >= 480:
        return "USB 2.0"
    return "low/full speed"


# ------------------------------------------------------------------- checks


@register("topology", "USB topology")
def check_topology(ctx):
    rx = ctx["receiver"]
    detail = [
        f"Receiver:  {rx['product']} [{LOGITECH_VID}:{rx['pid']}]",
    ]
    if rx["label"]:
        detail.append(f"Type:      {rx['label']}")
    detail.append(f"Sysfs:     {rx['path']}")
    detail.append(f"Address:   bus {rx['busnum']} device {rx['devnum']}")

    hub = root_hub_for(rx["path"])
    if hub is not None:
        hub_speed = read_attr(hub, "speed")
        if hub_speed:
            detail.append(f"Root hub:  {hub.name} @ {hub_speed} Mbps")
    pci = pci_controller_for(rx["path"])
    if pci:
        detail.append(f"Host ctlr: {pci}")

    detail.append("")
    detail.append("USB root hubs on this machine:")
    for dev in usb_device_dirs():
        if not re.fullmatch(r"usb\d+", dev.name):
            continue
        speed = read_attr(dev, "speed") or "?"
        ports = read_attr(dev, "maxchild") or "?"
        marker = "  <-- receiver is here" if hub is not None and dev.name == hub.name else ""
        detail.append(f"    {dev.name:<8} {speed:>6} Mbps  {ports:>2} ports  {speed_label(speed)}{marker}")

    detail.append("")
    detail.append(
        "This does NOT tell you whether the physical port is USB 2 or USB 3. A "
        "full-speed HID device always enumerates on the USB 2 companion bus, "
        "whether you plugged it into a black port or a blue one, so the two are "
        "indistinguishable from software. Use --watch to A/B test ports instead "
        "of guessing."
    )
    return make("topology", "info", f"Receiver at {rx['name']} ({rx['product']})", detail=detail)


@register("siblings", "Devices sharing the host controller")
def check_siblings(ctx):
    """Correlation, not diagnosis.

    The tool cannot tell a USB 2 port from a USB 3 one, and does not claim to.
    It can say that a SuperSpeed device is enumerated on the same controller,
    which is real evidence the user can act on by moving one of them."""
    rx = ctx["receiver"]
    pci = pci_controller_for(rx["path"])
    if not pci:
        return make(
            "siblings",
            "skipped",
            "Could not resolve the receiver's host controller",
            detail=["Without a PCI address there is nothing to compare against."],
        )

    siblings = []
    for dev in usb_device_dirs():
        if dev.name == rx["name"]:
            continue
        # Root hubs are not neighbours. Every modern xHCI controller exposes a
        # SuperSpeed root hub, so counting them would make this fire on
        # essentially every machine and say nothing about whether an actual
        # noisy device is nearby.
        if re.fullmatch(r"usb\d+", dev.name):
            continue
        if pci_controller_for(dev) != pci:
            continue
        speed = read_attr(dev, "speed") or "?"
        siblings.append(
            {
                "name": dev.name,
                "product": read_attr(dev, "product") or "(no product string)",
                "speed": speed,
                "superspeed": speed.replace(".", "").isdigit()
                and float(speed) >= SUPERSPEED_MBPS,
            }
        )

    if not siblings:
        return make(
            "siblings",
            "info",
            f"Nothing else is enumerated on {pci}",
            detail=["The receiver has the host controller to itself."],
        )

    detail = [f"Host controller {pci} also carries:"]
    for sib in siblings:
        flag = "  <-- SuperSpeed" if sib["superspeed"] else ""
        detail.append(f"    {sib['name']:<10} {sib['speed']:>6} Mbps  {sib['product']}{flag}")

    loud = [s for s in siblings if s["superspeed"]]
    if loud:
        detail.append("")
        detail.append(
            "SuperSpeed signalling emits broadband noise across 2.4 GHz. A device "
            "like that on the same controller, or a cable running alongside the "
            "receiver, raises the noise floor and costs range."
        )
        detail.append(
            "This is a correlation and not a diagnosis. It says a plausible noise "
            "source is nearby, not that it is causing your problem. --watch with "
            "the neighbour unplugged is what would settle it."
        )
        summary = f"{len(loud)} SuperSpeed device(s) share the receiver's controller"
    else:
        summary = f"{len(siblings)} other device(s) share the receiver's controller"

    return make("siblings", "info", summary, detail=detail)


@register("module", "Kernel module")
def check_module(ctx):
    text = None
    try:
        text = sysp(PROC_MODULES).read_text()
    except OSError:
        text = None

    if text is None:
        if sysp(SYS_MODULE_DJ).exists():
            return make("module", "ok", "hid_logitech_dj is built in")
        return make(
            "module",
            "unknown",
            "Could not read /proc/modules",
            detail=["Cannot tell whether hid_logitech_dj is loaded."],
        )

    if re.search(r"^hid_logitech_dj\b", text, re.M):
        return make("module", "ok", "hid_logitech_dj is loaded")
    if sysp(SYS_MODULE_DJ).exists():
        return make("module", "ok", "hid_logitech_dj is built in")
    return make(
        "module",
        "fail",
        "hid_logitech_dj is not loaded",
        detail=[
            "Without it the receiver appears as one generic HID device, and",
            "per-device battery reporting and pairing will not work.",
        ],
        fix="sudo modprobe hid-logitech-dj",
    )


@register("autosuspend", "USB autosuspend")
def check_autosuspend(ctx):
    rx = ctx["receiver"]
    control = read_attr(rx["path"], "power/control")
    delay = read_attr(rx["path"], "power/autosuspend_delay_ms")

    if control is None:
        # Not exposed means runtime PM does not apply to this device. That is
        # not the same as it being misconfigured.
        return make(
            "autosuspend",
            "skipped",
            "power/control is not exposed for this device",
            detail=["Runtime power management does not apply here."],
        )

    detail = [f"power/control = {control}" + (f"  (delay {delay} ms)" if delay else "")]

    if control == "on":
        return make("autosuspend", "ok", "Autosuspend is disabled for this receiver", detail=detail)

    result = make(
        "autosuspend",
        "warn",
        "Receiver is allowed to autosuspend",
        detail=detail
        + [
            "This shows up as the pointer ignoring the first flick after the box",
            "has been idle. Harmless on a desk, irritating from the couch.",
        ],
        fix=f"echo on | sudo tee {rx['path']}/power/control",
    )

    if ctx["apply"]:
        good, err = write_attr(rx["path"], "power/control", "on")
        if good:
            ctx["applied"].append("power/control = on")
            return make(
                "autosuspend",
                "ok",
                "Autosuspend disabled (applied)",
                detail=detail + ["Set power/control = on at runtime."],
            )
        return make(
            "autosuspend", "fail", f"Could not write power/control: {err}", detail=detail
        )
    return result


@register("wakeup", "USB remote wakeup")
def check_wakeup(ctx):
    rx = ctx["receiver"]
    wakeup = read_attr(rx["path"], "power/wakeup")

    if wakeup is None:
        # The device never advertised remote-wakeup capability. There is
        # nothing to enable, so this is not applicable rather than a problem:
        # reporting it as a warning would send the user looking for a setting
        # that does not exist.
        return make(
            "wakeup",
            "skipped",
            "This device does not support remote wakeup",
            detail=[
                "power/wakeup is not exposed, so the device did not advertise the",
                "capability. It cannot resume the machine regardless of settings.",
            ],
        )

    detail = [f"power/wakeup = {wakeup}"]
    if wakeup == "enabled":
        return make("wakeup", "ok", "Remote wakeup is enabled", detail=detail)

    if ctx["apply"]:
        good, err = write_attr(rx["path"], "power/wakeup", "enabled")
        if good:
            ctx["applied"].append("power/wakeup = enabled")
            return make(
                "wakeup",
                "ok",
                "Remote wakeup enabled (applied)",
                detail=detail + ["Set power/wakeup = enabled at runtime."],
            )
        return make("wakeup", "fail", f"Could not write power/wakeup: {err}", detail=detail)

    return make(
        "wakeup",
        "warn",
        "Remote wakeup is disabled; the keyboard will not resume the machine",
        detail=detail
        + ["This is the classic K400 complaint. A settings problem, not a hardware limit."],
        fix=f"echo enabled | sudo tee {rx['path']}/power/wakeup",
    )


@register("acpi", "ACPI controller wakeup")
def check_acpi(ctx):
    """The per-port setting is useless if the parent controller is masked."""
    rx = ctx["receiver"]
    path = sysp(PROC_ACPI_WAKEUP)
    if not path.exists():
        return make(
            "acpi",
            "skipped",
            "/proc/acpi/wakeup is not present",
            detail=["Non-ACPI system, or ACPI wakeup support is disabled."],
        )

    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        return make("acpi", "unknown", f"Could not read /proc/acpi/wakeup: {exc}")

    pci = pci_controller_for(rx["path"])
    if not pci:
        return make(
            "acpi",
            "unknown",
            "Could not resolve the receiver's host controller",
            detail=["Without a PCI address the wakeup entries cannot be matched."],
        )

    for line in lines:
        if not line.strip() or line.startswith("Device"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name, sstate, status = parts[0], parts[1], parts[2]
        node = parts[3] if len(parts) > 3 else ""
        if pci not in node:
            continue
        if "enabled" in status:
            return make(
                "acpi",
                "ok",
                f"{name} ({node}) is wakeup-enabled, deepest state {sstate}",
            )
        return make(
            "acpi",
            "fail",
            f"{name} ({node}) is wakeup-DISABLED",
            detail=[
                "The per-port setting cannot work while the parent controller is",
                "masked in ACPI.",
                "",
                "That write is a TOGGLE, not a set. Running it twice puts you back",
                "where you started, which is exactly why this tool will not do it",
                "for you: there is no way to make it idempotent.",
            ],
            fix=f"echo {name} | sudo tee /proc/acpi/wakeup   # run EXACTLY once",
        )

    return make(
        "acpi",
        "info",
        f"No /proc/acpi/wakeup entry references {pci}",
        detail=["Usually fine. Not every controller is listed."],
    )


@register("battery", "Battery")
def check_battery(ctx):
    root = sysp(POWER_SUPPLY)
    if not root.is_dir():
        return make("battery", "skipped", "No power_supply class on this system")

    entries = []
    try:
        for entry in sorted(root.iterdir()):
            if entry.name.startswith("hidpp_battery"):
                entries.append(entry)
    except OSError:
        return make("battery", "unknown", "Could not enumerate the power_supply class")

    if not entries:
        return make(
            "battery",
            "skipped",
            "No hidpp_battery devices",
            detail=[
                "Normal for devices that do not report battery over HID++,",
                "including some K400 revisions.",
                "",
                "Worth knowing regardless: falling alkaline voltage cuts transmit",
                "power long before any indicator fires. If range degrades over",
                "months, swap cells before debugging RF.",
            ],
        )

    detail = []
    worst = "ok"
    for entry in entries:
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
        detail.append(f"{model}: {', '.join(bits) if bits else 'no reading'}")

        low = (capacity and capacity.isdigit() and int(capacity) <= 20) or (
            level and level.lower() in {"low", "critical"}
        )
        if low:
            worst = "warn"

    if worst == "warn":
        return make(
            "battery",
            "warn",
            "A paired device is low on battery",
            detail=detail + ["Low cells cut transmit power, which reads as range loss."],
            fix="Replace or recharge the cells",
        )
    return make("battery", "ok", f"{len(entries)} battery reading(s), all healthy", detail=detail)


@register("solaar", "solaar")
def check_solaar(ctx):
    from shutil import which

    if which("solaar"):
        return make("solaar", "ok", "solaar is installed")
    return make(
        "solaar",
        "info",
        "solaar is not installed",
        detail=["Optional, but handy for pairing and button remapping."],
        fix="sudo pacman -S solaar   # or your distro's equivalent",
    )


def build_rule(rx):
    return (
        f"{MANAGED_MARKER} - Logitech receiver: keep awake, allow resume.\n"
        "# Disables runtime autosuspend and enables USB remote wakeup.\n"
        'ACTION=="add", SUBSYSTEM=="usb", '
        f'ATTR{{idVendor}}=="{LOGITECH_VID}", ATTR{{idProduct}}=="{rx["pid"]}", '
        'ATTR{power/control}="on", ATTR{power/wakeup}="enabled"\n'
    )


@register("udev", "Persistent udev rule")
def check_udev(ctx):
    rx = ctx["receiver"]
    desired = build_rule(rx)
    path = sysp(UDEV_RULE)

    if path.exists():
        try:
            current = path.read_text()
        except OSError as exc:
            return make("udev", "unknown", f"Could not read {UDEV_RULE}: {exc}")
        if current.strip() == desired.strip():
            return make(
                "udev",
                "ok",
                f"{UDEV_RULE} is present and current",
                detail=[f"Pinned to idProduct {rx['pid']}, not all of {LOGITECH_VID}."],
            )
        summary = f"{UDEV_RULE} exists but does not match this receiver"
    else:
        summary = "No persistent rule; runtime settings are lost on reboot or re-plug"

    if ctx["apply"]:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(desired)
        except OSError as exc:
            return make("udev", "fail", f"Could not write the rule: {exc}")
        ctx["applied"].append(f"wrote {UDEV_RULE}")
        for cmd in (
            ["udevadm", "control", "--reload"],
            ["udevadm", "trigger", "--subsystem-match=usb"],
        ):
            rc, _, reason = run(cmd)
            if rc is None:
                ctx["applied"].append(f"{' '.join(cmd)}: {reason}")
            else:
                ctx["applied"].append(" ".join(cmd))
        return make(
            "udev",
            "ok",
            f"Wrote {UDEV_RULE} (applied)",
            detail=[f"Pinned to idProduct {rx['pid']}, not all of {LOGITECH_VID}."],
        )

    return make(
        "udev",
        "warn",
        summary,
        detail=["Would install:"] + [f"    {line}" for line in desired.rstrip().splitlines()],
        fix="sudo ./logi-rx.py --apply",
    )


# ------------------------------------------------------------------- revert


def revert():
    """Remove the udev rule, but only one this tool wrote."""
    path = sysp(UDEV_RULE)
    if not path.exists():
        return make("revert", "skipped", f"{UDEV_RULE} is not present; nothing to do")

    try:
        current = path.read_text()
    except OSError as exc:
        return make("revert", "unknown", f"Could not read {UDEV_RULE}: {exc}")

    if MANAGED_MARKER not in current:
        # Somebody else's rule happens to live at this path. Deleting it would
        # be destroying a file this tool did not create.
        return make(
            "revert",
            "skipped",
            f"{UDEV_RULE} was not written by this tool; leaving it alone",
            detail=[
                f"The managed marker ({MANAGED_MARKER}) is absent, so this file is",
                "not ours to remove. Delete it by hand if you are sure.",
            ],
        )

    try:
        path.unlink()
    except OSError as exc:
        return make("revert", "fail", f"Could not remove the rule: {exc}")

    run(["udevadm", "control", "--reload"])
    return make(
        "revert",
        "ok",
        f"Removed {UDEV_RULE}",
        detail=["Runtime sysfs values are unchanged until reboot or re-plug."],
    )


# --------------------------------------------------------------- watch mode

# struct input_event: two longs (timeval), then __u16, __u16, __s32
EVENT_FMT = "llHHi"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
EV_REL = 0x02
REL_X = 0x00
REL_Y = 0x01


def find_pointer_event_device():
    """Locate the evdev node for the Logitech pointer.

    Only an interface with a `mouse` handler is a pointer. The receiver also
    presents a keyboard-only interface, and selecting that one would produce a
    run with no motion at all."""
    try:
        blob = sysp(PROC_INPUT).read_text()
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


def read_events(fh, duration, blocking=False):
    """Read input_event structs into (timestamp, code, value) motion samples.

    Uses the kernel's own event timestamp rather than the read time: it is more
    accurate than userspace scheduling, and it makes the analysis deterministic
    under test. Non-motion events are dropped here, so a keypress can never be
    counted as pointer movement."""
    samples = []
    started = time.monotonic()
    while True:
        chunk = fh.read(EVENT_SIZE)
        if not chunk or len(chunk) < EVENT_SIZE:
            if blocking:
                break  # end of stream
            if time.monotonic() - started >= duration:
                break
            time.sleep(0.001)
            continue
        sec, usec, etype, code, value = struct.unpack(EVENT_FMT, chunk)
        if etype != EV_REL or code not in (REL_X, REL_Y):
            continue
        samples.append((sec + usec / 1_000_000.0, code, value))
        if not blocking and time.monotonic() - started >= duration:
            break
    return samples


def median(values):
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _edge_velocity(samples, start, stop):
    window = samples[max(0, start):stop]
    if not window:
        return 0.0
    return sum(abs(value) for _, _, value in window) / len(window)


def analyse(samples, gap_ms=None):
    """Turn motion samples into gap statistics, a threshold, and classifications.

    Pure: no I/O, no clock. Everything watch mode decides happens here, which is
    what makes it testable without a receiver."""
    report = {
        "motion_events": len(samples),
        "duration_s": None,
        "median_gap_ms": None,
        "median_delta": None,
        "threshold_ms": None,
        "threshold_source": None,
        "median_ms": None,
        "p99_ms": None,
        "worst_ms": None,
        "gaps": [],
        "dropouts": 0,
        "pauses": 0,
        "axis_counts": {"x": 0, "y": 0},
    }

    for _, code, _ in samples:
        if code == REL_X:
            report["axis_counts"]["x"] += 1
        elif code == REL_Y:
            report["axis_counts"]["y"] += 1

    if len(samples) < 2:
        return report

    report["duration_s"] = samples[-1][0] - samples[0][0]
    intervals = [samples[i][0] - samples[i - 1][0] for i in range(1, len(samples))]
    report["median_gap_ms"] = median(intervals) * 1000.0
    report["median_delta"] = median([abs(value) for _, _, value in samples])

    ordered = sorted(intervals)
    report["median_ms"] = ordered[len(ordered) // 2] * 1000.0
    report["p99_ms"] = ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))] * 1000.0
    report["worst_ms"] = ordered[-1] * 1000.0

    if gap_ms is not None:
        report["threshold_ms"] = float(gap_ms)
        report["threshold_source"] = "explicit"
    elif len(samples) >= MIN_CALIBRATION_EVENTS:
        report["threshold_ms"] = GAP_MULTIPLIER * report["median_gap_ms"]
        report["threshold_source"] = "calibrated"
    else:
        # Too few samples for a stable median. A fabricated threshold would be
        # worse than saying the run was too short.
        return report

    floor = (report["median_delta"] or 0.0) * VELOCITY_FLOOR_FRAC
    threshold_s = report["threshold_ms"] / 1000.0
    edge = VELOCITY_EDGE_SAMPLES

    for index in range(1, len(samples)):
        interval = samples[index][0] - samples[index - 1][0]
        if interval <= threshold_s:
            continue
        before = _edge_velocity(samples, index - edge, index)
        after = _edge_velocity(samples, index, index + edge)
        # A user pause tapers: the deltas either side shrink toward zero. A real
        # dropout does not, it is full-velocity motion on both sides of a hole.
        if floor > 0 and before < floor and after < floor:
            classification = "pause"
            report["pauses"] += 1
        else:
            classification = "dropout"
            report["dropouts"] += 1
        report["gaps"].append(
            {
                "at_s": samples[index][0] - samples[0][0],
                "gap_ms": interval * 1000.0,
                "classification": classification,
                "velocity_before": before,
                "velocity_after": after,
            }
        )

    return report


def watch_results(report, device_name, node):
    """Turn an analyse() report into findings."""
    detail = [f"Device: {device_name}", f"Node:   {node}"]

    if report["motion_events"] < 2:
        return [
            make(
                "watch",
                "unknown",
                "No motion recorded",
                detail=detail
                + [
                    "The pointer has to be moving for this to measure anything.",
                    "Nothing was recorded, so there is no result either way.",
                ],
            )
        ]

    detail += [
        f"Motion events: {report['motion_events']}"
        f"  (x {report['axis_counts']['x']}, y {report['axis_counts']['y']})",
        f"Median interval: {report['median_gap_ms']:.1f} ms"
        f"  ({1000.0 / report['median_gap_ms']:.0f} Hz nominal)"
        if report["median_gap_ms"]
        else "",
        f"Median delta:    {report['median_delta']:.1f} counts",
        f"p99 interval:    {report['p99_ms']:.1f} ms",
        f"Worst interval:  {report['worst_ms']:.1f} ms",
    ]
    detail = [line for line in detail if line]

    if report["threshold_source"] is None:
        return [
            make(
                "watch",
                "unknown",
                f"Too few motion events to calibrate ({report['motion_events']} of {MIN_CALIBRATION_EVENTS})",
                detail=detail
                + [
                    "The median interval is not stable enough to derive a threshold",
                    "from, and inventing one would produce a confident wrong answer.",
                    "Run for longer, or set one explicitly with --gap-ms.",
                ],
            )
        ]

    if report["threshold_source"] == "calibrated":
        detail.append(
            f"Threshold:       {report['threshold_ms']:.1f} ms "
            f"({GAP_MULTIPLIER:.0f}x the median interval, calibrated to this device)"
        )
    else:
        detail.append(f"Threshold:       {report['threshold_ms']:.1f} ms (set with --gap-ms)")

    results = []
    if report["pauses"]:
        results.append(
            make(
                "watch",
                "info",
                f"{report['pauses']} gap(s) classified as you pausing, not dropouts",
                detail=[
                    "Motion tapered off before the gap and ramped back up after it,",
                    "which is what letting go of the mouse looks like. A dropout has",
                    "full-velocity motion on both sides.",
                ]
                + [
                    f"    {gap['gap_ms']:7.1f} ms at t+{gap['at_s']:5.1f}s"
                    f"   velocity {gap['velocity_before']:.1f} -> {gap['velocity_after']:.1f}"
                    for gap in report["gaps"]
                    if gap["classification"] == "pause"
                ],
                result_id="watch-pauses",
            )
        )

    if not report["dropouts"]:
        results.append(
            make(
                "watch",
                "ok",
                f"No dropouts above {report['threshold_ms']:.1f} ms",
                detail=detail + ["This link is healthy at this distance."],
                result_id="watch-dropouts",
            )
        )
        return results

    results.append(
        make(
            "watch",
            "fail",
            f"{report['dropouts']} dropout(s) above {report['threshold_ms']:.1f} ms",
            detail=detail
            + [""]
            + [
                f"    {gap['gap_ms']:7.1f} ms at t+{gap['at_s']:5.1f}s"
                f"   velocity {gap['velocity_before']:.1f} -> {gap['velocity_after']:.1f}"
                for gap in report["gaps"]
                if gap["classification"] == "dropout"
            ]
            + [
                "",
                "Full-velocity motion either side of each gap, so these are the link",
                "dropping reports rather than you pausing.",
                "",
                "Next steps, in order of how cheaply they settle it:",
                "  1. Re-run from the same spot with the receiver on a different",
                "     port. A large drop in the count means the old port was the",
                "     problem, and USB 3 emissions sit right on top of 2.4 GHz.",
                "  2. If nothing changes, the band itself is the suspect. rfscan in",
                "     this repo maps 2.4 GHz occupancy and will tell you whether",
                "     your WiFi is sitting on top of the receiver:",
                "         rfscan",
                "  3. If the band is clear too, it is distance or transmit power,",
                "     and no amount of configuration will fix it.",
                "",
                "  --json makes the A/B comparison mechanical: save a run, move the",
                "  dongle, and diff the two instead of eyeballing them.",
            ],
            result_id="watch-dropouts",
        )
    )
    return results


def run_watch(args):
    """The I/O half of watch mode. Everything it decides lives in analyse()."""
    node, name = find_pointer_event_device()
    if not node:
        return None, [
            make(
                "watch",
                "unknown",
                "Could not find a Logitech pointer event device",
                detail=[
                    "Looked for a Logitech entry in /proc/bus/input/devices with a",
                    "'mouse' handler. Is the receiver plugged in and the pointer",
                    "paired? A keyboard-only interface does not count.",
                ],
            )
        ]

    emit(f"  Move the pointer for {args.duration}s.")
    emit("  Continuous motion gives the cleanest read, but pauses are now detected")
    emit("  and reported separately rather than counted as dropouts.")
    emit()

    try:
        handle = open(node, "rb", buffering=0)
    except PermissionError:
        return None, [
            make(
                "watch",
                "unknown",
                f"Permission denied reading {node}",
                detail=["Cannot measure anything without read access to the event node."],
                fix='sudo usermod -aG input "$USER"   # then log back in',
            )
        ]
    except OSError as exc:
        return None, [make("watch", "unknown", f"Could not open {node}: {exc}")]

    try:
        os.set_blocking(handle.fileno(), False)
        samples = read_events(handle, args.duration)
    except KeyboardInterrupt:
        samples = []
    finally:
        handle.close()

    report = analyse(samples, gap_ms=args.gap_ms)
    return report, watch_results(report, name, node)


# ---------------------------------------------------------------- formatting

WRAP_WIDTH = 70


def safe_text(text):
    """Printable on whatever encoding stdout actually has. Product strings and
    device names are not guaranteed ASCII and the console may be POSIX."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode(encoding, "backslashreplace").decode(encoding, "replace")
    except LookupError:
        return text.encode("ascii", "backslashreplace").decode("ascii")


def emit(text=""):
    print(safe_text(text))


def rule_char():
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "─".encode(encoding)
        return "─"
    except (UnicodeEncodeError, LookupError):
        return "-"


def wrap(text, width=WRAP_WIDTH):
    lines = []
    current = ""
    for word in text.split():
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


class Out:
    TAGS = {
        "ok": ("32", "[ ok ]"),
        "warn": ("33", "[warn]"),
        "fail": ("31", "[fail]"),
        "unknown": ("35", "[ ?? ]"),
        "skipped": ("90", "[skip]"),
        "info": ("36", "[info]"),
    }

    def __init__(self, color=True):
        self.color = color and sys.stdout.isatty()

    def _c(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def header(self, text):
        emit()
        emit(self._c("1;36", text))
        emit(self._c("36", rule_char() * len(text)))

    def finding(self, res):
        code, tag = self.TAGS.get(res["status"], ("0", "[    ]"))
        lines = wrap(res["summary"])
        emit(f"  {self._c(code, tag)} {lines[0]}")
        for line in lines[1:]:
            emit(f"         {line}")
        for line in res["detail"]:
            if not line:
                emit()
                continue
            # Only wrap prose. A line that is indented or contains a run of
            # spaces is a pre-formatted table row or a rule fragment, and
            # collapsing its whitespace would destroy the column alignment it
            # was written to have.
            if line.startswith(" ") or "  " in line:
                emit(f"         {self._c('90', line)}")
                continue
            for wrapped in wrap(line, WRAP_WIDTH):
                emit(f"         {self._c('90', wrapped)}")
        if res["fix"]:
            emit(f"         {self._c('1', 'fix:')} {res['fix']}")


# ------------------------------------------------------------------- runner


def build_report(args):
    report = {
        "tool": "logi-rx",
        "linux": is_linux(),
        "mode": "watch" if args.watch else "revert" if args.revert else "audit",
        "root": is_root(),
        "receiver": None,
        "other_logitech_devices": [],
        "results": [],
        "watch": None,
        "applied": [],
        "counts": {status: 0 for status in STATUS_ORDER},
        "error": None,
        "exit_code": NO_FINDINGS,
    }

    def finish():
        for res in report["results"]:
            report["counts"][res["status"]] = report["counts"].get(res["status"], 0) + 1
        if report["error"]:
            report["exit_code"] = COULD_NOT_DETERMINE
        elif any(res["status"] in EXIT_STATUSES for res in report["results"]):
            report["exit_code"] = FINDINGS
        elif all(
            res["status"] in ("unknown", "skipped", "info") for res in report["results"]
        ) and report["results"]:
            # Nothing was determined either way. Exiting 0 would claim a clean
            # bill of health that was never established.
            report["exit_code"] = COULD_NOT_DETERMINE
        return report

    if not report["linux"]:
        report["error"] = "not-linux"
        report["results"].append(
            make("platform", "unknown", "This tool only works on Linux (it reads sysfs directly)")
        )
        return finish()

    if args.watch:
        watch_report, results = run_watch(args)
        report["watch"] = watch_report
        report["results"] = results
        if any(res["status"] == "unknown" for res in results) and not any(
            res["status"] in EXIT_STATUSES for res in results
        ):
            report["error"] = "watch-inconclusive"
        return finish()

    if args.revert:
        if not is_root():
            report["error"] = "needs-root"
            report["results"].append(
                make("revert", "unknown", "--revert needs root", fix="sudo ./logi-rx.py --revert")
            )
            return finish()
        report["results"].append(revert())
        return finish()

    if args.apply and not is_root():
        report["error"] = "needs-root"
        report["results"].append(
            make("apply", "unknown", "--apply needs root", fix="sudo ./logi-rx.py --apply")
        )
        return finish()

    receivers = find_receivers()
    if not receivers:
        report["error"] = "no-device"
        report["results"].append(
            make(
                "receiver",
                "unknown",
                "No Logitech USB devices found",
                detail=["Is the receiver plugged in?"],
                fix="lsusb -d 046d:",
            )
        )
        return finish()

    if args.device:
        picked = [r for r in receivers if r["name"] == args.device]
        if not picked:
            report["error"] = "device-not-found"
            report["results"].append(
                make(
                    "receiver",
                    "unknown",
                    f"No Logitech device at sysfs node {args.device}",
                    detail=["Present: " + ", ".join(r["name"] for r in receivers)],
                )
            )
            return finish()
        receiver = picked[0]
    else:
        receiver = receivers[0]

    report["receiver"] = receiver
    report["other_logitech_devices"] = [
        {"name": r["name"], "product": r["product"], "pid": r["pid"]}
        for r in receivers
        if r["name"] != receiver["name"]
    ]

    ctx = {"receiver": receiver, "apply": args.apply, "applied": report["applied"]}
    for entry in CHECKS:
        try:
            produced = entry["fn"](ctx)
        except Exception as exc:  # noqa: BLE001
            produced = make(
                entry["id"],
                "unknown",
                f"Check raised {type(exc).__name__}",
                detail=[str(exc), "This is a bug in logi-rx, not a finding about your system."],
            )
        if produced is None:
            continue
        if isinstance(produced, dict):
            produced = [produced]
        for res in produced:
            res["title"] = entry["title"]
            report["results"].append(res)

    return finish()


def render(out, report):
    if report["receiver"]:
        out.header("Receiver")
        rx = report["receiver"]
        emit(f"  {rx['product']} [{LOGITECH_VID}:{rx['pid']}] at {rx['name']}")
        for other in report["other_logitech_devices"]:
            emit(f"  also present: {other['name']}  {other['product']} [{other['pid']}]")
        if report["other_logitech_devices"]:
            emit("  override the choice with --device NAME")

    grouped = {status: [] for status in STATUS_ORDER}
    for res in report["results"]:
        grouped.setdefault(res["status"], []).append(res)

    titles = {
        "fail": "Failures",
        "warn": "Warnings",
        "unknown": "Could not determine",
        "info": "Informational",
        "skipped": "Not applicable",
        "ok": "Passed",
    }
    for status in STATUS_ORDER:
        group = grouped.get(status) or []
        if not group:
            continue
        out.header(titles[status])
        for res in group:
            out.finding(res)

    if report["applied"]:
        out.header("Changes applied")
        for change in report["applied"]:
            emit(f"  {change}")

    out.header("Summary")
    counts = report["counts"]
    emit(
        "  "
        + "  ".join(
            f"{counts.get(status, 0)} {status}"
            for status in ("fail", "warn", "unknown", "info", "skipped", "ok")
        )
    )
    if counts.get("unknown"):
        emit("  'could not determine' is not a pass and not a failure; it means the")
        emit("  answer was not available.")
    if counts.get("skipped"):
        emit("  'not applicable' means the check does not apply to this device.")
    emit()
    if report["exit_code"] == NO_FINDINGS:
        emit("  Nothing to fix.")
    elif report["exit_code"] == FINDINGS and not report["applied"]:
        emit("  Re-run with sudo --apply to fix what is fixable.")
        emit("  Then: ./logi-rx.py --watch  to measure the link empirically.")


# --------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="Check and tune a Logitech wireless receiver on Linux.",
        epilog=(
            "Read-only by default: nothing changes unless you pass --apply, and "
            "--revert undoes everything --apply does.\n\n"
            "Exit codes: 0 nothing to fix, 1 findings to act on, 2 could not "
            "determine (not Linux, no receiver, no read access, or a watch run "
            "with nothing to measure)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apply", action="store_true", help="apply fixes (needs root)")
    parser.add_argument("--revert", action="store_true", help="remove the udev rule (needs root)")
    parser.add_argument("--watch", action="store_true", help="measure input dropouts")
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION, help="watch duration in seconds"
    )
    parser.add_argument(
        "--gap-ms",
        type=float,
        default=None,
        help="dropout threshold in ms. Omit to calibrate to the device's own "
        "report rate, which is almost always what you want.",
    )
    parser.add_argument("--device", help="force a sysfs device name, e.g. 1-3")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    args = parser.parse_args()

    if args.json:
        # Watch mode narrates to stdout while it runs, which would corrupt the
        # JSON document. Silence it.
        global emit
        original = emit
        emit = lambda text="": None  # noqa: E731
        try:
            report = build_report(args)
        finally:
            emit = original
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return report["exit_code"]

    report = build_report(args)
    render(Out(color=not args.no_color), report)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
