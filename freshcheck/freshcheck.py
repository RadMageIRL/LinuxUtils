#!/usr/bin/env python3
"""
freshcheck.py - post-install and post-update audit for a Linux box.

The checklist you would otherwise run from memory on a new machine, plus the
handful of failure modes whose symptoms point nowhere near their cause.

  * running kernel vs installed modules, the single most common cause of
    "my box went weird after an update and I don't know why"
  * microcode, distinguishing installed from actually loaded
  * TRIM, only where it applies, and flagging discard+timer redundancy
  * journal size, including .conf.d drop-ins
  * swap and zram, with swappiness judged against which one you have
  * CPU scaling driver and governor, judged as a pair with the EPP
  * time sync and RTC mode, without calling a dual-boot setting broken
  * filesystem headroom, with /boot held to a stricter bar than /
  * failed systemd units
  * boot time, reported without judgement

Read-only. Always. Every finding prints the exact command that would fix it
and this tool never runs any of them. That is what makes it safe to point at
a machine you do not own.

    ./freshcheck.py                    # audit everything
    ./freshcheck.py --json             # machine-readable, for cron
    ./freshcheck.py --only kernel      # one check
    ./freshcheck.py --skip boot-time   # everything but one

Runs fully without root. Anything that genuinely needs root degrades to
"cannot determine" with a note, never to a false pass.

No third-party dependencies.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------- test seams
#
# Every filesystem read goes through sysp(), and every external command
# through run(). Tests point SYSROOT at a synthetic tree and stub run(), which
# makes all of the checks below reachable without root and without a real
# machine sitting in a broken state.

SYSROOT = Path("/")
RUNNING_KERNEL = None  # tests set a string; None means ask the kernel
IS_ROOT = None  # tests set a bool; None means ask the OS
PLATFORM = None  # tests set "linux"; None means ask sys


def is_linux():
    return (PLATFORM or sys.platform) == "linux"


def sysp(path):
    """Resolve an absolute system path underneath SYSROOT."""
    return SYSROOT / str(path).lstrip("/")


def running_kernel():
    if RUNNING_KERNEL is not None:
        return RUNNING_KERNEL
    try:
        return os.uname().release
    except AttributeError:  # not POSIX; main() has already bailed by here
        return ""


def is_root():
    if IS_ROOT is not None:
        return IS_ROOT
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run(cmd, timeout=20):
    """Run a command. Returns (rc, stdout, reason). rc is None when the command
    could not be run at all, in which case reason says why."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, text=True, errors="replace"
        )
    except FileNotFoundError:
        return None, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return None, "", f"{' '.join(cmd)} timed out after {timeout}s"
    except OSError as exc:
        return None, "", str(exc)
    return proc.returncode, proc.stdout, (proc.stderr or "").strip() or None


def disk_usage(path):
    """(total_bytes, available_bytes) for the filesystem holding path, or None.

    Uses f_bavail rather than f_bfree: the reserved blocks are not available to
    the user whose disk is filling up, so counting them would overstate
    headroom on exactly the systems where headroom matters."""
    try:
        stat = os.statvfs(path)
    except (OSError, AttributeError):
        return None
    return stat.f_blocks * stat.f_frsize, stat.f_bavail * stat.f_frsize


# ------------------------------------------------------------- read helpers


def read_text(path):
    try:
        return sysp(path).read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def read_value(path):
    """A one-line sysfs/procfs attribute, stripped, or None."""
    text = read_text(path)
    return text.strip() if text is not None else None


def parse_kv_file(text):
    """Parse KEY=VALUE lines with optional quoting, as in os-release."""
    values = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def parse_table(path):
    """Parse an fstab/mounts style table into dicts, skipping comments."""
    entries = []
    for line in (read_text(path) or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        entries.append(
            {
                "spec": parts[0],
                "mount": parts[1],
                "fstype": parts[2],
                "opts": parts[3].split(","),
            }
        )
    return entries


SIZE_SUFFIXES = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}

# An uncapped journal is only worth mentioning once it is actually large.
JOURNAL_WARN_BYTES = 1024**3


def parse_size(text):
    """systemd-style size ("500M", "1G", bare bytes) to an integer, or None."""
    if not text:
        return None
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT])?\s*", text, re.I)
    if not match:
        return None
    number = float(match.group(1))
    suffix = (match.group(2) or "").upper()
    return int(number * SIZE_SUFFIXES.get(suffix, 1))


def fmt_bytes(count):
    if count is None:
        return "unknown"
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def version_key(text):
    """Sort key for kernel version strings.

    Splits into numeric and alphabetic runs so that 6.10 sorts above 6.9, which
    a plain string comparison gets backwards.

    The trailing (2, ...) sentinel handles pre-releases. Without it "6.10.0" is
    a strict prefix of "6.10.0-rc1" and therefore sorts BELOW it, which would
    have the tool announce a release candidate as newer than the release. The
    sentinel outranks an alphabetic run, so a bare version beats its own rc."""
    key = []
    for part in re.findall(r"\d+|[A-Za-z]+", text):
        if part.isdigit():
            key.append((1, int(part), ""))
        else:
            key.append((0, 0, part))
    key.append((2, 0, ""))
    return key


# ------------------------------------------------------------------- results

STATUS_ORDER = ["fail", "warn", "unknown", "info", "skipped", "ok"]
# unknown, info and skipped deliberately do not affect the exit code. A
# non-root run legitimately cannot answer several of these, and a routine
# unprivileged audit must not look like a failure.
EXIT_STATUSES = {"fail", "warn"}


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


# --------------------------------------------------------- distro / packages

PACKAGE_FAMILIES = [
    (
        {"arch", "archarm", "manjaro", "endeavouros", "cachyos", "garuda"},
        "sudo pacman -S {pkg}",
        {"amd": "amd-ucode", "intel": "intel-ucode"},
    ),
    (
        {"debian", "ubuntu", "linuxmint", "pop", "raspbian"},
        "sudo apt install {pkg}",
        {"amd": "amd64-microcode", "intel": "intel-microcode"},
    ),
    (
        {"fedora", "rhel", "centos", "rocky", "almalinux"},
        "sudo dnf install {pkg}",
        {"amd": "amd-ucode-firmware", "intel": "microcode_ctl"},
    ),
    (
        {"opensuse", "opensuse-tumbleweed", "opensuse-leap", "suse", "sles"},
        "sudo zypper install {pkg}",
        {"amd": "ucode-amd", "intel": "ucode-intel"},
    ),
]


def detect_distro():
    values = parse_kv_file(read_text("/etc/os-release"))
    id_like = [token for token in (values.get("ID_LIKE") or "").split() if token]
    return {
        "id": values.get("ID"),
        "id_like": id_like,
        "pretty_name": values.get("PRETTY_NAME"),
    }


def package_family(distro):
    """The packaging family for this distro, or None when unrecognised."""
    names = [distro.get("id")] + list(distro.get("id_like") or [])
    for name in names:
        if not name:
            continue
        for ids, template, packages in PACKAGE_FAMILIES:
            if name.lower() in ids:
                return template, packages
    return None, None


def microcode_hint(distro, vendor):
    template, packages = package_family(distro)
    if template is None or vendor not in ("amd", "intel"):
        return None
    return template.format(pkg=packages[vendor])


def have_systemd():
    """Whether this looks like a systemd system at all. Checks that depend on
    systemd report skipped rather than ok when it is absent."""
    rc, _, _ = run(["systemctl", "--version"])
    return rc == 0


# ------------------------------------------------------------------ checks


@register("kernel", "Running kernel vs installed modules")
def check_kernel(ctx):
    """The highest-value check here.

    After an update replaces the kernel package, the module tree for the
    *running* kernel is gone. modprobe then fails for anything not already
    loaded: USB devices stop enumerating on hotplug, VirtualBox breaks,
    filesystems refuse to mount. None of those error messages mention the
    kernel, which is why this is worth leading with."""
    running = running_kernel()

    # Arch keeps modules in /usr/lib/modules with /lib a symlink to usr/lib;
    # others use /lib/modules directly. Deduplicate by resolved path so a
    # symlinked layout is not reported twice.
    bases = {}
    for candidate in ("/usr/lib/modules", "/lib/modules"):
        path = sysp(candidate)
        if not path.is_dir():
            continue
        try:
            key = path.resolve()
        except OSError:
            key = path
        bases.setdefault(key, (candidate, path))

    if not bases:
        return make(
            "kernel",
            "unknown",
            "No module tree found under /usr/lib/modules or /lib/modules",
            detail=["Unusual layout, or a distro that does not ship modules there."],
        )

    installed = {}
    for origin, path in bases.values():
        try:
            for entry in path.iterdir():
                if entry.is_dir():
                    installed.setdefault(entry.name, set()).add(origin)
        except OSError:
            continue

    if not installed:
        return make(
            "kernel",
            "unknown",
            "Module directories exist but contain no kernel versions",
        )

    versions = sorted(installed, key=version_key)
    newest = versions[-1]
    results = []

    if running not in installed:
        results.append(
            make(
                "kernel",
                "fail",
                f"Modules for the running kernel ({running}) are missing",
                detail=[
                    "An update replaced the kernel package and deleted the module",
                    "tree the running system is still using. modprobe now fails for",
                    "anything not already loaded: USB devices will not enumerate on",
                    "hotplug, VirtualBox and similar break, and filesystems whose",
                    "modules are not resident will refuse to mount.",
                    "",
                    f"Installed versions: {', '.join(versions)}",
                    "",
                    "Until you reboot, avoid hotplugging hardware and mounting",
                    "filesystem types you have not already used this session.",
                ],
                fix="sudo reboot",
                result_id="kernel-modules",
            )
        )
    else:
        found_in = ", ".join(sorted(installed[running]))
        results.append(
            make(
                "kernel",
                "ok",
                f"Modules for the running kernel ({running}) are present",
                detail=[f"Found under {found_in}."],
                result_id="kernel-modules",
            )
        )

    # Reported separately and at a lower severity: a pending reboot is routine
    # housekeeping, a missing module tree is an actively degraded system.
    if version_key(newest) > version_key(running):
        results.append(
            make(
                "kernel",
                "warn",
                f"Newer kernel installed ({newest}) than the one running ({running})",
                detail=[
                    "Routine after an update. The running kernel keeps working until",
                    "you reboot; this is only flagged so the reboot is a decision",
                    "rather than a surprise.",
                ],
                fix="sudo reboot",
                result_id="kernel-reboot-pending",
            )
        )

    return results


@register("microcode", "CPU microcode")
def check_microcode(ctx):
    """Installed and loaded are different questions. A package sitting on disk
    proves nothing: if its image is not wired into the bootloader it never
    loads, and the sysfs revision alone cannot tell you which happened."""
    vendor_raw = None
    model = None
    for line in (read_text("/proc/cpuinfo") or "").splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "vendor_id" and vendor_raw is None:
            vendor_raw = value.strip()
        elif key == "model name" and model is None:
            model = value.strip()

    vendor = {"AuthenticAMD": "amd", "GenuineIntel": "intel"}.get(vendor_raw or "")
    version = read_value("/sys/devices/system/cpu/cpu0/microcode/version")

    detail = []
    if model:
        detail.append(f"CPU: {model}")
    if version:
        detail.append(f"Running microcode revision: {version}")

    if version is None:
        return make(
            "microcode",
            "unknown",
            "Kernel does not expose a microcode revision for cpu0",
            detail=detail
            + ["Without /sys/.../microcode/version there is nothing to compare."],
        )

    # dmesg is the only way to confirm an *early* load, and it is restricted by
    # default on many distros. Reporting "not loaded" when we simply were not
    # allowed to look would be the exact false negative this check exists to
    # avoid.
    restricted = (read_value("/proc/sys/kernel/dmesg_restrict") or "0").strip() != "0"
    if restricted and not is_root():
        return make(
            "microcode",
            "unknown",
            "Cannot confirm early microcode load: dmesg is restricted",
            detail=detail
            + [
                "kernel.dmesg_restrict=1 and this run is unprivileged, so the boot",
                "log is unreadable. The revision above may be the factory one or an",
                "updated one; from here those look identical.",
                "",
                "Re-run as root to check, or read it directly:",
                "    sudo dmesg | grep -i microcode",
            ],
        )

    rc, output, reason = run(["dmesg"])
    if rc != 0:
        return make(
            "microcode",
            "unknown",
            "Cannot confirm early microcode load: dmesg unavailable",
            detail=detail + [f"dmesg: {reason or 'failed'}"],
        )

    lines = [line for line in output.splitlines() if "microcode" in line.lower()]
    if lines:
        return make(
            "microcode",
            "ok",
            "Microcode is loaded",
            detail=detail + ["Kernel log:"] + [f"    {line.strip()}" for line in lines[:4]],
        )

    hint = microcode_hint(ctx["distro"], vendor)
    image = f"{vendor}-ucode.img" if vendor else "the microcode image"
    return make(
        "microcode",
        "warn",
        "No microcode update found in the kernel log",
        detail=detail
        + [
            "The package may be installed without being wired into boot. The image",
            f"({image}) has to be listed as an initrd BEFORE the main initramfs in",
            "the bootloader entry, or it is never read.",
            "",
            "systemd-boot: add to /boot/loader/entries/*.conf",
            "GRUB:         regenerate with grub-mkconfig -o /boot/grub/grub.cfg",
        ],
        fix=hint,
    )


@register("trim", "SSD TRIM")
def check_trim(ctx):
    """Only meaningful where there is a real SSD. zram and loop devices also
    report non-rotational, and counting them would invent an SSD on machines
    that do not have one."""
    ignore = ("zram", "loop", "ram", "sr", "fd")
    ssds = []
    block = sysp("/sys/block")
    if block.is_dir():
        try:
            for device in sorted(block.iterdir()):
                if device.name.startswith(ignore):
                    continue
                rotational = read_value(f"/sys/block/{device.name}/queue/rotational")
                if rotational == "0":
                    ssds.append(device.name)
        except OSError:
            pass

    if not ssds:
        return make(
            "trim",
            "skipped",
            "No non-rotational devices present",
            detail=["Nothing here needs TRIM."],
        )

    rc, virt, _ = run(["systemd-detect-virt"])
    virt = (virt or "").strip()
    if rc == 0 and virt and virt != "none":
        return make(
            "trim",
            "skipped",
            f"Running under {virt}; discard is the host's business",
            detail=[
                f"Non-rotational devices: {', '.join(ssds)}",
                "Guest-side trim may be a no-op or may pass through, depending on how",
                "the host configured the backing store. Not something this tool can",
                "determine from inside the guest.",
            ],
        )

    if not ctx["systemd"]:
        return make(
            "trim",
            "skipped",
            "No systemd; fstrim.timer does not apply",
            detail=[f"Non-rotational devices: {', '.join(ssds)}"],
        )

    rc, enabled, _ = run(["systemctl", "is-enabled", "fstrim.timer"])
    enabled = (enabled or "").strip()
    timer_on = enabled in ("enabled", "enabled-runtime", "static", "indirect")

    discard_mounts = [
        entry["mount"]
        for entry in parse_table("/etc/fstab")
        if any(opt == "discard" for opt in entry["opts"])
    ]

    detail = [f"Non-rotational devices: {', '.join(ssds)}", f"fstrim.timer: {enabled or 'unknown'}"]
    if discard_mounts:
        detail.append(f"fstab discard on: {', '.join(discard_mounts)}")

    if timer_on and discard_mounts:
        return make(
            "trim",
            "warn",
            "Both fstrim.timer and continuous discard are active",
            detail=detail
            + [
                "Redundant. Continuous discard issues a trim on every delete, which",
                "is a measurable throughput cost on many SSDs. Periodic trim via the",
                "timer is the current recommended default.",
                "",
                "Drop the discard option from the entries above and remount.",
            ],
            fix="sudoedit /etc/fstab   # remove the 'discard' mount option",
        )
    if timer_on:
        return make("trim", "ok", "fstrim.timer is enabled", detail=detail)
    if discard_mounts:
        return make(
            "trim",
            "warn",
            "Trim happens via continuous discard rather than the timer",
            detail=detail
            + [
                "This does trim, but at a throughput cost on every delete. The timer",
                "is the recommended arrangement.",
            ],
            fix="sudo systemctl enable --now fstrim.timer",
        )
    return make(
        "trim",
        "warn",
        "No TRIM configured",
        detail=detail
        + ["Neither fstrim.timer nor a discard mount option is in effect."],
        fix="sudo systemctl enable --now fstrim.timer",
    )


@register("journal", "Journal size")
def check_journal(ctx):
    """journald's default cap is 10% of the filesystem, which on a large root
    partition is gigabytes of logs nobody asked for."""
    files = []
    main = sysp("/etc/systemd/journald.conf")
    if main.is_file():
        files.append(("/etc/systemd/journald.conf", main))
    dropins = sysp("/etc/systemd/journald.conf.d")
    if dropins.is_dir():
        try:
            for path in sorted(dropins.glob("*.conf")):
                files.append((f"/etc/systemd/journald.conf.d/{path.name}", path))
        except OSError:
            pass

    # Last setting wins, and drop-ins are read after the main file. Checking
    # only journald.conf is the common bug here and misreports a correctly
    # configured system as unconfigured.
    cap_raw, cap_source = None, None
    for label, path in files:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;" or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip().lower() == "systemmaxuse":
                cap_raw, cap_source = value.strip(), label

    usage = None
    journal_dir = sysp("/var/log/journal")
    if journal_dir.is_dir():
        usage = 0
        try:
            for entry in journal_dir.rglob("*"):
                try:
                    if entry.is_file():
                        usage += entry.stat().st_size
                except OSError:
                    continue
        except OSError:
            pass

    detail = [f"On-disk journal: {fmt_bytes(usage)}" if usage is not None else "No /var/log/journal (volatile or absent)"]
    if files:
        detail.append(f"Config read: {', '.join(label for label, _ in files)}")

    if cap_raw:
        detail.append(f"SystemMaxUse={cap_raw} (from {cap_source})")
        return make("journal", "ok", f"Journal capped at {cap_raw}", detail=detail)

    detail.append("No SystemMaxUse set; journald defaults to 10% of the filesystem.")
    if usage is not None and usage > JOURNAL_WARN_BYTES:
        return make(
            "journal",
            "warn",
            f"Journal is {fmt_bytes(usage)} with no explicit cap",
            detail=detail,
            fix="echo 'SystemMaxUse=500M' | sudo tee /etc/systemd/journald.conf.d/00-size.conf",
        )
    return make(
        "journal",
        "ok",
        f"Journal is {fmt_bytes(usage)}, no explicit cap",
        detail=detail,
    )


@register("swap", "Swap and zram")
def check_swap(ctx):
    """The nuance worth writing this for: with zram, a HIGH swappiness is
    correct. Compressing to RAM is cheap, so you want the kernel to prefer it.
    A tool that flagged 180 as a problem would be actively wrong."""
    swaps = []
    for line in (read_text("/proc/swaps") or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            try:
                size = int(parts[2]) * 1024
            except ValueError:
                size = None
            swaps.append({"name": parts[0], "type": parts[1], "size": size})

    mem_total = None
    match = re.search(r"^MemTotal:\s+(\d+)\s*kB", read_text("/proc/meminfo") or "", re.M)
    if match:
        mem_total = int(match.group(1)) * 1024

    zram_present = any(sysp("/sys/block").glob("zram*")) if sysp("/sys/block").is_dir() else False
    zram_swaps = [s for s in swaps if "zram" in s["name"]]
    swappiness = read_value("/proc/sys/vm/swappiness")

    detail = []
    if mem_total:
        detail.append(f"RAM: {fmt_bytes(mem_total)}")
    for entry in swaps:
        share = ""
        if entry["size"] and mem_total:
            share = f"  ({entry['size'] / mem_total * 100:.0f}% of RAM)"
        detail.append(f"Swap: {entry['name']}  {entry['type']}  {fmt_bytes(entry['size'])}{share}")
    if swappiness is not None:
        detail.append(f"vm.swappiness = {swappiness}")

    if not swaps:
        detail.append("zram devices present but unused for swap" if zram_present else "")
        return make(
            "swap",
            "warn",
            "No swap configured",
            detail=[line for line in detail if line]
            + [
                "Workable on a large-RAM machine, but it removes the kernel's ability",
                "to evict anything under pressure: the OOM killer becomes the first",
                "response rather than the last. zram costs no disk and is compressed",
                "into RAM.",
            ],
            fix="sudo systemctl enable --now systemd-zram-setup@zram0.service",
        )

    try:
        swappiness_value = int(swappiness) if swappiness is not None else None
    except ValueError:
        swappiness_value = None

    if zram_swaps:
        if swappiness_value is None:
            return make(
                "swap",
                "unknown",
                "zram swap active, but vm.swappiness is unreadable",
                detail=detail,
            )
        if swappiness_value >= 100:
            return make(
                "swap",
                "ok",
                f"zram swap active with vm.swappiness={swappiness_value}",
                detail=detail
                + [
                    "Correct pairing. zram compresses into RAM, so swapping is cheap",
                    "and the kernel should prefer it over reclaiming page cache. High",
                    "swappiness is the right setting here, not a problem.",
                ],
            )
        return make(
            "swap",
            "warn",
            f"zram swap active but vm.swappiness={swappiness_value} is tuned for disk",
            detail=detail
            + [
                "The default of 60 assumes swapping is expensive because it means",
                "disk I/O. With zram it does not: it is a compressed region of RAM.",
                "180 is the commonly recommended value for zram-backed swap.",
            ],
            fix="echo 'vm.swappiness=180' | sudo tee /etc/sysctl.d/99-swappiness.conf",
        )

    if swappiness_value is not None and swappiness_value >= 100:
        return make(
            "swap",
            "warn",
            f"Disk swap with vm.swappiness={swappiness_value}",
            detail=detail
            + [
                "That value is tuned for zram. On disk-backed swap it will push the",
                "machine into paging sooner than it needs to, which is felt as",
                "stutter. 60 is the default and is a reasonable place to be.",
            ],
            fix="echo 'vm.swappiness=60' | sudo tee /etc/sysctl.d/99-swappiness.conf",
        )
    return make("swap", "ok", "Swap configured", detail=detail)


@register("cpu", "CPU scaling")
def check_cpu(ctx):
    """Governor alone is not a verdict.

    On amd_pstate-epp and intel_pstate in active mode, the powersave governor
    paired with a performance EPP is the CORRECT configuration and is what a
    current Ryzen will be running. Flagging that as a problem would be wrong
    and would teach the user to ignore this tool."""
    base = "/sys/devices/system/cpu/cpu0/cpufreq"
    if not sysp(base).is_dir():
        return make(
            "cpu",
            "unknown",
            "No cpufreq interface for cpu0",
            detail=["Scaling may be firmware-managed, or this is a VM."],
        )

    driver = read_value(f"{base}/scaling_driver")
    governor = read_value(f"{base}/scaling_governor")
    epp = read_value(f"{base}/energy_performance_preference")
    pstate_status = read_value("/sys/devices/system/cpu/amd_pstate/status")

    detail = [f"Driver: {driver or 'unknown'}", f"Governor: {governor or 'unknown'}"]
    if epp:
        detail.append(f"Energy performance preference: {epp}")
    if pstate_status:
        detail.append(f"amd_pstate status: {pstate_status}")

    normalised = (driver or "").replace("_", "-").lower()

    # The presence of the EPP attribute is the reliable signal for active/EPP
    # mode, more so than matching driver name spellings across kernel versions.
    if epp is not None or normalised in ("amd-pstate-epp", "intel-pstate"):
        if governor == "performance":
            return make(
                "cpu",
                "ok",
                f"{driver} with the performance governor",
                detail=detail
                + ["Maximum responsiveness, at a higher idle power draw."],
            )
        if governor == "powersave":
            if epp in ("performance", "balance_performance"):
                return make(
                    "cpu",
                    "ok",
                    f"{driver}: powersave governor with {epp} EPP",
                    detail=detail
                    + [
                        "This is the correct configuration, not a problem. In active",
                        "EPP mode the governor name is misleading: the hardware picks",
                        "frequencies and the EPP is what biases it. powersave plus a",
                        "performance-leaning EPP is the normal desktop arrangement.",
                    ],
                )
            if epp is None:
                return make(
                    "cpu",
                    "unknown",
                    f"{driver} with the powersave governor, EPP unreadable",
                    detail=detail
                    + ["Cannot judge the pairing without the EPP value."],
                )
            return make(
                "cpu",
                "warn",
                f"{driver}: powersave governor with {epp} EPP",
                detail=detail
                + [
                    "The EPP is biased toward efficiency over responsiveness. That is",
                    "a reasonable choice on a laptop on battery and a questionable one",
                    "on a desktop.",
                ],
                fix="echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference",
            )
        return make(
            "cpu",
            "unknown",
            f"{driver} with an unrecognised governor ({governor})",
            detail=detail,
        )

    # Passive / acpi-cpufreq: here the classic governor semantics do apply, and
    # powersave really does pin the CPU near its minimum frequency.
    if governor == "powersave":
        return make(
            "cpu",
            "warn",
            f"{driver} with the powersave governor",
            detail=detail
            + [
                "On this driver the governor is not advisory: powersave holds the CPU",
                "near its minimum frequency. On a desktop that is felt as sluggishness",
                "under light load.",
            ],
            fix="echo schedutil | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
        )
    if governor in ("schedutil", "ondemand", "conservative", "performance"):
        return make("cpu", "ok", f"{driver} with the {governor} governor", detail=detail)
    return make(
        "cpu",
        "unknown",
        f"{driver} with an unrecognised governor ({governor})",
        detail=detail,
    )


@register("time", "Time sync and RTC")
def check_time(ctx):
    if not ctx["systemd"]:
        return make("time", "skipped", "No systemd; timedatectl unavailable")

    rc, output, reason = run(["timedatectl", "show"])
    if rc != 0:
        return make(
            "time",
            "unknown",
            "Could not query timedatectl",
            detail=[reason or "timedatectl failed"],
        )

    values = parse_kv_file(output)
    synced = values.get("NTPSynchronized")
    ntp = values.get("NTP")
    local_rtc = values.get("LocalRTC")
    timezone = values.get("Timezone")

    results = []
    detail = [f"Timezone: {timezone}" if timezone else "", f"NTP enabled: {ntp}"]
    detail = [line for line in detail if line]

    if synced == "yes":
        results.append(make("time", "ok", "Clock is synchronised", detail=detail, result_id="time-sync"))
    elif synced == "no":
        results.append(
            make(
                "time",
                "warn",
                "Clock is not synchronised",
                detail=detail
                + [
                    "Drift breaks TLS certificate validation and package signature",
                    "checks long before it becomes visible as a wrong clock.",
                ],
                fix="sudo timedatectl set-ntp true",
                result_id="time-sync",
            )
        )
    else:
        results.append(
            make("time", "unknown", "timedatectl did not report NTPSynchronized", detail=detail, result_id="time-sync")
        )

    if local_rtc == "yes":
        results.append(
            make(
                "time",
                "ok",
                "RTC is in local time",
                detail=[
                    "This is the Windows-compatible setting and is almost certainly",
                    "deliberate on a dual-boot machine, so it is reported rather than",
                    "flagged. The tradeoff is that DST transitions and timezone",
                    "changes are handled by whichever OS booted last.",
                    "",
                    "On a Linux-only machine, UTC is the better default:",
                    "    sudo timedatectl set-local-rtc 0",
                ],
                result_id="time-rtc",
            )
        )
    elif local_rtc == "no":
        results.append(
            make(
                "time",
                "ok",
                "RTC is in UTC",
                detail=["The right default, unless this machine dual-boots Windows."],
                result_id="time-rtc",
            )
        )

    return results


@register("filesystem", "Filesystem headroom")
def check_filesystem(ctx):
    """/boot is held to a stricter bar than / on purpose. It is typically small,
    every kernel update writes a new initramfs into it, and a full /boot makes
    an update fail PARTWAY: a kernel installed with no matching initramfs is a
    much worse state than an update that refused to start."""
    mounts = parse_table("/proc/mounts")
    mounted = {entry["mount"]: entry for entry in mounts}

    targets = [("/", 10, 5)]
    for path in ("/boot", "/var"):
        if path in mounted:
            targets.append((path, 20 if path == "/boot" else 10, 10 if path == "/boot" else 5))

    esp = next(
        (
            entry["mount"]
            for entry in mounts
            if entry["fstype"] in ("vfat", "msdos")
            and entry["mount"].startswith(("/boot", "/efi"))
        ),
        None,
    )
    if esp and esp not in [t[0] for t in targets]:
        targets.append((esp, 20, 10))

    detail = []
    worst = "ok"
    findings = []
    for path, warn_pct, fail_pct in targets:
        usage = disk_usage(sysp(path))
        if usage is None:
            detail.append(f"{path:<12} could not be measured")
            if worst == "ok":
                worst = "unknown"
            continue
        total, available = usage
        if total <= 0:
            continue
        pct = available / total * 100
        detail.append(
            f"{path:<12} {fmt_bytes(available):>10} free of {fmt_bytes(total):>10}  ({pct:.0f}%)"
        )
        if pct < fail_pct:
            worst = "fail"
            findings.append(f"{path} is at {pct:.0f}% free")
        elif pct < warn_pct:
            if worst != "fail":
                worst = "warn"
            findings.append(f"{path} is at {pct:.0f}% free")

    if not detail:
        return make("filesystem", "unknown", "No filesystems could be measured")

    if worst == "ok":
        return make("filesystem", "ok", "Filesystem headroom is fine", detail=detail)
    if worst == "unknown":
        return make("filesystem", "unknown", "Some filesystems could not be measured", detail=detail)

    boot_involved = any(f.startswith(("/boot", "/efi")) for f in findings)
    extra = []
    if boot_involved:
        extra = [
            "",
            "A full /boot is worse than it looks: kernel updates write a new",
            "initramfs there and fail partway when they run out of room, leaving a",
            "kernel with no matching initramfs. Clear old kernels before updating.",
        ]
    return make(
        "filesystem",
        worst,
        "; ".join(findings),
        detail=detail + extra,
        fix="sudo journalctl --vacuum-size=200M   # and remove unused kernels",
    )


@register("failed-units", "Failed systemd units")
def check_failed_units(ctx):
    if not ctx["systemd"]:
        return make("failed-units", "skipped", "No systemd on this machine")

    rc, output, reason = run(["systemctl", "--failed", "--no-legend", "--plain"])
    if rc is None:
        return make("failed-units", "unknown", "Could not run systemctl", detail=[reason or ""])

    units = [line.split()[0] for line in (output or "").splitlines() if line.strip()]
    if not units:
        return make("failed-units", "ok", "No failed units")
    return make(
        "failed-units",
        "fail",
        f"{len(units)} failed unit(s)",
        detail=[f"    {unit}" for unit in units],
        fix=f"systemctl status {units[0]}",
    )


@register("boot-time", "Boot time")
def check_boot_time(ctx):
    """Informational only. A slow unit is not necessarily a problem, so this
    deliberately does not assign a pass or fail."""
    if not ctx["systemd"]:
        return make("boot-time", "skipped", "No systemd on this machine")

    detail = []
    rc, output, _ = run(["systemd-analyze", "time"])
    summary = "Boot time"
    if rc == 0 and output.strip():
        summary = output.strip().splitlines()[0]

    rc, output, reason = run(["systemd-analyze", "blame"])
    if rc == 0:
        for line in output.splitlines()[:5]:
            if line.strip():
                detail.append(f"    {line.strip()}")
    elif rc is None:
        return make("boot-time", "skipped", "systemd-analyze unavailable", detail=[reason or ""])

    if detail:
        detail.insert(0, "Slowest units:")
    detail.append("")
    detail.append("Informational. A slow unit is not automatically a problem.")
    return make("boot-time", "info", summary, detail=detail)


# ---------------------------------------------------------------- formatting

WRAP_WIDTH = 72


def safe_text(text):
    """Printable on whatever encoding stdout actually has.

    Unit names and PRETTY_NAME strings are not guaranteed ASCII and the console
    may be POSIX/ASCII under cron. Escaping beats dying."""
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


class Out:
    """Tiny console formatter. Colour only when stdout is a terminal."""

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
        emit(f"  {self._c(code, tag)} {res['summary']}")
        for line in res["detail"]:
            emit(f"         {self._c('90', line)}" if line else "")
        if res["fix"]:
            emit(f"         {self._c('1', 'fix:')} {res['fix']}")


# ------------------------------------------------------------------ runner


def run_checks(selected):
    ctx = {"distro": detect_distro(), "systemd": have_systemd()}
    results = []
    for entry in CHECKS:
        if entry["id"] not in selected:
            continue
        try:
            produced = entry["fn"](ctx)
        except Exception as exc:  # noqa: BLE001
            # One check blowing up must not take down the audit. The failure is
            # reported as unknown for that check and nothing else.
            produced = make(
                entry["id"],
                "unknown",
                f"Check raised {type(exc).__name__}",
                detail=[str(exc), "This is a bug in freshcheck, not a finding about your system."],
            )
        if produced is None:
            continue
        if isinstance(produced, dict):
            produced = [produced]
        for res in produced:
            res["title"] = entry["title"]
            results.append(res)
    return ctx, results


def build_report(args):
    report = {
        "tool": "freshcheck",
        "linux": is_linux(),
        "distro": None,
        "kernel": None,
        "root": None,
        "results": [],
        "counts": {status: 0 for status in STATUS_ORDER},
        "exit_code": 0,
    }
    if not report["linux"]:
        report["exit_code"] = 2
        return report

    selected = [entry["id"] for entry in CHECKS]
    if args.only:
        selected = [cid for cid in selected if cid in args.only]
    if args.skip:
        selected = [cid for cid in selected if cid not in args.skip]

    ctx, results = run_checks(selected)
    report["distro"] = ctx["distro"]
    report["kernel"] = running_kernel()
    report["root"] = is_root()
    report["results"] = results
    for res in results:
        report["counts"][res["status"]] = report["counts"].get(res["status"], 0) + 1
    if any(res["status"] in EXIT_STATUSES for res in results):
        report["exit_code"] = 1
    return report


def render(out, report):
    if not report["linux"]:
        out.header("Result")
        out.finding(
            make("platform", "fail", "This tool only works on Linux (it reads /proc and /sys directly)")
        )
        return

    out.header("System")
    distro = report["distro"] or {}
    emit(f"  {distro.get('pretty_name') or distro.get('id') or 'unknown distribution'}")
    emit(f"  kernel {report['kernel']}")
    if not report["root"]:
        emit("  running unprivileged; checks that need root will say so rather than guess")

    by_status = {status: [] for status in STATUS_ORDER}
    for res in report["results"]:
        by_status.setdefault(res["status"], []).append(res)

    titles = {
        "fail": "Failures",
        "warn": "Warnings",
        "unknown": "Could not determine",
        "info": "Informational",
        "skipped": "Not applicable",
        "ok": "Passed",
    }
    for status in STATUS_ORDER:
        group = by_status.get(status) or []
        if not group:
            continue
        out.header(titles[status])
        for res in group:
            out.finding(res)

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
        emit("  answer was not available, usually for want of root.")
    if counts.get("skipped"):
        emit("  'not applicable' means the check does not apply to this machine.")
    emit()
    if report["exit_code"] == 0:
        emit("  Nothing to fix.")
    else:
        emit("  Fix commands are printed above. This tool does not run any of them.")


# --------------------------------------------------------------------- main


def main():
    check_ids = [entry["id"] for entry in CHECKS]
    parser = argparse.ArgumentParser(
        description="Post-install and post-update audit for a Linux machine.",
        epilog=(
            "Read-only: every finding prints the command that would fix it and this "
            "tool runs none of them.\n\n"
            "Checks: " + ", ".join(check_ids)
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    parser.add_argument(
        "--only", action="append", metavar="CHECK", help="run only these checks (repeatable, comma-separated)"
    )
    parser.add_argument(
        "--skip", action="append", metavar="CHECK", help="skip these checks (repeatable, comma-separated)"
    )
    args = parser.parse_args()

    def expand(values):
        out = []
        for value in values or []:
            out.extend(part.strip() for part in value.split(",") if part.strip())
        return out

    args.only = expand(args.only)
    args.skip = expand(args.skip)

    unknown = [cid for cid in args.only + args.skip if cid not in check_ids]
    if unknown:
        parser.error(
            f"unknown check(s): {', '.join(unknown)}\nvalid checks: {', '.join(check_ids)}"
        )

    report = build_report(args)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        render(Out(color=not args.no_color), report)

    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
