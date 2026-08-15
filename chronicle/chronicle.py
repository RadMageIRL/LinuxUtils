#!/usr/bin/env python3
"""
chronicle.py - what changed on this machine, and when.

The other tools in this repo diagnose a subsystem or audit current state.
Nothing answers the temporal question, which is the one you actually have at
11pm when something that worked yesterday does not.

Every Linux box has a reconstructable history that nobody reconstructs, because
the pieces live in four places and none of them correlate:

  * the package manager log: every install, upgrade and removal, timestamped
  * the journal: boot boundaries, unit failures
  * /etc mtimes: configuration edited, and when
  * kernel version across boots

Individually each is readable and nearly useless. Merged into one timeline they
answer the question directly.

    chronicle                        # last 7 days
    chronicle --since "3 days ago"
    chronicle --boot -1              # scope to the previous boot
    chronicle --before-boot          # the window preceding the last failed boot
    chronicle --json

Read-only. There is no --apply and no write path. Where an action is implied
the command is printed and never run.

ADJACENCY IS NOT CAUSATION. A package upgrade an hour before a failure is
temporally adjacent, and that is all this tool knows. It orders and labels
events; drawing the line between them is your job. There is deliberately no
"likely cause" field, no ranking of suspects, and no severity attached to
correlation.

No third-party dependencies.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- test seams

SYSROOT = Path("/")
PLATFORM = None  # tests set "linux"
IS_ROOT = None  # tests set a bool
NOW = None  # tests set an aware datetime, so relative windows are deterministic
USER = None  # tests set a username, for journal group membership


def sysp(path):
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


def now():
    if NOW is not None:
        return NOW
    return datetime.now(timezone.utc).astimezone()


def current_user():
    if USER is not None:
        return USER
    return os.environ.get("USER") or os.environ.get("LOGNAME") or ""


def run(cmd, timeout=60):
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

PACMAN_LOG = "/var/log/pacman.log"
PACMAN_CACHE = "/var/cache/pacman/pkg"
OS_RELEASE = "/etc/os-release"
ETC = "/etc"
GROUP_FILE = "/etc/group"

# Groups whose members can read the whole journal. Which one applies varies by
# distro, so all three are accepted.
JOURNAL_GROUPS = ("systemd-journal", "adm", "wheel")

DEFAULT_WINDOW_DAYS = 7

# How far outside a package transaction an /etc mtime can fall and still be
# attributed to it. Package scripts run after the last log line, so a small
# tail is expected; anything beyond this is treated as an independent edit.
TRANSACTION_ETC_SLACK_S = 120

# Walking /etc is cheap but not free, and a pathological tree should not hang
# the run. Beyond this many entries the walk stops and says it truncated.
ETC_WALK_LIMIT = 20000

STATUS_ORDER = ["fail", "warn", "unknown", "info", "skipped", "ok"]
EXIT_STATUSES = {"fail", "warn"}

NOTHING_FOUND = 0
FOUND_SOMETHING = 1
COULD_NOT_DETERMINE = 2


class WindowError(ValueError):
    """A --since/--until value that could not be understood."""


def make(check_id, status, summary, detail=None, fix=None, result_id=None):
    return {
        "id": result_id or check_id,
        "check": check_id,
        "status": status,
        "summary": summary,
        "detail": list(detail or []),
        "fix": fix,
    }


# ------------------------------------------------------------ time handling


def local_tz():
    return now().tzinfo or timezone.utc


def from_epoch(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone(local_tz())


RELATIVE = re.compile(
    r"^\s*(\d+)\s+(second|minute|hour|day|week|month)s?\s+ago\s*$", re.I
)

UNIT_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
    "month": 2592000,  # 30 days; documented as approximate
}

ACCEPTED_WINDOW_FORMS = (
    "an ISO date (2026-08-01) or datetime (2026-08-01T15:30 or "
    "'2026-08-01 15:30'), 'now', 'today', 'yesterday', or a relative form "
    "like '3 days ago', '2 weeks ago', '6 hours ago'"
)


def parse_when(text, reference=None):
    """Parse a --since/--until value into an aware datetime.

    Hand-rolled on purpose: reaching for a dependency to read '3 days ago'
    would break the stdlib-only rule for one of the smallest problems here.
    Anything unrecognised raises rather than quietly defaulting to a window the
    user did not ask for."""
    if text is None:
        raise WindowError("no value given")
    reference = reference or now()
    value = text.strip()
    if not value:
        raise WindowError("empty value")

    lowered = value.lower()
    if lowered == "now":
        return reference
    if lowered == "today":
        return reference.replace(hour=0, minute=0, second=0, microsecond=0)
    if lowered == "yesterday":
        midnight = reference.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight - timedelta(days=1)

    match = RELATIVE.match(value)
    if match:
        count = int(match.group(1))
        unit = match.group(2).lower()
        return reference - timedelta(seconds=count * UNIT_SECONDS[unit])

    normalised = value.replace(" ", "T", 1) if " " in value else value
    for candidate in (normalised, value):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=local_tz())
        return parsed

    raise WindowError(f"could not understand {text!r}")


# --------------------------------------------------- package source: pacman
#
# The package reader is deliberately behind a one-function interface,
# iter_package_events(path) -> (events, skipped), so dpkg and dnf can be added
# later without restructuring anything above it. v0.1 is pacman only, and a
# system it cannot read says so rather than producing an empty timeline: an
# unsupported source and a quiet one must not look the same.

# Current pacman: [2026-08-15T15:00:12+0100] [ALPM] upgraded linux (6.11.4-1 -> 6.11.5-1)
# Older pacman:   [2015-09-16 15:47] [PACMAN] Running 'pacman -Syu'
PACMAN_LINE = re.compile(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$")
PACMAN_ACTION = re.compile(
    r"^(installed|upgraded|removed|downgraded|reinstalled)\s+(\S+)\s+\((.+)\)\s*$"
)
VERSION_ARROW = re.compile(r"^(.*?)\s*->\s*(.*)$")


def parse_pacman_timestamp(text):
    """Both timestamp formats pacman has used. Returns an aware datetime."""
    value = text.strip()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        # The old format carries no offset. Local time is the only reasonable
        # reading, and it is what pacman meant when it wrote it.
        parsed = parsed.replace(tzinfo=local_tz())
    return parsed


def iter_package_events(path):
    """Read a pacman log into transactions and standalone package events.

    Returns (events, skipped). Grouping is by the transaction delimiters pacman
    writes, not by timestamp proximity: that is what turns 47 individual log
    lines into one '47 packages upgraded' event, and it is exact rather than
    heuristic."""
    events = []
    skipped = 0
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return events, skipped

    open_transaction = None

    def close(transaction, end_time):
        if transaction is None:
            return
        if not transaction["packages"]:
            return
        counts = {}
        for package in transaction["packages"]:
            counts[package["action"]] = counts.get(package["action"], 0) + 1
        transaction["counts"] = counts
        transaction["end_epoch"] = end_time
        transaction["summary"] = summarise_transaction(transaction)
        events.append(transaction)

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        match = PACMAN_LINE.match(line)
        if not match:
            skipped += 1
            continue
        stamp = parse_pacman_timestamp(match.group(1))
        if stamp is None:
            skipped += 1
            continue
        caller = match.group(2).strip()
        body = match.group(3).strip()
        epoch = stamp.timestamp()

        if body == "transaction started":
            close(open_transaction, epoch)
            open_transaction = {
                "source": "pacman",
                "type": "transaction",
                "epoch": epoch,
                "timestamp": stamp.isoformat(),
                "caller": caller,
                "packages": [],
                "counts": {},
                "end_epoch": epoch,
                "summary": "",
            }
            continue
        if body == "transaction completed":
            close(open_transaction, epoch)
            open_transaction = None
            continue

        action = PACMAN_ACTION.match(body)
        if action:
            verb, name, versions = action.group(1), action.group(2), action.group(3)
            arrow = VERSION_ARROW.match(versions)
            entry = {
                "action": verb,
                "name": name,
                "old_version": arrow.group(1).strip() if arrow else None,
                "new_version": (arrow.group(2) if arrow else versions).strip(),
                "epoch": epoch,
            }
            if open_transaction is not None:
                open_transaction["packages"].append(entry)
            else:
                events.append(
                    {
                        "source": "pacman",
                        "type": "package",
                        "epoch": epoch,
                        "timestamp": stamp.isoformat(),
                        "caller": caller,
                        "packages": [entry],
                        "counts": {verb: 1},
                        "end_epoch": epoch,
                        "summary": describe_package(entry),
                    }
                )
            continue

        # Everything else is real log content that is simply not a package
        # change: pacman's own "Running ..." lines, warnings, and the arbitrary
        # output of package install scripts. Recognised and ignored rather than
        # counted as malformed, so the skipped count stays meaningful as a
        # measure of lines this reader genuinely does not understand.
        if caller.upper().startswith("ALPM-SCRIPTLET"):
            continue
        if body.lower().startswith(("running ", "warning:", "error:", "note:", "==>")):
            continue
        skipped += 1

    close(open_transaction, open_transaction["end_epoch"] if open_transaction else 0)
    return events, skipped


def describe_package(entry):
    if entry["action"] == "upgraded" and entry["old_version"]:
        return f"{entry['name']} {entry['old_version']} -> {entry['new_version']}"
    if entry["action"] == "downgraded" and entry["old_version"]:
        return f"{entry['name']} downgraded {entry['old_version']} -> {entry['new_version']}"
    return f"{entry['name']} {entry['new_version']} ({entry['action']})"


def describe_package_short(entry):
    """Name and versions without the verb, for use where the surrounding text
    has already said what happened."""
    if entry["old_version"]:
        return f"{entry['name']} {entry['old_version']} -> {entry['new_version']}"
    return f"{entry['name']} {entry['new_version']}"


def summarise_transaction(transaction):
    parts = []
    for verb in ("upgraded", "installed", "removed", "downgraded", "reinstalled"):
        count = transaction["counts"].get(verb, 0)
        if count:
            parts.append(f"{count} package{'s' if count != 1 else ''} {verb}")
    head = ", ".join(parts) if parts else "transaction"
    packages = transaction["packages"]

    # A small transaction is named in full: "1 package installed" tells you
    # nothing you could act on.
    if len(packages) <= 3:
        return head + " (" + ", ".join(describe_package_short(p) for p in packages) + ")"

    # A large one names a few widely recognised packages so the line is
    # scannable. This is emphatically not a ranking of what mattered: it is a
    # fixed list of names, and the tool has no opinion about which package in a
    # transaction is relevant to your problem.
    notable = [
        describe_package(p)
        for p in packages
        if p["name"] in ("linux", "linux-lts", "linux-zen", "systemd", "mkinitcpio", "glibc", "grub", "nvidia")
    ]
    if notable:
        head += " (" + ", ".join(notable[:3]) + ")"
    return head


PACKAGE_READERS = {"pacman": (PACMAN_LOG, iter_package_events)}


def detect_package_source():
    """Which package reader applies here, if any.

    Returns (name, path, reader) or (None, None, None). Detection is by distro
    ID and ID_LIKE, then by the log actually existing."""
    values = {}
    try:
        for line in sysp(OS_RELEASE).read_text(errors="replace").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip("\"'")
    except OSError:
        pass

    names = [values.get("ID", "")] + (values.get("ID_LIKE", "") or "").split()
    names = [n.lower() for n in names if n]
    if any(n in ("arch", "archarm", "manjaro", "endeavouros", "cachyos", "garuda") for n in names):
        path, reader = PACKAGE_READERS["pacman"]
        return "pacman", path, reader
    return None, None, None


# ------------------------------------------------------------------ journal


def journal_access():
    """How much of the journal this run can actually see.

    Non-root users see only their own messages unless they are in one of the
    journal groups, and journalctl does not error in that case, it just returns
    less. Silently presenting a truncated journal as a complete one is the
    failure this exists to prevent."""
    if is_root():
        return "root"
    user = current_user()
    if not user:
        return "unknown"
    try:
        text = sysp(GROUP_FILE).read_text(errors="replace")
    except OSError:
        return "unknown"
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) < 4:
            continue
        if fields[0] in JOURNAL_GROUPS:
            members = [m for m in fields[3].split(",") if m]
            if user in members:
                return "member"
    return "limited"


# journalctl's text table separates the two timestamps with U+2014. Written as
# an escape rather than the character itself, both to keep the literal out of
# this source and because a character class containing a plain hyphen would
# match the hyphens inside the date and truncate the timestamp.
BOOT_TEXT_LINE = re.compile(
    r"^\s*(-?\d+)\s+([0-9a-f]{32})\s+(.*?)(?:\s*\u2014\s*|\s+-\s+)(.*)$"
)
KERNEL_BANNER = re.compile(r"Linux version (\S+)")


def read_boots():
    """Boot list from journalctl. Returns (boots, reason).

    Tries JSON first and falls back to the text table, which is all older
    systemd offers."""
    rc, output, reason = run(["journalctl", "--list-boots", "--output=json"])
    if rc == 0 and output.strip():
        try:
            raw = json.loads(output)
        except ValueError:
            raw = None
        if isinstance(raw, list):
            boots = []
            for entry in raw:
                try:
                    boots.append(
                        {
                            "index": int(entry.get("index", 0)),
                            "boot_id": entry.get("boot_id", ""),
                            "first_epoch": float(entry["first_entry"]) / 1_000_000.0,
                            "last_epoch": float(entry["last_entry"]) / 1_000_000.0,
                        }
                    )
                except (KeyError, TypeError, ValueError):
                    continue
            if boots:
                return sorted(boots, key=lambda b: b["first_epoch"]), None

    rc, output, text_reason = run(["journalctl", "--list-boots"])
    if rc != 0:
        return [], reason or text_reason or "journalctl --list-boots failed"

    boots = []
    for line in output.splitlines():
        match = BOOT_TEXT_LINE.match(line)
        if not match:
            continue
        first = parse_when_loose(match.group(3))
        last = parse_when_loose(match.group(4))
        if first is None:
            continue
        boots.append(
            {
                "index": int(match.group(1)),
                "boot_id": match.group(2),
                "first_epoch": first.timestamp(),
                "last_epoch": (last or first).timestamp(),
            }
        )
    if not boots:
        return [], "could not parse any boots from journalctl --list-boots"
    return sorted(boots, key=lambda b: b["first_epoch"]), None


def parse_when_loose(text):
    """Best-effort datetime from journalctl's human table, which carries a
    weekday and a timezone name neither of which fromisoformat accepts."""
    cleaned = re.sub(r"^[A-Za-z]{3}\s+", "", text.strip())
    cleaned = re.sub(r"\s+[A-Z]{2,5}$", "", cleaned)
    try:
        parsed = datetime.fromisoformat(cleaned.replace(" ", "T", 1))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=local_tz())
    return parsed


UNIT_FAILURE = re.compile(
    r"(Failed to start|entered failed state|Failed with result|Start request repeated)",
    re.I,
)
CLEAN_SHUTDOWN = re.compile(
    r"(Reached target .*(Shutdown|Power-Off|Reboot)|Shutting down|System is powering down)",
    re.I,
)


def read_journal(window):
    """Journal records in the window. Returns (records, reason).

    journalctl --output=json is a documented, stable interface, one JSON object
    per line, so unlike the pacman log this is not the fragile part."""
    since = datetime.fromtimestamp(window[0], tz=timezone.utc).astimezone(local_tz())
    until = datetime.fromtimestamp(window[1], tz=timezone.utc).astimezone(local_tz())
    rc, output, reason = run(
        [
            "journalctl",
            "--output=json",
            "--since",
            since.strftime("%Y-%m-%d %H:%M:%S"),
            "--until",
            until.strftime("%Y-%m-%d %H:%M:%S"),
        ]
    )
    if rc != 0:
        return [], reason or "journalctl failed"

    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        records.append(record)
    return records, None


def journal_events(records):
    """Extract the things worth putting on a timeline.

    _BOOT_ID is the join key: it is what ties a unit failure to the boot it
    happened in."""
    failures = []
    kernels = {}
    shutdowns = set()

    for record in records:
        message = record.get("MESSAGE") or ""
        if not isinstance(message, str):
            continue
        boot_id = record.get("_BOOT_ID", "")
        try:
            epoch = float(record.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000.0
        except (TypeError, ValueError):
            continue

        banner = KERNEL_BANNER.search(message)
        if banner and boot_id:
            kernels.setdefault(boot_id, banner.group(1))

        if CLEAN_SHUTDOWN.search(message) and boot_id:
            shutdowns.add(boot_id)

        if UNIT_FAILURE.search(message):
            unit = record.get("UNIT") or record.get("_SYSTEMD_UNIT") or ""
            failures.append(
                {
                    "source": "journal",
                    "type": "unit-failure",
                    "epoch": epoch,
                    "timestamp": from_epoch(epoch).isoformat(),
                    "unit": unit,
                    "boot_id": boot_id,
                    "message": message.strip(),
                }
            )
    return failures, kernels, shutdowns


# --------------------------------------------------------------- /etc walk


def walk_etc(window, transactions):
    """Config files whose mtime falls in the window.

    Metadata only: this never reads a file's contents.

    Most /etc changes during an upgrade are the upgrade rewriting config files,
    not a human editing them, so anything landing inside a transaction window
    is labelled as package-originated rather than listed as an independent
    event. .pacnew and .pacsave get their own callout: they are the highest
    signal thing in /etc, because they mean a config you had customised was
    superseded and the merge is still owed."""
    start, end = window
    spans = [
        (t["epoch"] - 1, t["end_epoch"] + TRANSACTION_ETC_SLACK_S)
        for t in transactions
        if t["type"] == "transaction"
    ]

    events = []
    seen = 0
    truncated = False
    root = sysp(ETC)
    if not root.is_dir():
        return events, False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            seen += 1
            if seen > ETC_WALK_LIMIT:
                truncated = True
                break
            full = Path(dirpath) / name
            try:
                if full.is_symlink():
                    continue
                mtime = full.stat().st_mtime
            except OSError:
                continue
            if not (start <= mtime <= end):
                continue

            relative = "/" + str(full.relative_to(SYSROOT)).replace("\\", "/")
            package_originated = any(low <= mtime <= high for low, high in spans)
            is_pacnew = name.endswith((".pacnew", ".pacsave"))
            events.append(
                {
                    "source": "etc",
                    "type": "pacnew" if is_pacnew else "config-change",
                    "epoch": mtime,
                    "timestamp": from_epoch(mtime).isoformat(),
                    "path": relative,
                    "package_originated": package_originated and not is_pacnew,
                }
            )
        if truncated:
            break
    return events, truncated


# ------------------------------------------------------------ rollback hints


CACHE_SUFFIXES = (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar")


def rollback_hints(transactions):
    """Where the previous version of each changed package lives, if anywhere.

    The cache file is checked for existence before it is named: paccache may
    have cleared it, and pointing someone at a file that is not there is worse
    than telling them it is gone."""
    hints = []
    cache = sysp(PACMAN_CACHE)
    for transaction in transactions:
        for package in transaction["packages"]:
            if package["action"] not in ("upgraded", "downgraded"):
                continue
            if not package["old_version"]:
                continue
            found = None
            if cache.is_dir():
                for suffix in CACHE_SUFFIXES:
                    for arch in ("x86_64", "any", "aarch64"):
                        candidate = cache / f"{package['name']}-{package['old_version']}-{arch}{suffix}"
                        if candidate.exists():
                            found = "/" + str(candidate.relative_to(SYSROOT)).replace("\\", "/")
                            break
                    if found:
                        break
            hints.append(
                {
                    "name": package["name"],
                    "from_version": package["old_version"],
                    "to_version": package["new_version"],
                    "cache_file": found,
                    "available": found is not None,
                }
            )
    return hints


# ------------------------------------------------------------------ windows


def resolve_window(args, boots):
    """Work out the (start, end) epoch pair, or raise WindowError."""
    reference = now()

    if args.boot is not None:
        if not boots:
            raise WindowError("no boot list available, so --boot cannot be resolved")
        match = [b for b in boots if b["index"] == args.boot]
        if not match:
            known = ", ".join(str(b["index"]) for b in boots)
            raise WindowError(f"no boot with index {args.boot} (known: {known})")
        boot = match[0]
        return boot["first_epoch"], boot["last_epoch"], f"boot {args.boot}"

    start = reference - timedelta(days=DEFAULT_WINDOW_DAYS)
    end = reference
    label = f"last {DEFAULT_WINDOW_DAYS} days"
    if args.since:
        start = parse_when(args.since, reference)
        label = f"since {start.isoformat()}"
    if args.until:
        end = parse_when(args.until, reference)
        label += f" until {end.isoformat()}"
    if end < start:
        raise WindowError("--until is before --since")
    return start.timestamp(), end.timestamp(), label


def find_last_failed_boot(boots, failures, shutdowns):
    """The most recent boot that either had a unit failure, or was preceded by
    one that never recorded a clean shutdown.

    Stated plainly because it is a definition rather than a detection: this is
    what the tool means by "failed boot", and it is not a claim about why."""
    failed_ids = {f["boot_id"] for f in failures if f["boot_id"]}
    candidates = []
    for index, boot in enumerate(boots):
        reasons = []
        if boot["boot_id"] in failed_ids:
            reasons.append("units failed during this boot")
        if index > 0:
            previous = boots[index - 1]
            if previous["boot_id"] and previous["boot_id"] not in shutdowns:
                reasons.append("the preceding boot recorded no clean shutdown")
        if reasons:
            candidates.append((boot, reasons))
    return candidates[-1] if candidates else (None, [])


# ------------------------------------------------------------------ gather


def build_report(args):
    report = {
        "tool": "chronicle",
        "linux": is_linux(),
        "root": is_root(),
        "window": None,
        "events": [],
        "results": [],
        "sources": {},
        "boots": [],
        "rollback_hints": [],
        "counts": {status: 0 for status in STATUS_ORDER},
        "error": None,
        "exit_code": NOTHING_FOUND,
    }

    def finish():
        report["events"].sort(key=lambda e: e["epoch"])
        for res in report["results"]:
            report["counts"][res["status"]] = report["counts"].get(res["status"], 0) + 1
        if report["error"]:
            report["exit_code"] = COULD_NOT_DETERMINE
        elif any(res["status"] in EXIT_STATUSES for res in report["results"]):
            # Finding something worth attention is a positive result even from
            # an incomplete timeline, so it outranks a degraded source.
            report["exit_code"] = FOUND_SOMETHING
        elif any(
            source.get("status") in ("unknown", "skipped")
            for source in report["sources"].values()
        ):
            # Nothing found, but not everything could be looked at. Exiting 0
            # would claim a clean window that was never fully examined.
            report["exit_code"] = COULD_NOT_DETERMINE
        return report

    if not report["linux"]:
        report["error"] = "not-linux"
        report["results"].append(
            make("platform", "unknown", "This tool only works on Linux")
        )
        return finish()

    # --- journal first: the boot list is what --boot and --before-boot need
    systemd_present = run(["systemctl", "--version"])[0] == 0
    access = journal_access()
    boots, boot_reason = ([], "systemd not present")
    if systemd_present:
        boots, boot_reason = read_boots()
    report["boots"] = boots

    try:
        start, end, label = resolve_window(args, boots)
    except WindowError as exc:
        report["error"] = "bad-window"
        report["results"].append(
            make(
                "window",
                "unknown",
                f"Could not resolve the time window: {exc}",
                detail=[f"Accepted forms: {ACCEPTED_WINDOW_FORMS}."],
            )
        )
        return finish()

    window = (start, end)
    report["window"] = {
        "start": from_epoch(start).isoformat(),
        "end": from_epoch(end).isoformat(),
        "label": label,
    }

    # --- packages
    name, path, reader = detect_package_source()
    if name is None:
        report["sources"]["packages"] = {
            "status": "skipped",
            "name": None,
            "detail": "No supported package manager log on this system. v0.1 reads "
            "pacman only; dpkg and dnf are not supported, so the package timeline "
            "is unavailable rather than empty.",
        }
        transactions = []
    elif not sysp(path).exists():
        report["sources"]["packages"] = {
            "status": "unknown",
            "name": name,
            "detail": f"{path} does not exist, so no package history could be read.",
        }
        transactions = []
    else:
        all_events, skipped = reader(sysp(path))
        transactions = [
            e for e in all_events if start <= e["epoch"] <= end
        ]
        report["sources"]["packages"] = {
            "status": "ok",
            "name": name,
            "detail": f"{len(all_events)} transaction(s) in {path}, "
            f"{len(transactions)} in window",
            "skipped_lines": skipped,
        }
        if skipped:
            report["results"].append(
                make(
                    "packages",
                    "info",
                    f"{skipped} unrecognised line(s) in {path} were skipped",
                    detail=["Old log formats and third-party tooling both write lines",
                            "this reader does not model. They are counted, not fatal."],
                )
            )
        report["events"].extend(transactions)

    # --- journal
    failures, kernels, shutdowns = [], {}, set()
    if not systemd_present:
        report["sources"]["journal"] = {
            "status": "skipped",
            "detail": "systemd is not present, so there is no journal to read. The "
            "package timeline above is unaffected.",
        }
    else:
        records, reason = read_journal(window)
        if reason:
            report["sources"]["journal"] = {
                "status": "unknown",
                "detail": f"journalctl could not be read: {reason}",
            }
        else:
            failures, kernels, shutdowns = journal_events(records)
            partial = access == "limited"
            report["sources"]["journal"] = {
                "status": "unknown" if partial else "ok",
                "access": access,
                "detail": (
                    "Only your own messages are visible: this run is unprivileged "
                    "and the user is not in a journal group, so the timeline below "
                    "is PARTIAL, not complete."
                    if partial
                    else f"{len(records)} record(s) read"
                ),
                "records": len(records),
            }
            if partial:
                report["results"].append(
                    make(
                        "journal",
                        "unknown",
                        "Journal access is restricted; this timeline is partial",
                        detail=[
                            "Without membership of a journal group an unprivileged",
                            "user sees only their own messages, and journalctl does",
                            "not say so. System unit failures and boot records are",
                            "missing from the timeline below.",
                        ],
                        fix=f'sudo usermod -aG systemd-journal "{current_user() or "$USER"}"   # then log back in',
                    )
                )

        for boot in boots:
            if start <= boot["first_epoch"] <= end:
                report["events"].append(
                    {
                        "source": "journal",
                        "type": "boot",
                        "epoch": boot["first_epoch"],
                        "timestamp": from_epoch(boot["first_epoch"]).isoformat(),
                        "boot_id": boot["boot_id"],
                        "index": boot["index"],
                        "kernel": kernels.get(boot["boot_id"]),
                    }
                )

        in_window = [f for f in failures if start <= f["epoch"] <= end]
        report["events"].extend(in_window)
        if in_window:
            units = sorted({f["unit"] or "(unnamed unit)" for f in in_window})
            report["results"].append(
                make(
                    "units",
                    "warn",
                    f"{len(in_window)} unit failure(s) in this window",
                    detail=[f"    {unit}" for unit in units]
                    + [
                        "",
                        "Listed in time order below alongside everything else that",
                        "happened. What preceded a failure is adjacent to it and",
                        "nothing more; this tool does not assign cause.",
                    ],
                    fix=f"systemctl status {units[0]}" if units else None,
                )
            )

    # --- before-boot
    if args.before_boot:
        boot, reasons = find_last_failed_boot(boots, failures, shutdowns)
        if boot is None:
            report["error"] = "no-failed-boot"
            report["results"].append(
                make(
                    "before-boot",
                    "unknown",
                    "No failed boot found, so there is no window preceding one",
                    detail=[
                        "A boot counts as failed when a unit failed during it, or",
                        "when the boot before it recorded no clean shutdown.",
                        "Neither was seen, so nothing was determined. The default",
                        "window is deliberately NOT substituted here.",
                    ],
                )
            )
            return finish()
        report["window"] = {
            "start": from_epoch(start).isoformat(),
            "end": from_epoch(boot["first_epoch"]).isoformat(),
            "label": f"before failed boot {boot['index']}",
            "failed_boot": {
                "index": boot["index"],
                "boot_id": boot["boot_id"],
                "reasons": reasons,
            },
        }
        end = boot["first_epoch"]
        window = (start, end)
        report["events"] = [e for e in report["events"] if e["epoch"] <= end]
        transactions = [t for t in transactions if t["epoch"] <= end]

        # The failures happened AT the boot that now bounds the window, so they
        # are no longer inside it. Reporting them as events in the window would
        # contradict the timeline below. They are restated as what defines the
        # window instead, which is also what keeps this a finding.
        report["results"] = [r for r in report["results"] if r["check"] != "units"]
        boot_failures = sorted(
            {f["unit"] or "(unnamed unit)" for f in failures if f["boot_id"] == boot["boot_id"]}
        )
        report["results"].append(
            make(
                "before-boot",
                "warn",
                f"Boot {boot['index']} failed; showing everything before it",
                detail=[f"    {reason}" for reason in reasons]
                + ([""] + [f"    {unit}" for unit in boot_failures] if boot_failures else [])
                + [
                    "",
                    "The timeline below ends where that boot begins. What is in it",
                    "preceded the failure and is adjacent to it; that is the whole",
                    "of what this tool knows.",
                ],
                result_id="before-boot-window",
            )
        )

    # --- /etc
    etc_events, truncated = walk_etc(window, transactions)
    report["events"].extend(etc_events)
    report["sources"]["etc"] = {
        "status": "ok",
        "detail": f"{len(etc_events)} file(s) modified in window",
        "truncated": truncated,
    }
    pacnew = [e for e in etc_events if e["type"] == "pacnew"]
    if pacnew:
        report["results"].append(
            make(
                "pacnew",
                "warn",
                f"{len(pacnew)} .pacnew/.pacsave file(s) awaiting a merge",
                detail=[f"    {e['path']}" for e in pacnew]
                + [
                    "",
                    "A config you had customised was superseded by a package. The",
                    "old and new versions are both on disk and the merge is owed.",
                ],
                fix="pacdiff",
            )
        )

    if args.rollback_hint:
        report["rollback_hints"] = rollback_hints(transactions)

    return finish()


# ---------------------------------------------------------------- rendering

WRAP_WIDTH = 72


def safe_text(text):
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
            if line.startswith(" ") or "  " in line:
                emit(f"         {self._c('90', line)}")
                continue
            for wrapped in wrap(line):
                emit(f"         {self._c('90', wrapped)}")
        if res["fix"]:
            emit(f"         {self._c('1', 'fix:')} {res['fix']}")


EVENT_MARKS = {
    "transaction": "pkg ",
    "package": "pkg ",
    "boot": "BOOT",
    "unit-failure": "FAIL",
    "config-change": "etc ",
    "pacnew": "etc!",
}


def render_timeline(out, report, verbose):
    out.header("Timeline")
    window = report["window"] or {}
    emit(f"  window: {window.get('label', 'unknown')}")
    if window.get("failed_boot"):
        failed = window["failed_boot"]
        emit(f"  scoped to everything before boot {failed['index']} ({failed['boot_id'][:12]})")
        for reason in failed["reasons"]:
            emit(f"    counted as failed because: {reason}")
    emit()

    if not report["events"]:
        emit("  Nothing recorded in this window.")
        return

    current_day = None
    for event in report["events"]:
        stamp = from_epoch(event["epoch"])
        day = stamp.strftime("%a %Y-%m-%d")
        if day != current_day:
            current_day = day
            emit()
            emit(f"  {out._c('1', day)}")

        clock = stamp.strftime("%H:%M")
        mark = EVENT_MARKS.get(event["type"], "    ")

        if event["type"] == "boot":
            kernel = f" (kernel {event['kernel']})" if event.get("kernel") else ""
            emit(f"  {out._c('36', rule_char() * 66)}")
            emit(f"  {clock}  {out._c('1;36', mark)}  boot {event['index']}{kernel}")
            continue

        if event["type"] == "unit-failure":
            unit = event["unit"] or "(unnamed unit)"
            emit(f"  {clock}  {out._c('31', mark)}  {unit}")
            for line in wrap(event["message"], 56):
                emit(f"              {out._c('90', line)}")
            continue

        if event["type"] in ("transaction", "package"):
            emit(f"  {clock}  {out._c('33', mark)}  {event['summary']}")
            if verbose:
                for package in event["packages"]:
                    emit(f"              {out._c('90', describe_package(package))}")
            continue

        note = "  (rewritten by the package transaction)" if event.get("package_originated") else ""
        colour = "35" if event["type"] == "pacnew" else "90"
        emit(f"  {clock}  {out._c(colour, mark)}  {event['path']}{out._c('90', note)}")


def render_sources(out, report):
    out.header("Sources")
    for name, source in report["sources"].items():
        code, tag = Out.TAGS.get(source.get("status", "info"), ("0", "[    ]"))
        emit(f"  {out._c(code, tag)} {name}: {source.get('detail', '')}")


def render_rollback(out, report):
    if not report["rollback_hints"]:
        return
    out.header("Rollback candidates")
    available = [h for h in report["rollback_hints"] if h["available"]]
    missing = [h for h in report["rollback_hints"] if not h["available"]]

    for hint in available:
        emit(f"  {hint['name']}  {hint['from_version']} -> {hint['to_version']}")
        emit(f"      {out._c('90', hint['cache_file'])}")
    if missing:
        emit()
        emit(f"  {len(missing)} package(s) have no cached previous version:")
        for hint in missing[:10]:
            emit(f"      {out._c('90', hint['name'] + ' ' + hint['from_version'])}")
        emit(f"      {out._c('90', 'paccache has cleared them, so they cannot be rolled back from disk.')}")

    if available:
        emit()
        emit("  To roll back, run this yourself. chronicle never will:")
        emit(f"      sudo pacman -U {' '.join(h['cache_file'] for h in available[:6])}")
        if len(available) > 6:
            emit(f"      ... and {len(available) - 6} more")


def render(out, report):
    if report["results"]:
        by_status = {}
        for res in report["results"]:
            by_status.setdefault(res["status"], []).append(res)
        titles = {
            "fail": "Failures",
            "warn": "Worth attention",
            "unknown": "Could not determine",
            "info": "Informational",
            "skipped": "Not applicable",
            "ok": "Fine",
        }
        for status in STATUS_ORDER:
            group = by_status.get(status)
            if not group:
                continue
            out.header(titles[status])
            for res in group:
                out.finding(res)

    if report["error"]:
        emit()
        return

    render_sources(out, report)
    render_timeline(out, report, report.get("_verbose", False))
    render_rollback(out, report)

    out.header("Reading this")
    emit("  Events are ordered and labelled. That is the whole contract.")
    emit()
    for line in wrap(
        "A package upgrade an hour before a failure is temporally adjacent, and "
        "adjacency is all this tool knows. It does not rank suspects, assign "
        "cause, or attach severity to correlation, because the moment it started "
        "guessing you could no longer trust the parts it is certain about."
    ):
        emit(f"  {line}")


# --------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="Merge package, journal and /etc history into one timeline.",
        epilog=(
            "Read-only: there is no --apply and no write path.\n\n"
            "Adjacency is not causation. This tool orders and labels events; it "
            "never claims one caused another.\n\n"
            "Exit codes: 0 nothing found, 1 something worth attention, 2 no "
            "verdict reached."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--since", help="window start: ISO date or e.g. '3 days ago'")
    parser.add_argument("--until", help="window end, same forms as --since")
    parser.add_argument("--boot", type=int, help="scope to a boot index, e.g. -1")
    parser.add_argument(
        "--before-boot",
        action="store_true",
        help="show the window preceding the most recent failed boot",
    )
    parser.add_argument(
        "--rollback-hint",
        action="store_true",
        help="list cached previous package versions and print the pacman -U command",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="expand transactions to individual packages"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    args = parser.parse_args()

    report = build_report(args)
    report["_verbose"] = args.verbose

    if args.json:
        payload = {k: v for k, v in report.items() if not k.startswith("_")}
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return report["exit_code"]

    render(Out(color=not args.no_color), report)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
