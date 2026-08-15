#!/usr/bin/env python3
"""
portwatch.py - snapshot listening sockets, diff against a baseline.

`ss -tlnp` tells you what is listening right now. Nothing tells you what
changed since last week. "Port 8080 appeared on Tuesday, owned by a process
that was not here before" is a question you have on any machine you did not
personally set up, and there is no good answer for it.

    portwatch                     # what is listening now
    portwatch --save              # write a baseline snapshot
    portwatch --diff              # compare now against the latest baseline
    portwatch --diff FILE         # against a specific snapshot
    portwatch --list              # stored snapshots
    portwatch --json

Read-only with respect to system state. It writes snapshot files and nothing
else: it never kills a process, closes a socket, or touches a firewall. Where
an action is implied the command is printed and never run.

Reads /proc/net/{tcp,tcp6,udp,udp6,unix} directly rather than shelling out to
`ss`, whose output is a formatting target rather than an API: its columns move
between iproute2 versions and it truncates process names.

NO RISK SCORING. This tool reports what changed and does not rank it. It has no
idea what your machine is for, so a "suspicious" label from it would be
confident output that is wrong in a direction you cannot check. Observations
are reported as observations; the judgement is yours.

Pairs with chronicle, which answers the same question on a different axis: what
changed on this machine, and when.

No third-party dependencies.
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- test seams

SYSROOT = Path("/")
PLATFORM = None  # tests set "linux"
IS_ROOT = None  # tests set a bool
NOW = None  # tests set an aware datetime
STATE_DIR = None  # tests point this at a tempdir


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


def state_dir():
    """Where snapshots live.

    XDG_STATE_HOME, not XDG_CONFIG_HOME: these are captured machine state that
    the tool produced, not configuration a human wrote, and the spec is
    explicit about the difference."""
    if STATE_DIR is not None:
        return Path(STATE_DIR)
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "portwatch"
    return Path(os.path.expanduser("~")) / ".local" / "state" / "portwatch"


# ----------------------------------------------------------------- constants

PROC_NET = "/proc/net"
PROC = "/proc"
PORT_RANGE_FILE = "/proc/sys/net/ipv4/ip_local_port_range"

# TCP socket states, from include/net/tcp_states.h. 0A is TCP_LISTEN, and it is
# the only one that means "a service is waiting here".
TCP_LISTEN_STATE = "0A"

# Used only when ip_local_port_range cannot be read. The real range is read at
# runtime because distros and sysctl tuning both move it.
EPHEMERAL_FALLBACK = (32768, 60999)

# Bumped when the snapshot layout changes in a way older readers cannot handle.
# A snapshot carrying anything else is refused rather than parsed optimistically.
SCHEMA_VERSION = 1

STATUS_ORDER = ["fail", "warn", "unknown", "info", "skipped", "ok"]
EXIT_STATUSES = {"fail", "warn"}

NO_CHANGES = 0
CHANGES_FOUND = 1
COULD_NOT_DETERMINE = 2

CHANGE_CLASSES = ("appeared", "disappeared", "rebound", "owner-changed", "restarted")

SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")

LOOPBACK_V4 = "127."
WILDCARD_ADDRESSES = {"0.0.0.0", "::"}

CONTAINER_HINTS = ("docker", "podman", "containerd", "lxc", "machine.slice", "kubepods")


def make(check_id, status, summary, detail=None, fix=None, result_id=None):
    return {
        "id": result_id or check_id,
        "check": check_id,
        "status": status,
        "summary": summary,
        "detail": list(detail or []),
        "fix": fix,
    }


# ------------------------------------------------------------ address decode


def decode_v4(hex_address):
    """One 32-bit word, printed little-endian.

    0100007F is 127.0.0.1. Reading it big-endian yields 1.0.0.127, which is a
    perfectly plausible address and completely wrong, so this is the single
    easiest thing in the tool to get silently backwards."""
    return socket.inet_ntoa(struct.pack("<I", int(hex_address, 16)))


def decode_v6(hex_address):
    """Four 32-bit words, each printed little-endian, reassembled in order."""
    raw = b"".join(
        struct.pack("<I", int(hex_address[index:index + 8], 16))
        for index in range(0, 32, 8)
    )
    return socket.inet_ntop(socket.AF_INET6, raw)


def decode_address(hex_address):
    """Returns (address, family) with IPv4-mapped IPv6 normalised to IPv4.

    A dual-stack listener shows up as ::ffff:0.0.0.0. Left alone it becomes a
    second, distinct listener and every diff carries a phantom pair."""
    text = hex_address.strip()
    if len(text) == 8:
        return decode_v4(text), "ipv4"
    if len(text) == 32:
        address = decode_v6(text)
        if address.startswith("::ffff:") and "." in address:
            return address[len("::ffff:"):], "ipv4-mapped"
        return address, "ipv6"
    raise ValueError(f"unrecognised address width: {hex_address!r}")


def split_endpoint(field):
    address, _, port = field.partition(":")
    return address, int(port, 16)


def is_wildcard(address):
    return address in WILDCARD_ADDRESSES


def is_loopback(address):
    return address.startswith(LOOPBACK_V4) or address == "::1"


# ---------------------------------------------------------- /proc/net parser


def ephemeral_range():
    """The kernel's ephemeral port range, read rather than assumed."""
    try:
        parts = sysp(PORT_RANGE_FILE).read_text().split()
        return int(parts[0]), int(parts[1])
    except (OSError, ValueError, IndexError):
        return EPHEMERAL_FALLBACK


def parse_proc_net(text, protocol):
    """Parse one /proc/net/{tcp,tcp6,udp,udp6} table.

    Returns (sockets, skipped). A line this parser cannot read is counted and
    skipped, never fatal."""
    sockets = []
    skipped = 0
    lines = text.splitlines()
    for line in lines[1:]:  # first line is the column header
        fields = line.split()
        if len(fields) < 10:
            if line.strip():
                skipped += 1
            continue
        try:
            local_address, local_port = split_endpoint(fields[1])
            remote_address, remote_port = split_endpoint(fields[2])
            state = fields[3].upper()
            uid = int(fields[7])
            inode = int(fields[9])
            address, family = decode_address(local_address)
        except (ValueError, IndexError):
            skipped += 1
            continue

        if protocol.startswith("tcp"):
            # Only TCP_LISTEN means a service is waiting. Everything else is a
            # connection in some stage of its life.
            if state != TCP_LISTEN_STATE:
                continue
            listening = True
        else:
            # UDP has no listen state. "Listening" here means bound with no
            # peer, which is a different concept and is labelled as one rather
            # than pretending the two match.
            if remote_port != 0:
                continue
            listening = False

        sockets.append(
            {
                "protocol": protocol,
                "address": address,
                "family": family,
                "port": local_port,
                "state": state,
                "tcp_listening": listening,
                "uid": uid,
                "inode": inode,
            }
        )
    return sockets, skipped


UNIX_STATE_LISTENING = "01"


def parse_proc_net_unix(text):
    """Parse /proc/net/unix, keeping only listening sockets.

    Columns: Num RefCount Protocol Flags Type St Inode Path"""
    sockets = []
    skipped = 0
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 7:
            if line.strip():
                skipped += 1
            continue
        try:
            state = fields[5].upper()
            inode = int(fields[6])
        except (ValueError, IndexError):
            skipped += 1
            continue
        if state != UNIX_STATE_LISTENING:
            continue
        path = fields[7] if len(fields) > 7 else "(unnamed)"
        sockets.append(
            {
                "protocol": "unix",
                "address": path,
                "family": "unix",
                "port": 0,
                "state": state,
                "tcp_listening": True,
                "uid": None,
                "inode": inode,
            }
        )
    return sockets, skipped


def read_listeners(include_unix=False):
    """All listening sockets. Returns (sockets, skipped, unreadable)."""
    sockets = []
    skipped = 0
    unreadable = []
    tables = [("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")]
    for filename, protocol in tables:
        path = sysp(f"{PROC_NET}/{filename}")
        try:
            text = path.read_text(errors="replace")
        except OSError:
            unreadable.append(f"{PROC_NET}/{filename}")
            continue
        found, missed = parse_proc_net(text, protocol)
        sockets.extend(found)
        skipped += missed

    if include_unix:
        path = sysp(f"{PROC_NET}/unix")
        try:
            found, missed = parse_proc_net_unix(path.read_text(errors="replace"))
            sockets.extend(found)
            skipped += missed
        except OSError:
            unreadable.append(f"{PROC_NET}/unix")

    return sockets, skipped, unreadable


# ------------------------------------------------------- process attribution


def clock_ticks():
    try:
        return os.sysconf("SC_CLK_TCK") or 100
    except (AttributeError, ValueError, OSError):
        return 100


def boot_time():
    try:
        for line in sysp("/proc/stat").read_text(errors="replace").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def read_process(pid_dir, btime):
    """Everything worth recording about the process holding a socket."""
    def attribute(name):
        try:
            return (pid_dir / name).read_text(errors="replace")
        except OSError:
            return None

    comm = (attribute("comm") or "").strip() or None
    raw_cmdline = attribute("cmdline") or ""
    # cmdline is NUL-separated, and the trailing NUL leaves an empty final arg.
    cmdline = [part for part in raw_cmdline.split("\0") if part]

    uid = None
    status = attribute("status") or ""
    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                uid = int(line.split()[1])
            except (ValueError, IndexError):
                pass
            break

    start_ticks = None
    stat = attribute("stat")
    if stat:
        # comm can contain spaces and parentheses, so field splitting has to
        # start after the last ')' rather than at the first space.
        close = stat.rfind(")")
        if close != -1:
            rest = stat[close + 1:].split()
            # starttime is field 22 overall; after comm that is index 19.
            if len(rest) > 19:
                try:
                    start_ticks = int(rest[19])
                except ValueError:
                    start_ticks = None

    start_epoch = None
    if start_ticks is not None and btime is not None:
        start_epoch = btime + (start_ticks / clock_ticks())

    cgroup = None
    cgroup_text = attribute("cgroup") or ""
    for line in cgroup_text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[2]:
            cgroup = parts[2].strip()
            break

    lowered = (cgroup or "").lower()
    return {
        "pid": int(pid_dir.name),
        "name": comm,
        "cmdline": cmdline,
        "uid": uid,
        "start_ticks": start_ticks,
        "start_epoch": start_epoch,
        "cgroup": cgroup,
        "in_container": any(hint in lowered for hint in CONTAINER_HINTS),
        "unit_like": bool(cgroup) and cgroup.endswith((".service", ".scope", ".slice")),
    }


def socket_owners():
    """inode -> process, by scanning /proc/*/fd for socket:[inode] symlinks.

    Returns (owners, scanned, denied). An unprivileged run can only read its
    own processes' descriptors, so `denied` is what tells the caller the
    attribution is incomplete rather than empty."""
    owners = {}
    scanned = 0
    denied = 0
    btime = boot_time()
    root = sysp(PROC)
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return owners, scanned, denied

    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            descriptors = list(fd_dir.iterdir())
        except OSError:
            denied += 1
            continue
        scanned += 1
        info = None
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            match = SOCKET_LINK.match(target)
            if not match:
                continue
            if info is None:
                info = read_process(entry, btime)
            owners[int(match.group(1))] = info
    return owners, scanned, denied


# ---------------------------------------------------------------- snapshots


def listener_key(listener):
    """What makes two listeners the same thing across snapshots.

    Protocol, address and port. Everything else about the socket is a property
    that can change while remaining the same listener, which is exactly what
    the diff classes describe."""
    return (listener["protocol"], listener["address"], listener["port"])


def key_string(key):
    return f"{key[0]}|{key[1]}|{key[2]}"


def owner_identity(listener):
    """The part of ownership that decides 'same service' vs 'different one'."""
    owner = listener.get("owner")
    if not owner:
        return None
    if owner.get("cmdline"):
        return " ".join(owner["cmdline"])
    return owner.get("name")


def capture(args):
    """Take a snapshot of what is listening now."""
    sockets, skipped, unreadable = read_listeners(include_unix=args.unix)
    owners, scanned, denied = socket_owners()

    low, high = ephemeral_range()
    listeners = []
    suppressed = 0
    for entry in sockets:
        entry = dict(entry)
        entry["owner"] = owners.get(entry["inode"])
        if not args.all and entry["protocol"] != "unix" and low <= entry["port"] <= high:
            suppressed += 1
            continue
        listeners.append(entry)

    listeners.sort(key=lambda item: (item["port"], item["protocol"], item["address"]))
    return {
        "version": SCHEMA_VERSION,
        "captured_at": now().isoformat(),
        "captured_as_root": is_root(),
        "ephemeral_range": [low, high],
        "ephemeral_suppressed": suppressed,
        "include_unix": bool(args.unix),
        "include_ephemeral": bool(args.all),
        "parse_skipped": skipped,
        "unreadable": unreadable,
        "processes_scanned": scanned,
        "processes_denied": denied,
        "listeners": listeners,
    }


def snapshot_path(when):
    stamp = when.strftime("%Y%m%dT%H%M%S")
    return state_dir() / f"{stamp}.json"


def save_snapshot(snapshot):
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = snapshot_path(now())
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    return path


def stored_snapshots():
    directory = state_dir()
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.json"))


class SnapshotError(Exception):
    """A snapshot that cannot be trusted to mean what it says."""


def load_snapshot(path):
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SnapshotError(f"could not read {path}: {exc}")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise SnapshotError(f"{path} does not contain a snapshot object")
    version = data.get("version")
    if version != SCHEMA_VERSION:
        # Parsing an unknown layout optimistically would produce a diff whose
        # errors all look like real findings.
        raise SnapshotError(
            f"{path} has schema version {version!r}, but this build understands "
            f"only version {SCHEMA_VERSION}. Take a fresh baseline with --save."
        )
    return data


# --------------------------------------------------------------------- diff


def diff_snapshots(baseline, current):
    """Classify what changed between two snapshots.

    Ownership-dependent classes are only produced when both sides could
    actually see ownership; see the root-mismatch handling in build_report."""
    trust_owners = baseline.get("captured_as_root") == current.get("captured_as_root")

    old = {listener_key(item): item for item in baseline.get("listeners", [])}
    new = {listener_key(item): item for item in current.get("listeners", [])}

    events = []
    appeared_keys = [key for key in new if key not in old]
    disappeared_keys = [key for key in old if key not in new]

    # Pair a disappearance with an appearance on the same protocol and port as
    # a rebind. 127.0.0.1:8080 becoming 0.0.0.0:8080 is one event: a service
    # that was local-only is now reachable from the network. Rendering it as a
    # disappearance plus an appearance loses exactly the thing worth knowing.
    rebound = []
    for gone_key in list(disappeared_keys):
        gone = old[gone_key]
        for new_key in list(appeared_keys):
            fresh = new[new_key]
            if gone_key[0] != new_key[0] or gone_key[2] != new_key[2]:
                continue
            gone_identity = owner_identity(gone)
            fresh_identity = owner_identity(fresh)
            if gone_identity is not None and fresh_identity is not None:
                if gone_identity != fresh_identity:
                    continue
                verified = True
            elif gone_identity is None and fresh_identity is None:
                # Neither side could be attributed, which is the normal case on
                # an unprivileged run. The port moving address is still the most
                # likely reading, but it is recorded as unverified rather than
                # asserted.
                verified = False
            else:
                continue
            rebound.append((gone_key, new_key, verified))
            disappeared_keys.remove(gone_key)
            appeared_keys.remove(new_key)
            break

    for key in sorted(appeared_keys):
        events.append({"change": "appeared", "key": key_string(key), "current": new[key]})
    for key in sorted(disappeared_keys):
        events.append({"change": "disappeared", "key": key_string(key), "baseline": old[key]})
    for gone_key, new_key, verified in rebound:
        events.append(
            {
                "change": "rebound",
                "key": key_string(new_key),
                "baseline": old[gone_key],
                "current": new[new_key],
                "from_address": gone_key[1],
                "to_address": new_key[1],
                "owner_verified": verified,
                "newly_reachable": is_loopback(gone_key[1]) and is_wildcard(new_key[1]),
            }
        )

    for key in sorted(set(old) & set(new)):
        before, after = old[key], new[key]
        if not trust_owners:
            continue
        before_identity = owner_identity(before)
        after_identity = owner_identity(after)
        if before_identity != after_identity:
            events.append(
                {
                    "change": "owner-changed",
                    "key": key_string(key),
                    "baseline": before,
                    "current": after,
                    "from_owner": before_identity,
                    "to_owner": after_identity,
                }
            )
            continue
        before_owner = before.get("owner") or {}
        after_owner = after.get("owner") or {}
        if before_owner and after_owner:
            if (before_owner.get("pid"), before_owner.get("start_epoch")) != (
                after_owner.get("pid"),
                after_owner.get("start_epoch"),
            ):
                events.append(
                    {
                        "change": "restarted",
                        "key": key_string(key),
                        "baseline": before,
                        "current": after,
                        "from_pid": before_owner.get("pid"),
                        "to_pid": after_owner.get("pid"),
                    }
                )

    order = {name: index for index, name in enumerate(CHANGE_CLASSES)}
    events.sort(key=lambda event: (order.get(event["change"], 99), event["key"]))
    return events, trust_owners


# ----------------------------------------------------------------- findings


def observations(events, current):
    """Things worth pointing at, as observations rather than judgements.

    Deliberately info: this tool does not know what the machine is for, so it
    reports what changed and leaves the question of whether that is fine to
    somebody who does."""
    results = []

    exposed = [e for e in events if e["change"] == "rebound" and e["newly_reachable"]]
    if exposed:
        results.append(
            make(
                "exposure",
                "info",
                f"{len(exposed)} listener(s) moved from loopback to a wildcard address",
                detail=[
                    f"    {e['key']}  {e['from_address']} -> {e['to_address']}"
                    for e in exposed
                ]
                + [
                    "",
                    "A service that was reachable only from this machine now accepts",
                    "connections from the network. Whether that is intended is not",
                    "something this tool can know, so it is reported and not ranked.",
                ],
            )
        )

    wildcard_new = [
        e
        for e in events
        if e["change"] == "appeared" and is_wildcard(e["current"]["address"])
    ]
    if wildcard_new:
        results.append(
            make(
                "new-wildcard",
                "info",
                f"{len(wildcard_new)} new listener(s) bound to a wildcard address",
                detail=[
                    f"    {e['key']}  {describe_owner(e['current'])}" for e in wildcard_new
                ],
            )
        )

    unmanaged = []
    for event in events:
        if event["change"] != "appeared":
            continue
        owner = event["current"].get("owner")
        if owner and not owner.get("unit_like") and not owner.get("in_container"):
            unmanaged.append(event)
    if unmanaged:
        results.append(
            make(
                "unmanaged",
                "info",
                f"{len(unmanaged)} new listener(s) whose process is not under a systemd unit",
                detail=[
                    f"    {e['key']}  {describe_owner(e['current'])}"
                    f"  cgroup {(e['current'].get('owner') or {}).get('cgroup')}"
                    for e in unmanaged
                ]
                + [
                    "",
                    "Not inherently wrong: a login shell, a container runtime and a",
                    "hand-started daemon all look like this. It is noted because it",
                    "is the difference between a packaged service and something",
                    "somebody launched.",
                ],
            )
        )
    return results


def describe_owner(listener):
    owner = listener.get("owner")
    if not owner:
        return "(owner not attributed)"
    name = owner.get("name") or "?"
    pid = owner.get("pid")
    marker = "  [container]" if owner.get("in_container") else ""
    return f"{name} (pid {pid}){marker}"


# ------------------------------------------------------------------ report


def build_report(args):
    report = {
        "tool": "portwatch",
        "linux": is_linux(),
        "root": is_root(),
        "mode": "diff" if args.diff is not None else "list" if args.list else
                "save" if args.save else "show",
        "snapshot": None,
        "baseline": None,
        "baseline_path": None,
        "saved_to": None,
        "snapshots": [],
        "events": [],
        "results": [],
        "counts": {status: 0 for status in STATUS_ORDER},
        "error": None,
        "exit_code": NO_CHANGES,
    }

    def finish():
        for res in report["results"]:
            report["counts"][res["status"]] = report["counts"].get(res["status"], 0) + 1
        if report["error"]:
            report["exit_code"] = COULD_NOT_DETERMINE
        elif report["mode"] == "diff" and report["events"]:
            report["exit_code"] = CHANGES_FOUND
        return report

    if not report["linux"]:
        report["error"] = "not-linux"
        report["results"].append(
            make("platform", "unknown", "This tool only works on Linux (it reads /proc directly)")
        )
        return finish()

    if args.list:
        paths = stored_snapshots()
        report["snapshots"] = [str(p) for p in paths]
        if not paths:
            report["results"].append(
                make(
                    "snapshots",
                    "info",
                    f"No snapshots stored in {state_dir()}",
                    fix="portwatch --save",
                )
            )
        return finish()

    snapshot = capture(args)
    report["snapshot"] = snapshot

    if snapshot["unreadable"]:
        report["error"] = "proc-unreadable"
        report["results"].append(
            make(
                "proc",
                "unknown",
                "Could not read the kernel socket tables",
                detail=[f"    {path}" for path in snapshot["unreadable"]],
            )
        )
        return finish()

    # The root limitation, stated loudly rather than rendered as an absence.
    if not report["root"] and snapshot["processes_denied"]:
        report["results"].append(
            make(
                "attribution",
                "unknown",
                f"Ownership could not be determined for {snapshot['processes_denied']} process(es)",
                detail=[
                    "An unprivileged run can only read its own processes' file",
                    "descriptors, so sockets belonging to anything else are listed",
                    "correctly but with no owner.",
                    "",
                    "This is a limit of what this run could see, not a statement that",
                    "those sockets are unowned. Re-run with privileges for full",
                    "attribution.",
                ],
                fix="sudo portwatch" + (" --save" if args.save else ""),
            )
        )

    if snapshot["ephemeral_suppressed"] and not args.all:
        low, high = snapshot["ephemeral_range"]
        report["results"].append(
            make(
                "ephemeral",
                "info",
                f"{snapshot['ephemeral_suppressed']} socket(s) in the ephemeral range "
                f"{low}-{high} were not listed",
                detail=[
                    "Mostly outbound UDP source ports, which are noise in a diff.",
                    "The range was read from the kernel rather than assumed.",
                ],
                fix="portwatch --all",
            )
        )

    if snapshot["parse_skipped"]:
        report["results"].append(
            make(
                "parse",
                "info",
                f"{snapshot['parse_skipped']} unparseable line(s) in /proc/net were skipped",
            )
        )

    if args.save:
        try:
            path = save_snapshot(snapshot)
        except OSError as exc:
            report["error"] = "save-failed"
            report["results"].append(
                make("save", "unknown", f"Could not write the snapshot: {exc}")
            )
            return finish()
        report["saved_to"] = str(path)
        report["results"].append(
            make("save", "ok", f"Baseline saved to {path}")
        )
        return finish()

    if args.diff is None:
        return finish()

    # --- diff mode
    if args.diff:
        candidate = Path(args.diff)
    else:
        paths = stored_snapshots()
        if not paths:
            report["error"] = "no-baseline"
            report["results"].append(
                make(
                    "baseline",
                    "unknown",
                    f"No baseline snapshot in {state_dir()}",
                    detail=["There is nothing to compare against, so nothing was determined."],
                    fix="portwatch --save",
                )
            )
            return finish()
        candidate = paths[-1]

    try:
        baseline = load_snapshot(candidate)
    except SnapshotError as exc:
        report["error"] = "bad-snapshot"
        report["results"].append(make("baseline", "unknown", str(exc), fix="portwatch --save"))
        return finish()

    report["baseline"] = baseline
    report["baseline_path"] = str(candidate)

    events, trust_owners = diff_snapshots(baseline, snapshot)
    report["events"] = events

    if not trust_owners:
        # Diffing a privileged baseline against an unprivileged run turns every
        # attributed listener into an unattributed one, which would render as a
        # wall of ownership changes that are entirely an artefact of how the two
        # snapshots were taken.
        report["error"] = "root-mismatch"
        was, now_state = baseline.get("captured_as_root"), snapshot["captured_as_root"]
        report["results"].append(
            make(
                "root-mismatch",
                "unknown",
                "Baseline and current run had different privileges; ownership changes "
                "are not comparable",
                detail=[
                    f"    baseline captured as root: {was}",
                    f"    this run as root:          {now_state}",
                    "",
                    "Ownership-dependent classes (owner-changed, restarted) are",
                    "suppressed because every one of them would be an artefact of the",
                    "privilege difference rather than a change on the machine.",
                    "Appeared, disappeared and rebound are still reported: those do",
                    "not depend on being able to see the owner.",
                ],
                fix="sudo portwatch --diff" if was and not now_state else "portwatch --save",
            )
        )

    report["results"].extend(observations(events, snapshot))

    if not events:
        report["results"].append(
            make("diff", "ok", f"No changes against {candidate.name}")
        )
    else:
        counts = {}
        for event in events:
            counts[event["change"]] = counts.get(event["change"], 0) + 1
        summary = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))
        report["results"].append(
            make(
                "diff",
                "info",
                f"{len(events)} change(s) against {candidate.name}: {summary}",
                detail=[
                    "Restarts are listed but are not findings: services restart, and a",
                    "tool that flagged every one would teach you to skip past it.",
                ],
            )
        )

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


def address_class(address):
    """What kind of address this is, for deciding whether two rows are the two
    halves of one dual-stack listener.

    Only the loopback pair (127.0.0.1 / ::1) and the wildcard pair (0.0.0.0 /
    ::) are equivalent. Two specific addresses that merely share a port are not,
    and merging them would invent a single service where there might be two."""
    if is_loopback(address):
        return "loopback"
    if is_wildcard(address):
        return "wildcard"
    return address


def group_listeners(listeners):
    """Collapse the IPv4 and IPv6 rows of one dual-stack service into one line.

    The same daemon on 0.0.0.0:22 and :::22 is one service, and listing it twice
    makes a short table look twice as busy as the machine actually is.

    This is display only. The diff uses the full protocol/address/port key, so
    nothing here can hide a change."""
    groups = {}
    for listener in listeners:
        base = listener["protocol"].rstrip("6")
        owner = listener.get("owner") or {}
        key = (
            base,
            listener["port"],
            owner.get("pid"),
            owner.get("name"),
            address_class(listener["address"]),
        )
        entry = groups.setdefault(
            key,
            {
                "protocol": base,
                "port": listener["port"],
                "addresses": [],
                "families": [],
                "owner": listener.get("owner"),
                "uid": listener.get("uid"),
            },
        )
        entry["addresses"].append(listener["address"])
        entry["families"].append(listener["family"])
    return [groups[key] for key in sorted(groups, key=lambda k: (k[1], k[0], k[4]))]


def render_current(out, report):
    snapshot = report["snapshot"]
    if not snapshot:
        return
    out.header("Listening now")
    listeners = snapshot["listeners"]
    if not listeners:
        emit("  Nothing is listening.")
        return

    emit(f"  {'PROTO':<6} {'ADDRESS':<26} {'PORT':>6}  {'PROCESS':<24} {'CGROUP'}")
    for group in group_listeners(listeners):
        addresses = ", ".join(sorted(set(group["addresses"])))
        if len(addresses) > 26:
            addresses = addresses[:23] + "..."
        owner = group.get("owner") or {}
        if owner:
            process = f"{owner.get('name') or '?'} ({owner.get('pid')})"
        else:
            process = out._c("35", "not attributed")
        cgroup = owner.get("cgroup") or ""
        if owner.get("in_container"):
            cgroup = "[container] " + cgroup
        if len(cgroup) > 40:
            cgroup = "..." + cgroup[-37:]
        emit(f"  {group['protocol']:<6} {addresses:<26} {group['port']:>6}  {process:<24} {out._c('90', cgroup)}")


CHANGE_LABELS = {
    "appeared": ("32", "appeared"),
    "disappeared": ("33", "disappeared"),
    "rebound": ("35", "rebound"),
    "owner-changed": ("36", "owner changed"),
    "restarted": ("90", "restarted"),
}


def render_diff(out, report):
    events = report["events"]
    if report["mode"] != "diff":
        return
    out.header("Changes")
    emit(f"  baseline: {report['baseline_path']}")
    emit()
    if not events:
        emit("  Nothing changed.")
        return

    for change in CHANGE_CLASSES:
        group = [event for event in events if event["change"] == change]
        if not group:
            continue
        code, label = CHANGE_LABELS[change]
        emit(f"  {out._c('1', label.upper())}")
        for event in group:
            protocol, address, port = event["key"].split("|")
            head = f"    {out._c(code, protocol):<6} {address}:{port}"
            if change == "appeared":
                emit(f"{head}   {describe_owner(event['current'])}")
            elif change == "disappeared":
                emit(f"{head}   was {describe_owner(event['baseline'])}")
            elif change == "rebound":
                note = "" if event["owner_verified"] else "   (ownership unverified this run)"
                emit(
                    f"    {out._c(code, protocol):<6} port {port}: "
                    f"{event['from_address']} -> {event['to_address']}{note}"
                )
                if event["newly_reachable"]:
                    emit(f"           {out._c('1', 'was loopback-only, now reachable from the network')}")
            elif change == "owner-changed":
                emit(f"{head}")
                emit(f"           was: {event['from_owner']}")
                emit(f"           now: {event['to_owner']}")
            elif change == "restarted":
                emit(f"{head}   pid {event['from_pid']} -> {event['to_pid']}")
        emit()


def render(out, report):
    if report["results"]:
        grouped = {}
        for res in report["results"]:
            grouped.setdefault(res["status"], []).append(res)
        titles = {
            "fail": "Failures",
            "warn": "Worth attention",
            "unknown": "Could not determine",
            "info": "Observations",
            "skipped": "Not applicable",
            "ok": "Fine",
        }
        for status in STATUS_ORDER:
            group = grouped.get(status)
            if not group:
                continue
            out.header(titles[status])
            for res in group:
                out.finding(res)

    if report["mode"] == "list":
        out.header("Stored snapshots")
        for path in report["snapshots"]:
            emit(f"  {path}")
        return

    if report["error"] in ("not-linux", "proc-unreadable", "no-baseline", "bad-snapshot"):
        return

    if report["mode"] == "diff":
        render_diff(out, report)
    else:
        render_current(out, report)

    out.header("Reading this")
    for line in wrap(
        "This tool reports what changed and does not rank it. There is no risk "
        "score and no suspicious label, because it has no idea what this machine "
        "is for: a new listener on 0.0.0.0 is a deployment on one box and an "
        "incident on another, and only you know which. For when it changed, "
        "chronicle covers the same question on the time axis."
    ):
        emit(f"  {line}")


# --------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="Snapshot listening sockets and diff them against a baseline.",
        epilog=(
            "Read-only with respect to system state: it writes snapshot files and "
            "nothing else.\n\n"
            "No risk scoring. It reports what changed; judging it is your job.\n\n"
            "Exit codes: 0 no changes, 1 the diff found changes, 2 no verdict "
            "reached."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--save", action="store_true", help="write a baseline snapshot")
    parser.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help="compare against the latest baseline, or a specific snapshot file",
    )
    parser.add_argument("--list", action="store_true", help="list stored snapshots")
    parser.add_argument("--unix", action="store_true", help="include unix domain sockets")
    parser.add_argument(
        "--all", action="store_true", help="include ephemeral-range sockets"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    args = parser.parse_args()

    report = build_report(args)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return report["exit_code"]

    render(Out(color=not args.no_color), report)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
