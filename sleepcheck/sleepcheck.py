#!/usr/bin/env python3
"""Audit Linux suspend and hibernate configuration without changing it.

sleepcheck answers the parts of "why will this machine not sleep?" that can be
observed safely: kernel sleep states, systemd policy, current inhibitor locks,
enabled firmware wake sources, and recent sleep-service messages.  It never
asks the machine to sleep and it does not decide which enabled wake source (if
any) caused a resume.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------- test seams
SYSROOT = Path("/")
PLATFORM = None
IS_ROOT = None


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


def run(cmd, timeout=20):
    """Return (returncode, stdout, reason); returncode is None on no command."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                              errors="replace")
    except FileNotFoundError:
        return None, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return None, "", f"{' '.join(cmd)} timed out after {timeout}s"
    except OSError as exc:
        return None, "", str(exc)
    return proc.returncode, proc.stdout, (proc.stderr or "").strip() or None


def read_text(path):
    try:
        return sysp(path).read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


# ------------------------------------------------------------------- results
STATUS_ORDER = ["fail", "warn", "unknown", "info", "skipped", "ok"]
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


# ----------------------------------------------------------- systemd config
def parse_config(text):
    """Parse a systemd .conf file. Repeated keys use the last value."""
    values = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


CONFIG_ROOTS = ("/usr/lib/systemd", "/usr/local/lib/systemd", "/run/systemd", "/etc/systemd")


def effective_config(name):
    """Read systemd's effective main file and lexical .d snippets.

    A main file in a higher-priority directory replaces lower-priority copies.
    Drop-ins accumulate, except that a same-named drop-in in a higher-priority
    directory replaces the lower one.  Looking only at /etc is tempting but
    can turn a vendor or runtime AllowSuspend=no into a false pass.
    """
    main = None
    for root in CONFIG_ROOTS:
        path = f"{root}/{name}"
        if read_text(path) is not None:
            main = path
    paths = [main] if main else []
    dropins = {}
    for root in CONFIG_ROOTS:
        directory = sysp(f"{root}/{name}.d")
        try:
            for path in directory.glob("*.conf"):
                dropins[path.name] = f"{root}/{name}.d/{path.name}"
        except OSError:
            continue
    paths.extend(dropins[key] for key in sorted(dropins))
    values, used = {}, []
    for path in paths:
        text = read_text(path)
        if text is not None:
            values.update(parse_config(text))
            used.append(path)
    return values, used


def have_systemd():
    # The runtime directory is the useful gate.  A config file on disk alone
    # does not mean PID 1 is systemd.
    return sysp("/run/systemd/system").exists()


def parse_mem_sleep(text):
    states, selected = [], None
    for word in (text or "").split():
        match = re.fullmatch(r"\[([^]]+)\]", word)
        state = match.group(1) if match else word
        states.append(state)
        if match:
            selected = state
    return states, selected


def parse_inhibitors(text):
    """Parse systemd-inhibit's table without assuming fixed column widths.

    WHO, WHAT, WHY and MODE are the fields that matter here.  The middle UID,
    USER, PID and COMM columns vary across systemd releases, so retain the
    stable ends and present the rest as context rather than inventing columns.
    """
    locks = []
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    for line in lines:
        if line.lstrip().startswith(("WHO", "No inhibitors")):
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3:
            continue
        mode = parts[-1]
        what = parts[1] if len(parts) > 1 else ""
        why = parts[-2] if len(parts) >= 4 else ""
        locks.append({"who": parts[0], "what": what, "why": why, "mode": mode,
                      "raw": line.strip()})
    return locks


def parse_acpi_wakeup(text):
    sources = []
    # /proc/acpi/wakeup's table is not a machine interface.  The device name
    # and its trailing *enabled/*disabled marker are the only stable pieces.
    for line in (text or "").splitlines():
        match = re.match(r"^\s*(\S+).*\*?(enabled|disabled)\s*$", line, re.I)
        if match and match.group(1).lower() != "device":
            sources.append({"device": match.group(1), "enabled": match.group(2).lower() == "enabled"})
    return sources


def parse_journal(text):
    events, skipped = [], 0
    for line in (text or "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        message = item.get("MESSAGE")
        if not isinstance(message, str):
            skipped += 1
            continue
        events.append({
            "timestamp": item.get("__REALTIME_TIMESTAMP"),
            "unit": item.get("_SYSTEMD_UNIT"),
            "priority": item.get("PRIORITY"),
            "message": message,
        })
    return events, skipped


# -------------------------------------------------------------------- checks
@register("states", "Kernel sleep states")
def check_states(ctx):
    state_text = read_text("/sys/power/state")
    if state_text is None:
        return make("states", "unknown", "Could not read kernel sleep states",
                    ["/sys/power/state is unavailable or unreadable."])
    states = state_text.split()
    ctx["sleep_states"] = states
    mem_states, selected = parse_mem_sleep(read_text("/sys/power/mem_sleep"))
    ctx["mem_sleep_states"] = mem_states
    ctx["mem_sleep_selected"] = selected
    results = []
    if "mem" not in states:
        results.append(make("suspend-unavailable", "warn", "Kernel suspend is unavailable",
                            ["The kernel did not advertise the 'mem' sleep state."],
                            "Check firmware settings and kernel boot parameters.", "states"))
    else:
        detail = ["Available states: " + ", ".join(states)]
        if mem_states:
            detail.append("mem variants: " + ", ".join(mem_states) +
                          (f"; selected: {selected}" if selected else "; selected variant was not marked"))
        results.append(make("suspend-state", "ok", "Kernel suspend is available", detail, result_id="states"))
    if "disk" in states:
        results.append(make("hibernate-state", "info", "Kernel hibernation is available",
                            ["This reports kernel capability, not whether swap is large enough for hibernation."],
                            result_id="states"))
    else:
        results.append(make("hibernate-state", "info", "Kernel hibernation is not advertised",
                            ["The 'disk' sleep state is absent."], result_id="states"))
    return results


@register("policy", "systemd sleep policy")
def check_policy(ctx):
    if not ctx["systemd"]:
        return make("policy", "skipped", "systemd is not running",
                    ["sleepcheck does not infer another init system's sleep policy."])
    sleep, sleep_files = effective_config("sleep.conf")
    logind, logind_files = effective_config("logind.conf")
    ctx["sleep_policy"] = sleep
    ctx["logind_policy"] = logind
    ctx["config_files"] = {"sleep": sleep_files, "logind": logind_files}
    results = []
    disabled = []
    for key, label in (("AllowSuspend", "suspend"), ("AllowHibernation", "hibernation"),
                       ("AllowHybridSleep", "hybrid sleep"), ("AllowSuspendThenHibernate", "suspend-then-hibernate")):
        value = sleep.get(key)
        if value is not None and value.lower() in ("no", "false", "0"):
            disabled.append(label)
    if disabled:
        results.append(make("policy-disabled", "warn", "systemd policy disables " + ", ".join(disabled),
                            ["Effective settings are assembled from: " + (", ".join(sleep_files) or "system defaults"),
                             "This may be deliberate; sleepcheck does not change it."],
                            "Set the relevant Allow...= option to yes in /etc/systemd/sleep.conf or a drop-in.",
                            "policy"))
    else:
        results.append(make("policy-sleep", "ok", "systemd policy does not disable suspend",
                            ["No effective AllowSuspend=no setting was found."], result_id="policy"))
    lid = logind.get("HandleLidSwitch")
    if lid:
        results.append(make("lid-switch", "info", f"Lid-close policy: {lid}",
                            ["Effective logind config: " + (", ".join(logind_files) or "system defaults"),
                             "This is context, not a judgement: desktops, docks and servers need different policies."],
                            result_id="policy"))
    return results


@register("inhibitors", "Active inhibitor locks")
def check_inhibitors(ctx):
    if not ctx["systemd"]:
        return make("inhibitors", "skipped", "systemd is not running")
    rc, text, reason = run(["systemd-inhibit", "--list", "--no-pager"])
    if rc is None:
        return make("inhibitors", "unknown", "Could not list inhibitor locks", [reason or "command unavailable"])
    if rc != 0:
        return make("inhibitors", "unknown", "Inhibitor-lock query failed", [reason or "systemd-inhibit returned an error"])
    locks = parse_inhibitors(text)
    ctx["inhibitors"] = locks
    blocking = [lock for lock in locks if lock["mode"] == "block" and
                any(x in lock["what"].split(":") for x in ("sleep", "shutdown", "idle"))]
    if blocking:
        detail = [f"{lock['who']}: {lock['what']} — {lock['why'] or 'no reason supplied'}" for lock in blocking]
        detail.append("A lock is an observation of what is blocking sleep now, not a claim that it is wrong.")
        return make("sleep-blocked", "warn", f"{len(blocking)} active inhibitor lock(s) can block sleep", detail,
                    "Review with: systemd-inhibit --list", "inhibitors")
    return make("inhibitors", "ok", "No active inhibitor lock is blocking sleep",
                [f"{len(locks)} non-blocking inhibitor lock(s) were also reported." if locks else "No inhibitor locks reported."])


@register("wake", "Firmware wake sources")
def check_wake(ctx):
    text = read_text("/proc/acpi/wakeup")
    if text is None:
        return make("wake", "skipped", "ACPI wake-source table is unavailable",
                    ["This is normal on non-ACPI systems and on some firmware."])
    sources = parse_acpi_wakeup(text)
    ctx["wake_sources"] = sources
    if not sources:
        return make("wake", "unknown", "Could not parse the ACPI wake-source table",
                    ["The table was present but contained no recognised device states."])
    enabled = [s["device"] for s in sources if s["enabled"]]
    return make("wake", "info", f"{len(enabled)} ACPI wake source(s) enabled",
                ["Enabled: " + (", ".join(enabled) if enabled else "none"),
                 "An enabled source is capable of waking the machine; it is not evidence that it did."],
                result_id="wake")


@register("journal", "Recent sleep-service events")
def check_journal(ctx):
    if not ctx["systemd"]:
        return make("journal", "skipped", "systemd is not running")
    cmd = ["journalctl", "--no-pager", "--output=json", "--since", "7 days ago",
           "-u", "systemd-suspend.service", "-u", "systemd-hibernate.service",
           "-u", "systemd-hybrid-sleep.service", "-u", "systemd-suspend-then-hibernate.service"]
    rc, text, reason = run(cmd, timeout=30)
    if rc is None:
        return make("journal", "unknown", "Could not read sleep-service journal entries", [reason or "journalctl unavailable"])
    if rc != 0:
        return make("journal", "unknown", "Sleep-service journal query failed", [reason or "journalctl returned an error"])
    events, skipped = parse_journal(text)
    ctx["journal_events"] = events
    ctx["journal_skipped"] = skipped
    failed = [e for e in events if re.search(r"\b(failed|failure|error)\b", e["message"], re.I)]
    if failed:
        return make("sleep-service-failure", "warn", f"{len(failed)} recent sleep-service error message(s)",
                    [e["message"] for e in failed[:5]] +
                    ["These messages describe service failures; they do not identify a wake source."],
                    "journalctl -b -u systemd-suspend.service", "journal")
    return make("journal", "info", f"{len(events)} sleep-service event(s) in the last 7 days",
                ([f"Skipped {skipped} malformed journal record(s)."] if skipped else []) +
                ["No failure wording was found in the returned events."], result_id="journal")


# ------------------------------------------------------------------- runner
def run_checks(selected):
    ctx = {"systemd": have_systemd(), "sleep_states": [], "mem_sleep_states": [],
           "mem_sleep_selected": None, "sleep_policy": {}, "logind_policy": {},
           "config_files": {}, "inhibitors": [], "wake_sources": [], "journal_events": [],
           "journal_skipped": 0}
    results = []
    for entry in CHECKS:
        if entry["id"] not in selected:
            continue
        try:
            produced = entry["fn"](ctx)
        except Exception as exc:  # one broken parser cannot erase the rest
            produced = make(entry["id"], "unknown", f"Check raised {type(exc).__name__}",
                            [str(exc), "This is a bug in sleepcheck, not a finding about your system."])
        if isinstance(produced, dict):
            produced = [produced]
        for result in produced or []:
            result["title"] = entry["title"]
            results.append(result)
    return ctx, results


def build_report(args):
    report = {"tool": "sleepcheck", "linux": is_linux(), "root": None, "systemd": None,
              "sleep_states": [], "mem_sleep_states": [], "mem_sleep_selected": None,
              "policy": {"sleep": {}, "logind": {}, "files": {}}, "inhibitors": [],
              "wake_sources": [], "journal_events": [], "journal_skipped": 0,
              "results": [], "counts": {s: 0 for s in STATUS_ORDER}, "error": None, "exit_code": 0}
    if not report["linux"]:
        report.update(error="not-linux", exit_code=2)
        return report
    selected = [entry["id"] for entry in CHECKS]
    if args.only:
        selected = [x for x in selected if x in args.only]
    if args.skip:
        selected = [x for x in selected if x not in args.skip]
    ctx, results = run_checks(selected)
    report.update(root=is_root(), systemd=ctx["systemd"], sleep_states=ctx["sleep_states"],
                  mem_sleep_states=ctx["mem_sleep_states"], mem_sleep_selected=ctx["mem_sleep_selected"],
                  policy={"sleep": ctx["sleep_policy"], "logind": ctx["logind_policy"], "files": ctx["config_files"]},
                  inhibitors=ctx["inhibitors"], wake_sources=ctx["wake_sources"],
                  journal_events=ctx["journal_events"], journal_skipped=ctx["journal_skipped"], results=results)
    for result in results:
        report["counts"][result["status"]] += 1
    if any(r["status"] in EXIT_STATUSES for r in results):
        report["exit_code"] = 1
    return report


def render(report):
    if not report["linux"]:
        print("sleepcheck only works on Linux (it reads /proc and /sys directly).")
        return
    for status in STATUS_ORDER:
        group = [r for r in report["results"] if r["status"] == status]
        if not group:
            continue
        print("\n" + {"fail": "Failures", "warn": "Warnings", "unknown": "Could not determine",
                       "info": "Informational", "skipped": "Not applicable", "ok": "Passed"}[status])
        print("-" * len({"fail": "Failures", "warn": "Warnings", "unknown": "Could not determine",
                           "info": "Informational", "skipped": "Not applicable", "ok": "Passed"}[status]))
        for result in group:
            print("  " + result["summary"])
            for line in result["detail"]:
                print("    " + line)
            if result["fix"]:
                print("    fix: " + result["fix"])
    counts = report["counts"]
    print("\nSummary\n-------")
    print("  " + "  ".join(f"{counts[s]} {s}" for s in STATUS_ORDER))
    print("  sleepcheck is read-only; it never suspends the machine or changes wake settings.")


def main():
    check_ids = [entry["id"] for entry in CHECKS]
    parser = argparse.ArgumentParser(description="Read-only Linux suspend and hibernate audit.")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="accepted for consistency; output is plain")
    parser.add_argument("--only", action="append", metavar="CHECK", help="run only these checks (repeatable, comma-separated)")
    parser.add_argument("--skip", action="append", metavar="CHECK", help="skip these checks (repeatable, comma-separated)")
    args = parser.parse_args()
    expand = lambda items: [piece.strip() for item in (items or []) for piece in item.split(",") if piece.strip()]
    args.only, args.skip = expand(args.only), expand(args.skip)
    unknown = [x for x in args.only + args.skip if x not in check_ids]
    if unknown:
        parser.error("unknown check(s): " + ", ".join(unknown) + "; valid checks: " + ", ".join(check_ids))
    report = build_report(args)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        render(report)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
