#!/usr/bin/env python3
"""
Tests for chronicle.

    python3 -m unittest discover -s chronicle/tests -t chronicle/tests -v
    ./chronicle/tests/test_chronicle.py

Standard library only, same rule as the tools.

The pacman log reader is the fragile part, the same way iw output is in rfscan:
the format has changed across pacman versions and third-party tooling writes
lines it does not model. So it gets fixtures spanning both timestamp formats,
a real 47-package transaction, a removal, a downgrade, and malformed lines that
must be skipped and counted rather than fatal.

The other half of the suite is about honesty rather than parsing: an
unsupported package manager and an empty log must not look the same, a
restricted journal must be reported as partial rather than silently truncated,
and the tool must never claim one event caused another.
"""

import contextlib
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))

import chronicle  # noqa: E402

# Fixed clock so relative windows are deterministic.
FIXED_NOW = datetime(2026, 8, 12, 20, 0, 0, tzinfo=timezone.utc)

BOOT_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BOOT_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
BOOT_C = "cccccccccccccccccccccccccccccccc"

ARCH_OS_RELEASE = 'ID=arch\nPRETTY_NAME="Arch Linux"\n'
DEBIAN_OS_RELEASE = 'ID=debian\nID_LIKE=""\nPRETTY_NAME="Debian GNU/Linux 13"\n'


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class Args:
    def __init__(self, **kw):
        self.since = kw.get("since")
        self.until = kw.get("until")
        self.boot = kw.get("boot")
        self.before_boot = kw.get("before_boot", False)
        self.rollback_hint = kw.get("rollback_hint", False)
        self.verbose = kw.get("verbose", False)
        self.json = kw.get("json", False)
        self.no_color = kw.get("no_color", True)


class TreeCase(unittest.TestCase):
    """Synthetic system tree plus the module seams."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="chronicle-test-"))
        self._saved = (
            chronicle.SYSROOT,
            chronicle.PLATFORM,
            chronicle.IS_ROOT,
            chronicle.NOW,
            chronicle.USER,
            chronicle.run,
        )
        chronicle.SYSROOT = self.root
        chronicle.PLATFORM = "linux"
        chronicle.IS_ROOT = False
        chronicle.NOW = FIXED_NOW
        chronicle.USER = "dostrom"
        chronicle.run = lambda cmd, timeout=60: (None, "", "stubbed: unavailable")
        self.write("/etc/os-release", ARCH_OS_RELEASE)
        self.write("/etc/group", "root:x:0:\nsystemd-journal:x:190:\nwheel:x:998:\n")

    def tearDown(self):
        (
            chronicle.SYSROOT,
            chronicle.PLATFORM,
            chronicle.IS_ROOT,
            chronicle.NOW,
            chronicle.USER,
            chronicle.run,
        ) = self._saved
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, path, content, mtime=None):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if mtime is not None:
            os.utime(target, (mtime, mtime))
        return target

    def install_pacman_log(self):
        self.write(chronicle.PACMAN_LOG, fixture("pacman.log"))

    def stub_journal(self, boots=None, records=None, systemd=True):
        boots_json = boots if boots is not None else fixture("journal-boots.json")
        records_text = records if records is not None else fixture("journal-records.jsonl")

        def fake(cmd, timeout=60):
            joined = " ".join(cmd)
            if joined.startswith("systemctl --version"):
                return (0, "systemd 256\n", None) if systemd else (None, "", "not found")
            if not systemd:
                return None, "", "not found"
            if "--list-boots" in cmd:
                if "--output=json" in cmd:
                    return (0, boots_json, None) if boots_json else (1, "", "no json")
                return 1, "", "text not stubbed"
            if joined.startswith("journalctl --output=json"):
                return 0, records_text, None
            return None, "", "unavailable"

        chronicle.run = fake


# ------------------------------------------------------------ window parsing


class TestParseWhen(unittest.TestCase):
    def setUp(self):
        self.ref = FIXED_NOW

    def test_iso_date(self):
        parsed = chronicle.parse_when("2026-08-01", self.ref)
        self.assertEqual((parsed.year, parsed.month, parsed.day), (2026, 8, 1))

    def test_iso_datetime_with_t(self):
        parsed = chronicle.parse_when("2026-08-01T15:30", self.ref)
        self.assertEqual((parsed.hour, parsed.minute), (15, 30))

    def test_iso_datetime_with_space(self):
        parsed = chronicle.parse_when("2026-08-01 15:30", self.ref)
        self.assertEqual((parsed.hour, parsed.minute), (15, 30))

    def test_now(self):
        self.assertEqual(chronicle.parse_when("now", self.ref), self.ref)

    def test_today_is_midnight(self):
        parsed = chronicle.parse_when("today", self.ref)
        self.assertEqual((parsed.hour, parsed.minute, parsed.second), (0, 0, 0))
        self.assertEqual(parsed.day, self.ref.day)

    def test_yesterday_is_the_previous_midnight(self):
        parsed = chronicle.parse_when("yesterday", self.ref)
        self.assertEqual(parsed.day, 11)
        self.assertEqual(parsed.hour, 0)

    def test_days_ago(self):
        self.assertEqual(
            chronicle.parse_when("3 days ago", self.ref), self.ref - timedelta(days=3)
        )

    def test_weeks_ago(self):
        self.assertEqual(
            chronicle.parse_when("2 weeks ago", self.ref), self.ref - timedelta(days=14)
        )

    def test_hours_ago(self):
        self.assertEqual(
            chronicle.parse_when("6 hours ago", self.ref), self.ref - timedelta(hours=6)
        )

    def test_singular_and_plural_both_work(self):
        self.assertEqual(
            chronicle.parse_when("1 day ago", self.ref),
            chronicle.parse_when("1 days ago", self.ref),
        )

    def test_case_and_whitespace_tolerant(self):
        self.assertEqual(
            chronicle.parse_when("  3 DAYS AGO ", self.ref),
            chronicle.parse_when("3 days ago", self.ref),
        )

    def test_unparseable_raises_rather_than_defaulting(self):
        # Silently substituting a window the user did not ask for would make
        # every result quietly wrong rather than loudly absent.
        for bad in ("last tuesday", "3 fortnights ago", "", "   ", "soon", "2026-13-45"):
            with self.subTest(value=bad):
                with self.assertRaises(chronicle.WindowError):
                    chronicle.parse_when(bad, self.ref)

    def test_error_message_lists_accepted_forms(self):
        self.assertIn("days ago", chronicle.ACCEPTED_WINDOW_FORMS)
        self.assertIn("yesterday", chronicle.ACCEPTED_WINDOW_FORMS)
        self.assertIn("ISO date", chronicle.ACCEPTED_WINDOW_FORMS)


# ------------------------------------------------------------- pacman parser


class TestPacmanParser(unittest.TestCase):
    def setUp(self):
        self.events, self.skipped = chronicle.iter_package_events(FIXTURES / "pacman.log")
        self.transactions = [e for e in self.events if e["type"] == "transaction"]

    def test_malformed_lines_are_skipped_and_counted(self):
        # Two deliberately broken lines: one with no bracket structure, one
        # with an unparseable timestamp. Counted, never fatal.
        self.assertEqual(self.skipped, 2)

    def test_old_timestamp_format_is_parsed(self):
        installed = [
            e for e in self.events
            if e["type"] == "package" and e["packages"][0]["name"] == "vim"
        ]
        self.assertEqual(len(installed), 1)
        stamp = datetime.fromisoformat(installed[0]["timestamp"])
        self.assertEqual((stamp.year, stamp.month, stamp.day), (2015, 9, 16))

    def test_new_timestamp_format_is_parsed(self):
        stamp = datetime.fromisoformat(self.transactions[0]["timestamp"])
        self.assertEqual(stamp.year, 2026)
        self.assertIsNotNone(stamp.tzinfo)

    def test_both_formats_appear_in_one_log(self):
        years = {datetime.fromisoformat(e["timestamp"]).year for e in self.events}
        self.assertIn(2015, years)
        self.assertIn(2026, years)

    def test_the_47_package_transaction_is_one_event(self):
        # Grouping is by pacman's own transaction delimiters, not by timestamp
        # proximity, so this is exact rather than a heuristic.
        big = [t for t in self.transactions if len(t["packages"]) == 47]
        self.assertEqual(len(big), 1)
        self.assertEqual(big[0]["counts"]["upgraded"], 47)
        self.assertIn("47 packages upgraded", big[0]["summary"])

    def test_kernel_upgrade_is_named_in_the_summary(self):
        big = [t for t in self.transactions if len(t["packages"]) == 47][0]
        self.assertIn("linux 6.11.4-1 -> 6.11.5-1", big["summary"])

    def test_upgrade_captures_both_versions(self):
        big = [t for t in self.transactions if len(t["packages"]) == 47][0]
        linux = [p for p in big["packages"] if p["name"] == "linux"][0]
        self.assertEqual(linux["old_version"], "6.11.4-1")
        self.assertEqual(linux["new_version"], "6.11.5-1")

    def test_removal_is_captured(self):
        removals = [
            p for e in self.events for p in e["packages"] if p["action"] == "removed"
        ]
        names = {p["name"] for p in removals}
        self.assertIn("nano", names)
        self.assertIn("obsolete-thing", names)

    def test_downgrade_is_captured_with_direction(self):
        downgrades = [
            p for e in self.events for p in e["packages"] if p["action"] == "downgraded"
        ]
        self.assertEqual(len(downgrades), 1)
        mesa = downgrades[0]
        self.assertEqual(mesa["name"], "mesa")
        self.assertEqual(mesa["old_version"], "24.2.0-1")
        self.assertEqual(mesa["new_version"], "24.1.0-1")

    def test_pacman_own_chatter_is_not_counted_as_malformed(self):
        # "Running 'pacman -Syu'", scriptlet output and warnings are real log
        # content that is simply not a package change. Counting them would
        # inflate the skipped figure until it stopped meaning "lines this
        # reader does not understand", which is the only thing it is for.
        chatter = (
            "[2026-08-11T15:00:02+0100] [PACMAN] Running 'pacman -Syu'\n"
            "[2026-08-11T15:00:40+0100] [ALPM-SCRIPTLET] arbitrary script output\n"
            "[2026-08-11T15:00:41+0100] [ALPM-SCRIPTLET] ==> Building initramfs\n"
            "[2026-08-11T15:00:42+0100] [ALPM] warning: /etc/x installed as /etc/x.pacnew\n"
            "[2026-08-11T15:00:43+0100] [PACMAN] Running 'pacman -Q'\n"
        )
        path = pathlib.Path(tempfile.mkdtemp()) / "chatter.log"
        path.write_text(chatter, encoding="utf-8")
        try:
            events, skipped = chronicle.iter_package_events(path)
            self.assertEqual(events, [])
            self.assertEqual(skipped, 0)
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    def test_events_outside_a_transaction_still_recorded(self):
        standalone = [e for e in self.events if e["type"] == "package"]
        self.assertTrue(standalone)

    def test_missing_log_is_empty_not_an_exception(self):
        events, skipped = chronicle.iter_package_events(FIXTURES / "does-not-exist.log")
        self.assertEqual((events, skipped), ([], 0))

    def test_garbage_input_does_not_crash(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "junk.log"
        path.write_text("not a log\n\n\x00\x01\nnope\n", encoding="utf-8")
        events, skipped = chronicle.iter_package_events(path)
        self.assertEqual(events, [])
        self.assertGreater(skipped, 0)
        shutil.rmtree(path.parent, ignore_errors=True)


# --------------------------------------------------- package source support


class TestPackageSourceDetection(TreeCase):
    def test_arch_selects_the_pacman_reader(self):
        name, path, reader = chronicle.detect_package_source()
        self.assertEqual(name, "pacman")
        self.assertEqual(path, chronicle.PACMAN_LOG)
        self.assertIs(reader, chronicle.iter_package_events)

    def test_arch_derivative_via_id_like(self):
        self.write("/etc/os-release", 'ID=cachyos\nID_LIKE="arch"\n')
        self.assertEqual(chronicle.detect_package_source()[0], "pacman")

    def test_debian_is_unsupported_not_empty(self):
        # The distinction the brief exists for: v0.1 cannot read dpkg, and an
        # unsupported source must not look like a quiet one.
        self.write("/etc/os-release", DEBIAN_OS_RELEASE)
        self.assertEqual(chronicle.detect_package_source()[0], None)

    def test_unsupported_distro_reports_skipped_with_a_reason(self):
        self.write("/etc/os-release", DEBIAN_OS_RELEASE)
        self.stub_journal()
        report = chronicle.build_report(Args())
        source = report["sources"]["packages"]
        self.assertEqual(source["status"], "skipped")
        self.assertIn("pacman only", source["detail"])
        self.assertNotIn(source["status"], chronicle.EXIT_STATUSES)

    def test_supported_distro_with_no_log_is_unknown_not_skipped(self):
        # Arch with no pacman.log is a different situation from Debian: the
        # reader applies, the data is missing.
        self.stub_journal()
        report = chronicle.build_report(Args())
        self.assertEqual(report["sources"]["packages"]["status"], "unknown")


# ------------------------------------------------------------ journal access


class TestJournalAccess(TreeCase):
    def test_root_sees_everything(self):
        chronicle.IS_ROOT = True
        self.assertEqual(chronicle.journal_access(), "root")

    def test_group_member_sees_everything(self):
        self.write("/etc/group", "root:x:0:\nsystemd-journal:x:190:dostrom\n")
        self.assertEqual(chronicle.journal_access(), "member")

    def test_adm_group_also_counts(self):
        self.write("/etc/group", "adm:x:4:dostrom,other\n")
        self.assertEqual(chronicle.journal_access(), "member")

    def test_non_member_is_limited(self):
        self.write("/etc/group", "root:x:0:\nsystemd-journal:x:190:someoneelse\n")
        self.assertEqual(chronicle.journal_access(), "limited")

    def test_unreadable_group_file_is_unknown(self):
        (self.root / "etc/group").unlink()
        self.assertEqual(chronicle.journal_access(), "unknown")

    def test_restricted_journal_is_reported_as_partial(self):
        # journalctl does not error for a non-member, it just returns less.
        # Presenting that as a complete timeline is the failure being guarded.
        self.install_pacman_log()
        self.write("/etc/group", "systemd-journal:x:190:someoneelse\n")
        self.stub_journal()
        report = chronicle.build_report(Args())
        journal = report["sources"]["journal"]
        self.assertEqual(journal["status"], "unknown")
        self.assertIn("PARTIAL", journal["detail"])
        partial = [r for r in report["results"] if r["check"] == "journal"]
        self.assertEqual(len(partial), 1)
        self.assertIn("usermod", partial[0]["fix"])

    def test_member_journal_is_not_flagged_partial(self):
        self.install_pacman_log()
        self.write("/etc/group", "systemd-journal:x:190:dostrom\n")
        self.stub_journal()
        report = chronicle.build_report(Args())
        self.assertEqual(report["sources"]["journal"]["status"], "ok")


# ----------------------------------------------------------------- boots


class TestBoots(TreeCase):
    def test_json_boot_list_is_parsed(self):
        self.stub_journal()
        boots, reason = chronicle.read_boots()
        self.assertIsNone(reason)
        self.assertEqual([b["index"] for b in boots], [-2, -1, 0])
        self.assertEqual(boots[-1]["boot_id"], BOOT_C)

    def test_text_boot_list_fallback(self):
        # Older systemd has no --output=json for --list-boots. The text table
        # uses an em dash between timestamps, which the parser has to accept.
        # The separator journalctl writes is U+2014, spelled as an escape so no
        # literal one appears in this repo and so the test says which character
        # it means. A parser matching a plain hyphen instead would stop at the
        # first hyphen inside the date and truncate the timestamp.
        dash = "\u2014"
        text = (
            f"-1 {BOOT_B} Tue 2026-08-12 10:07:00 UTC{dash}Tue 2026-08-12 12:05:00 UTC\n"
            f" 0 {BOOT_C} Tue 2026-08-12 12:35:00 UTC{dash}Tue 2026-08-12 14:20:00 UTC\n"
        )

        def fake(cmd, timeout=60):
            if "--list-boots" in cmd and "--output=json" in cmd:
                return 1, "", "unknown option"
            if "--list-boots" in cmd:
                return 0, text, None
            return None, "", "unavailable"

        chronicle.run = fake
        boots, reason = chronicle.read_boots()
        self.assertIsNone(reason)
        self.assertEqual([b["index"] for b in boots], [-1, 0])

    def test_no_boot_list_reports_a_reason(self):
        chronicle.run = lambda cmd, timeout=60: (1, "", "No journal files were found")
        boots, reason = chronicle.read_boots()
        self.assertEqual(boots, [])
        self.assertIsNotNone(reason)


class TestJournalEvents(unittest.TestCase):
    def setUp(self):
        records = [
            json.loads(line)
            for line in fixture("journal-records.jsonl").splitlines()
            if line.strip()
        ]
        self.failures, self.kernels, self.shutdowns = chronicle.journal_events(records)

    def test_unit_failures_are_extracted_with_their_unit(self):
        self.assertTrue(self.failures)
        units = {f["unit"] for f in self.failures}
        self.assertIn("systemd-modules-load.service", units)

    def test_boot_id_is_the_join_key(self):
        self.assertTrue(all(f["boot_id"] for f in self.failures))
        self.assertEqual({f["boot_id"] for f in self.failures}, {BOOT_C})

    def test_kernel_version_is_read_from_the_banner_per_boot(self):
        self.assertEqual(self.kernels[BOOT_A], "6.11.4-arch1-1")
        self.assertEqual(self.kernels[BOOT_C], "6.11.5-arch1-1")

    def test_clean_shutdown_is_detected(self):
        self.assertIn(BOOT_A, self.shutdowns)
        self.assertNotIn(BOOT_B, self.shutdowns)

    def test_ordinary_messages_are_not_failures(self):
        messages = {f["message"] for f in self.failures}
        self.assertFalse(any("new full-speed USB device" in m for m in messages))


# -------------------------------------------------------------- before-boot


class TestBeforeBoot(TreeCase):
    def boots(self):
        return json.loads(fixture("journal-boots.json"))

    def test_finds_the_most_recent_failed_boot(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(before_boot=True, since="2026-08-01"))
        failed = report["window"]["failed_boot"]
        self.assertEqual(failed["boot_id"], BOOT_C)
        self.assertTrue(failed["reasons"])

    def test_failures_are_restated_as_defining_the_window_not_inside_it(self):
        # The failures happened AT the boot that bounds the window, so they are
        # not events within it. Leaving the ordinary unit-failure finding in
        # place would contradict the timeline it sits above.
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(before_boot=True, since="2026-08-01"))
        checks = {r["check"] for r in report["results"]}
        self.assertNotIn("units", checks)
        finding = [r for r in report["results"] if r["id"] == "before-boot-window"][0]
        self.assertEqual(finding["status"], "warn")
        self.assertIn("systemd-modules-load.service", " ".join(finding["detail"]))
        end = datetime.fromisoformat(report["window"]["end"]).timestamp()
        self.assertTrue(all(e["epoch"] <= end for e in report["events"]))

    def test_before_boot_still_exits_one(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(before_boot=True, since="2026-08-01"))
        self.assertEqual(report["exit_code"], chronicle.FOUND_SOMETHING)

    def test_window_ends_at_the_failed_boot(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(before_boot=True, since="2026-08-01"))
        end = datetime.fromisoformat(report["window"]["end"]).timestamp()
        self.assertAlmostEqual(end, 1786554900, delta=1)
        self.assertTrue(all(e["epoch"] <= end for e in report["events"]))

    def test_unclean_shutdown_also_marks_a_boot_as_failed(self):
        # Boot B recorded no clean shutdown, so boot C counts as failed on that
        # ground even with no unit failure of its own.
        boots = json.loads(fixture("journal-boots.json"))
        failures = []
        shutdowns = {BOOT_A}
        boot, reasons = chronicle.find_last_failed_boot(
            [
                {
                    "index": b["index"],
                    "boot_id": b["boot_id"],
                    "first_epoch": b["first_entry"] / 1e6,
                    "last_epoch": b["last_entry"] / 1e6,
                }
                for b in boots
            ],
            failures,
            shutdowns,
        )
        self.assertEqual(boot["boot_id"], BOOT_C)
        self.assertIn("no clean shutdown", " ".join(reasons))

    def test_no_failed_boot_exits_two_and_does_not_substitute_a_window(self):
        self.install_pacman_log()
        self.stub_journal(records=fixture("journal-clean.jsonl"))
        report = chronicle.build_report(Args(before_boot=True, since="2026-08-12T12:00"))
        self.assertEqual(report["error"], "no-failed-boot")
        self.assertEqual(report["exit_code"], chronicle.COULD_NOT_DETERMINE)
        result = [r for r in report["results"] if r["check"] == "before-boot"][0]
        self.assertIn("deliberately NOT substituted", " ".join(result["detail"]))


# ------------------------------------------------------------ rollback hints


class TestRollbackHints(TreeCase):
    def transactions(self):
        events, _ = chronicle.iter_package_events(FIXTURES / "pacman.log")
        return [e for e in events if e["type"] == "transaction"]

    def test_cached_previous_version_is_found(self):
        self.write(
            f"{chronicle.PACMAN_CACHE}/linux-6.11.4-1-x86_64.pkg.tar.zst", "binary"
        )
        hints = chronicle.rollback_hints(self.transactions())
        linux = [h for h in hints if h["name"] == "linux"][0]
        self.assertTrue(linux["available"])
        self.assertIn("linux-6.11.4-1-x86_64.pkg.tar.zst", linux["cache_file"])

    def test_missing_cache_file_is_reported_as_missing(self):
        # paccache may have cleared it. Naming a file that is not there is
        # worse than saying it is gone.
        hints = chronicle.rollback_hints(self.transactions())
        linux = [h for h in hints if h["name"] == "linux"][0]
        self.assertFalse(linux["available"])
        self.assertIsNone(linux["cache_file"])

    def test_only_upgrades_and_downgrades_are_candidates(self):
        hints = chronicle.rollback_hints(self.transactions())
        names = {h["name"] for h in hints}
        self.assertIn("mesa", names)
        self.assertNotIn("obsolete-thing", names)
        self.assertNotIn("ripgrep", names)

    def test_hints_are_not_produced_unless_asked(self):
        self.install_pacman_log()
        self.stub_journal()
        self.assertEqual(chronicle.build_report(Args())["rollback_hints"], [])
        report = chronicle.build_report(Args(rollback_hint=True, since="2026-08-01"))
        self.assertTrue(report["rollback_hints"])


# ----------------------------------------------------------------- /etc walk


class TestEtcWalk(TreeCase):
    def test_file_in_window_is_reported(self):
        stamp = FIXED_NOW.timestamp() - 3600
        self.write("/etc/ssh/sshd_config", "x", mtime=stamp)
        events, _ = chronicle.walk_etc((FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), [])
        paths = {e["path"] for e in events}
        self.assertIn("/etc/ssh/sshd_config", paths)

    def test_file_outside_window_is_not_reported(self):
        self.write("/etc/old.conf", "x", mtime=FIXED_NOW.timestamp() - 999999)
        events, _ = chronicle.walk_etc((FIXED_NOW.timestamp() - 3600, FIXED_NOW.timestamp()), [])
        self.assertNotIn("/etc/old.conf", {e["path"] for e in events})

    def test_mtime_inside_a_transaction_is_marked_package_originated(self):
        # Most /etc changes during an upgrade are the upgrade rewriting config,
        # not a human editing it. Listing those as independent events would
        # bury the one edit that actually was a human.
        start = FIXED_NOW.timestamp() - 7200
        transaction = {
            "type": "transaction",
            "epoch": start,
            "end_epoch": start + 60,
            "packages": [],
        }
        self.write("/etc/mkinitcpio.conf", "x", mtime=start + 30)
        self.write("/etc/hand-edited.conf", "x", mtime=start + 4000)
        events, _ = chronicle.walk_etc(
            (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), [transaction]
        )
        by_path = {e["path"]: e for e in events}
        self.assertTrue(by_path["/etc/mkinitcpio.conf"]["package_originated"])
        self.assertFalse(by_path["/etc/hand-edited.conf"]["package_originated"])

    def test_pacnew_gets_its_own_type_and_is_never_package_originated(self):
        start = FIXED_NOW.timestamp() - 7200
        transaction = {
            "type": "transaction",
            "epoch": start,
            "end_epoch": start + 60,
            "packages": [],
        }
        self.write("/etc/pacman.conf.pacnew", "x", mtime=start + 30)
        events, _ = chronicle.walk_etc(
            (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), [transaction]
        )
        entry = [e for e in events if e["path"].endswith(".pacnew")][0]
        self.assertEqual(entry["type"], "pacnew")
        self.assertFalse(entry["package_originated"])

    def test_pacsave_is_treated_the_same_as_pacnew(self):
        self.write("/etc/thing.conf.pacsave", "x", mtime=FIXED_NOW.timestamp() - 60)
        events, _ = chronicle.walk_etc(
            (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), []
        )
        self.assertEqual([e["type"] for e in events if "pacsave" in e["path"]], ["pacnew"])

    def test_mtime_just_after_a_transaction_is_still_package_originated(self):
        # Package install scripts run after the last log line, so a config
        # rewritten seconds after "transaction completed" is still the upgrade
        # doing it. The slack window is what covers that tail.
        start = FIXED_NOW.timestamp() - 7200
        transaction = {
            "type": "transaction",
            "epoch": start,
            "end_epoch": start + 60,
            "packages": [],
        }
        inside = start + 60 + (chronicle.TRANSACTION_ETC_SLACK_S / 2)
        outside = start + 60 + (chronicle.TRANSACTION_ETC_SLACK_S * 3)
        self.write("/etc/in-tail.conf", "x", mtime=inside)
        self.write("/etc/well-after.conf", "x", mtime=outside)
        events, _ = chronicle.walk_etc(
            (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), [transaction]
        )
        by_path = {e["path"]: e for e in events}
        self.assertTrue(by_path["/etc/in-tail.conf"]["package_originated"])
        self.assertFalse(by_path["/etc/well-after.conf"]["package_originated"])

    def test_walk_truncates_rather_than_hanging_on_a_huge_tree(self):
        saved = chronicle.ETC_WALK_LIMIT
        try:
            chronicle.ETC_WALK_LIMIT = 5
            for index in range(20):
                self.write(f"/etc/many/{index}.conf", "x", mtime=FIXED_NOW.timestamp() - 60)
            events, truncated = chronicle.walk_etc(
                (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), []
            )
            self.assertTrue(truncated)
            self.assertLessEqual(len(events), chronicle.ETC_WALK_LIMIT)
        finally:
            chronicle.ETC_WALK_LIMIT = saved

    def test_a_small_tree_is_not_reported_as_truncated(self):
        self.write("/etc/one.conf", "x", mtime=FIXED_NOW.timestamp() - 60)
        _, truncated = chronicle.walk_etc(
            (FIXED_NOW.timestamp() - 86400, FIXED_NOW.timestamp()), []
        )
        self.assertFalse(truncated)

    def test_pacnew_raises_a_finding(self):
        self.install_pacman_log()
        self.stub_journal()
        self.write("/etc/pacman.conf.pacnew", "x", mtime=FIXED_NOW.timestamp() - 60)
        report = chronicle.build_report(Args())
        pacnew = [r for r in report["results"] if r["check"] == "pacnew"]
        self.assertEqual(len(pacnew), 1)
        self.assertEqual(pacnew[0]["status"], "warn")
        self.assertEqual(pacnew[0]["fix"], "pacdiff")


# ---------------------------------------------------------- systemd absence


class TestWithoutSystemd(TreeCase):
    def test_journal_is_skipped_but_packages_still_work(self):
        # The decomposition freshcheck established: gate on systemd presence,
        # not distro identity. Losing the journal must not lose the package
        # timeline as well.
        self.install_pacman_log()
        self.stub_journal(systemd=False)
        report = chronicle.build_report(Args(since="2026-08-01"))
        self.assertEqual(report["sources"]["journal"]["status"], "skipped")
        self.assertEqual(report["sources"]["packages"]["status"], "ok")
        transactions = [e for e in report["events"] if e["type"] == "transaction"]
        self.assertTrue(transactions)

    def test_skipped_journal_is_not_a_failure(self):
        self.install_pacman_log()
        self.stub_journal(systemd=False)
        report = chronicle.build_report(Args(since="2026-08-01"))
        self.assertNotIn(report["sources"]["journal"]["status"], chronicle.EXIT_STATUSES)


# ------------------------------------------------------------- exit codes


class TestExitCodes(TreeCase):
    def test_failed_units_in_window_exit_one(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        self.assertEqual(report["exit_code"], chronicle.FOUND_SOMETHING)

    def test_clean_window_with_all_sources_exits_zero(self):
        self.install_pacman_log()
        self.write("/etc/group", "systemd-journal:x:190:dostrom\n")
        self.stub_journal(records=fixture("journal-clean.jsonl"))
        report = chronicle.build_report(Args(since="2026-08-12T13:00"))
        self.assertEqual(report["counts"]["warn"], 0)
        self.assertEqual(report["counts"]["fail"], 0)
        self.assertEqual(report["exit_code"], chronicle.NOTHING_FOUND)

    def test_degraded_source_with_nothing_found_exits_two(self):
        # Nothing found, but not everything could be looked at. Exiting 0 would
        # claim a clean window that was never fully examined.
        self.write("/etc/os-release", DEBIAN_OS_RELEASE)
        self.write("/etc/group", "systemd-journal:x:190:dostrom\n")
        self.stub_journal(records=fixture("journal-clean.jsonl"))
        report = chronicle.build_report(Args(since="2026-08-12T13:00"))
        self.assertEqual(report["exit_code"], chronicle.COULD_NOT_DETERMINE)

    def test_finding_something_outranks_a_degraded_source(self):
        # A partial timeline that still surfaced a failure is a positive
        # result, not an inconclusive one.
        self.write("/etc/os-release", DEBIAN_OS_RELEASE)
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        self.assertEqual(report["sources"]["packages"]["status"], "skipped")
        self.assertEqual(report["exit_code"], chronicle.FOUND_SOMETHING)

    def test_unparseable_window_exits_two(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="last tuesday"))
        self.assertEqual(report["error"], "bad-window")
        self.assertEqual(report["exit_code"], chronicle.COULD_NOT_DETERMINE)

    def test_until_before_since_exits_two(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-10", until="2026-08-01"))
        self.assertEqual(report["exit_code"], chronicle.COULD_NOT_DETERMINE)

    def test_unknown_boot_index_exits_two(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(boot=-99))
        self.assertEqual(report["exit_code"], chronicle.COULD_NOT_DETERMINE)

    def test_not_linux_exits_two(self):
        chronicle.PLATFORM = "win32"
        self.assertEqual(chronicle.build_report(Args())["exit_code"], chronicle.COULD_NOT_DETERMINE)


class TestDefaultWindow(TreeCase):
    def test_default_window_is_seven_days(self):
        # The literal is deliberate. Comparing the measured span against
        # DEFAULT_WINDOW_DAYS would be self-referential: it would pass for any
        # value of the constant and pin nothing at all. Changing the default is
        # a decision, and it should have to change this line and the README.
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args())
        start = datetime.fromisoformat(report["window"]["start"])
        self.assertEqual((FIXED_NOW - start).days, 7)
        self.assertIn("last 7 days", report["window"]["label"])

    def test_explicit_since_overrides_the_default(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2 days ago"))
        start = datetime.fromisoformat(report["window"]["start"])
        self.assertEqual((FIXED_NOW - start).days, 2)


class TestBootScoping(TreeCase):
    def test_boot_index_scopes_the_window(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(boot=-1))
        start = datetime.fromisoformat(report["window"]["start"]).timestamp()
        end = datetime.fromisoformat(report["window"]["end"]).timestamp()
        self.assertAlmostEqual(start, 1786546020, delta=1)
        self.assertAlmostEqual(end, 1786553100, delta=1)
        self.assertEqual(report["window"]["label"], "boot -1")


# ------------------------------------------------ adjacency, not causation


class TestAdjacencyDiscipline(TreeCase):
    """The contract: events are ordered and labelled, and that is all."""

    def test_no_causal_fields_in_the_schema(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        blob = json.dumps(report, default=str)
        payload = json.loads(blob)

        def keys(node):
            found = set()
            if isinstance(node, dict):
                for key, value in node.items():
                    found.add(key.lower())
                    found |= keys(value)
            elif isinstance(node, list):
                for item in node:
                    found |= keys(item)
            return found

        forbidden = {"cause", "caused_by", "likely_cause", "suspect", "suspects",
                     "culprit", "blame", "confidence", "probability"}
        self.assertEqual(keys(payload) & forbidden, set())

    def test_output_states_that_adjacency_is_not_causation(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            chronicle.render(chronicle.Out(color=False), report)
        text = buffer.getvalue().lower()
        self.assertIn("adjacency", text)
        self.assertIn("does not assign cause", text.replace("\n", " "))

    def test_output_points_at_portwatch_for_the_other_axis(self):
        # The reference is mutual: portwatch names chronicle in turn.
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            chronicle.render(chronicle.Out(color=False), report)
        self.assertIn("portwatch", buffer.getvalue())

    def test_unit_failure_finding_does_not_name_a_culprit(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        units = [r for r in report["results"] if r["check"] == "units"][0]
        joined = " ".join(units["detail"]).lower()
        self.assertIn("nothing more", joined)
        for word in ("caused", "because of", "due to", "responsible"):
            self.assertNotIn(word, joined)


# ---------------------------------------------------------- render and json


class TestRenderAndJson(TreeCase):
    def render_text(self, report):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            chronicle.render(chronicle.Out(color=False), report)
        return buffer.getvalue()

    def test_timeline_groups_by_day_and_marks_boots(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        text = self.render_text(report)
        self.assertIn("BOOT", text)
        self.assertIn("FAIL", text)
        self.assertIn("2026-08-11", text)

    def test_transactions_collapse_unless_verbose(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        collapsed = self.render_text(report)
        self.assertIn("47 packages upgraded", collapsed)
        self.assertNotIn("libassuan", collapsed)

        report["_verbose"] = True
        expanded = self.render_text(report)
        self.assertIn("libassuan", expanded)

    def test_skipped_source_never_renders_as_ok(self):
        self.write("/etc/os-release", DEBIAN_OS_RELEASE)
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        text = self.render_text(report)
        self.assertIn("[skip]", text)
        self.assertNotIn("[ ok ] packages", text)

    def test_json_is_valid_and_events_are_ordered(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(since="2026-08-01"))
        payload = json.loads(json.dumps(report, default=str))
        epochs = [e["epoch"] for e in payload["events"]]
        self.assertEqual(epochs, sorted(epochs))
        for event in payload["events"]:
            for key in ("timestamp", "source", "type", "epoch"):
                self.assertIn(key, event)

    def test_json_event_sources_are_from_the_documented_set(self):
        self.install_pacman_log()
        self.stub_journal()
        self.write("/etc/some.conf", "x", mtime=FIXED_NOW.timestamp() - 60)
        report = chronicle.build_report(Args(since="2026-08-01"))
        sources = {e["source"] for e in report["events"]}
        self.assertTrue(sources <= {"pacman", "journal", "etc"}, sources)
        types = {e["type"] for e in report["events"]}
        self.assertTrue(
            types <= {"transaction", "package", "boot", "unit-failure", "config-change", "pacnew"},
            types,
        )

    def test_rollback_output_never_runs_anything(self):
        self.install_pacman_log()
        self.write(f"{chronicle.PACMAN_CACHE}/linux-6.11.4-1-x86_64.pkg.tar.zst", "b")
        self.stub_journal()
        report = chronicle.build_report(Args(rollback_hint=True, since="2026-08-01"))
        text = self.render_text(report)
        self.assertIn("pacman -U", text)
        self.assertIn("chronicle never will", text)

    def test_rollback_missing_cache_is_stated(self):
        self.install_pacman_log()
        self.stub_journal()
        report = chronicle.build_report(Args(rollback_hint=True, since="2026-08-01"))
        text = self.render_text(report)
        self.assertIn("no cached previous version", text)
        self.assertIn("paccache", text)


class TestEncodingSafety(unittest.TestCase):
    def setUp(self):
        self.real = sys.stdout

    def tearDown(self):
        sys.stdout = self.real

    def test_ascii_console_escapes_rather_than_crashing(self):
        class Fake:
            encoding = "ascii"

            def write(self, text):
                pass

            def flush(self):
                pass

            def isatty(self):
                return False

        sys.stdout = Fake()
        self.assertEqual(chronicle.safe_text("naïve"), "na\\xefve")
        self.assertEqual(chronicle.rule_char(), "-")


if __name__ == "__main__":
    unittest.main(verbosity=2)
