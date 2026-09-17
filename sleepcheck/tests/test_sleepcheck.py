#!/usr/bin/env python3
"""Tests for sleepcheck. Command and system reads are replaced at the seam."""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import sleepcheck  # noqa: E402


class SeamCase(unittest.TestCase):
    def setUp(self):
        self.saved = (sleepcheck.read_text, sleepcheck.effective_config, sleepcheck.run)
        sleepcheck.run = lambda cmd, timeout=20: (0, "No inhibitors listed.\n", None)

    def tearDown(self):
        sleepcheck.read_text, sleepcheck.effective_config, sleepcheck.run = self.saved

    @staticmethod
    def context():
        return {"systemd": True}


class TestParsers(unittest.TestCase):
    def test_mem_sleep_brackets_mark_selected(self):
        self.assertEqual(sleepcheck.parse_mem_sleep("s2idle [deep]"), (["s2idle", "deep"], "deep"))

    def test_inhibitor_parser_keeps_stable_ends(self):
        locks = sleepcheck.parse_inhibitors("WHO            WHAT  WHY       MODE\nplayer         sleep  Playing   block\n")
        self.assertEqual(locks[0]["who"], "player")
        self.assertEqual(locks[0]["mode"], "block")

    def test_wake_parser_does_not_mark_disabled_enabled(self):
        rows = sleepcheck.parse_acpi_wakeup("Device  S-state   Status\nXHC  S3  *enabled\nRP01 S4 *disabled\n")
        self.assertEqual(rows, [{"device": "XHC", "enabled": True}, {"device": "RP01", "enabled": False}])

    def test_config_uses_last_value(self):
        values = sleepcheck.parse_config("AllowSuspend=no\nAllowSuspend=yes\n")
        self.assertEqual(values["AllowSuspend"], "yes")


class TestChecks(SeamCase):
    def test_no_mem_state_is_warning_not_pass(self):
        sleepcheck.read_text = lambda path: "freeze disk\n" if path == "/sys/power/state" else None
        results = sleepcheck.check_states(self.context())
        self.assertEqual(results[0]["status"], "warn")

    def test_effective_enabled_policy_is_pass(self):
        sleepcheck.effective_config = lambda name: (({"AllowSuspend": "yes"}, ["/etc/systemd/sleep.conf"])
                                                    if name == "sleep.conf" else ({}, []))
        result = sleepcheck.check_policy(self.context())[0]
        self.assertEqual(result["status"], "ok")

    def test_nonblocking_lock_is_not_a_sleep_blocker(self):
        sleepcheck.run = lambda cmd, timeout=20: (0, "backup  sleep  checkpointing  delay\n", None)
        result = sleepcheck.check_inhibitors(self.context())
        self.assertEqual(result["status"], "ok")

    def test_enabled_wake_source_is_information_not_warning(self):
        sleepcheck.read_text = lambda path: "Device S-state Status\nXHC S3 *enabled\n" if path == "/proc/acpi/wakeup" else None
        result = sleepcheck.check_wake(self.context())
        self.assertEqual(result["status"], "info")

    def test_journal_command_failure_is_unknown(self):
        sleepcheck.run = lambda cmd, timeout=20: (1, "", "Permission denied")
        result = sleepcheck.check_journal(self.context())
        self.assertEqual(result["status"], "unknown")

    def test_one_malformed_journal_line_does_not_erase_event(self):
        sleepcheck.run = lambda cmd, timeout=20: (0, "bad json\n{\"MESSAGE\": \"Suspending system\"}\n", None)
        result = sleepcheck.check_journal(self.context())
        self.assertEqual(result["status"], "info")
        self.assertIn("1 sleep-service", result["summary"])


if __name__ == "__main__":
    unittest.main()
