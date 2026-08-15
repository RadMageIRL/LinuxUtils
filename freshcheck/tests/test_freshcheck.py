#!/usr/bin/env python3
"""
Tests for freshcheck.

    python3 -m unittest discover -s freshcheck/tests -t freshcheck/tests -v
    ./freshcheck/tests/test_freshcheck.py

Standard library only, same rule as the tools.

Every check reads the system through sysp() and run(), so each test builds a
synthetic /proc, /sys and /etc tree in a tempdir, points SYSROOT at it, and
stubs run(). That makes every path reachable without root and without a real
machine sitting in a broken state.

The cases that matter most here are the ones where a naive implementation
reports the OPPOSITE of the truth: powersave-with-performance-EPP is correct
rather than a problem, high swappiness is correct on zram, a restricted dmesg
is unknown rather than a failure, and a skipped check is never a pass.
"""

import contextlib
import io
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import freshcheck  # noqa: E402

ARCH = {"id": "arch", "id_like": [], "pretty_name": "Arch Linux"}


def ctx(distro=None, systemd=True):
    return {"distro": distro or ARCH, "systemd": systemd}


class TreeCase(unittest.TestCase):
    """Base: builds a synthetic system tree and restores the module seams."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="freshcheck-test-"))
        self._saved = (
            freshcheck.SYSROOT,
            freshcheck.RUNNING_KERNEL,
            freshcheck.IS_ROOT,
            freshcheck.PLATFORM,
            freshcheck.run,
            freshcheck.disk_usage,
        )
        freshcheck.SYSROOT = self.root
        freshcheck.IS_ROOT = False
        freshcheck.PLATFORM = "linux"
        freshcheck.run = lambda cmd, timeout=20: (None, "", "stubbed: not available")

    def tearDown(self):
        (
            freshcheck.SYSROOT,
            freshcheck.RUNNING_KERNEL,
            freshcheck.IS_ROOT,
            freshcheck.PLATFORM,
            freshcheck.run,
            freshcheck.disk_usage,
        ) = self._saved
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, path, content):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def mkdir(self, path):
        (self.root / path.lstrip("/")).mkdir(parents=True, exist_ok=True)

    def stub_run(self, table):
        """Stub run() from {command-prefix-string: (rc, stdout)}."""

        def fake(cmd, timeout=20):
            joined = " ".join(cmd)
            for prefix, (rc, out) in table.items():
                if joined.startswith(prefix):
                    return rc, out, None
            return None, "", f"stubbed: {joined} unavailable"

        freshcheck.run = fake


# ------------------------------------------------------------------ helpers


class TestHelpers(unittest.TestCase):
    def test_version_key_orders_numerically(self):
        # The whole point: a string compare puts 6.9 above 6.10, which would
        # invert the reboot-pending verdict on every kernel update past .9.
        self.assertGreater(
            freshcheck.version_key("6.10.1-arch1-1"), freshcheck.version_key("6.9.7-arch1-1")
        )
        self.assertGreater(
            freshcheck.version_key("6.9.7-arch1-1"), freshcheck.version_key("6.9.6-arch1-1")
        )

    def test_version_key_release_beats_rc(self):
        self.assertGreater(
            freshcheck.version_key("6.10.0"), freshcheck.version_key("6.10.0-rc1")
        )

    def test_parse_size(self):
        self.assertEqual(freshcheck.parse_size("500M"), 500 * 1024**2)
        self.assertEqual(freshcheck.parse_size("1G"), 1024**3)
        self.assertEqual(freshcheck.parse_size("4096"), 4096)
        self.assertIsNone(freshcheck.parse_size("not a size"))
        self.assertIsNone(freshcheck.parse_size(None))

    def test_parse_kv_file_strips_quotes(self):
        values = freshcheck.parse_kv_file('ID=arch\nPRETTY_NAME="Arch Linux"\n# comment\n')
        self.assertEqual(values["ID"], "arch")
        self.assertEqual(values["PRETTY_NAME"], "Arch Linux")

    def test_package_family_falls_back_to_id_like(self):
        template, packages = freshcheck.package_family(
            {"id": "cachyos", "id_like": ["arch"]}
        )
        self.assertIn("pacman", template)
        self.assertEqual(packages["amd"], "amd-ucode")

    def test_unknown_distro_yields_no_hint(self):
        self.assertIsNone(
            freshcheck.microcode_hint({"id": "plan9", "id_like": []}, "amd")
        )


# ------------------------------------------------------------------- kernel


class TestKernel(TreeCase):
    def test_running_kernel_modules_missing_is_a_failure(self):
        # The degraded case: an update deleted the running kernel's modules.
        freshcheck.RUNNING_KERNEL = "6.9.7-arch1-1"
        self.mkdir("/usr/lib/modules/6.10.1-arch1-1")
        results = freshcheck.check_kernel(ctx())
        modules = [r for r in results if r["id"] == "kernel-modules"][0]
        self.assertEqual(modules["status"], "fail")
        self.assertIn("6.9.7-arch1-1", modules["summary"])
        self.assertEqual(modules["fix"], "sudo reboot")

    def test_reboot_pending_is_separate_and_lower_severity(self):
        # The routine case: newer kernel installed, running one still intact.
        # These are different severities and must not be collapsed.
        freshcheck.RUNNING_KERNEL = "6.9.7-arch1-1"
        self.mkdir("/usr/lib/modules/6.9.7-arch1-1")
        self.mkdir("/usr/lib/modules/6.10.1-arch1-1")
        results = freshcheck.check_kernel(ctx())
        statuses = {r["id"]: r["status"] for r in results}
        self.assertEqual(statuses["kernel-modules"], "ok")
        self.assertEqual(statuses["kernel-reboot-pending"], "warn")

    def test_clean_system_is_ok_with_no_reboot_notice(self):
        freshcheck.RUNNING_KERNEL = "6.10.1-arch1-1"
        self.mkdir("/usr/lib/modules/6.10.1-arch1-1")
        results = freshcheck.check_kernel(ctx())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "ok")

    def test_lib_modules_layout_is_found(self):
        # Distros that use /lib/modules directly rather than Arch's
        # /usr/lib/modules must not be reported as having no modules at all.
        freshcheck.RUNNING_KERNEL = "6.1.0-18-amd64"
        self.mkdir("/lib/modules/6.1.0-18-amd64")
        results = freshcheck.check_kernel(ctx())
        self.assertEqual(results[0]["status"], "ok")

    def test_both_paths_present_does_not_double_report(self):
        freshcheck.RUNNING_KERNEL = "6.10.1-arch1-1"
        self.mkdir("/usr/lib/modules/6.10.1-arch1-1")
        self.mkdir("/lib/modules/6.10.1-arch1-1")
        results = freshcheck.check_kernel(ctx())
        self.assertEqual(len([r for r in results if r["id"] == "kernel-modules"]), 1)
        self.assertEqual(results[0]["status"], "ok")

    def test_no_module_tree_is_unknown_not_a_failure(self):
        freshcheck.RUNNING_KERNEL = "6.10.1-arch1-1"
        result = freshcheck.check_kernel(ctx())
        self.assertEqual(result["status"], "unknown")


# ---------------------------------------------------------------- microcode


class TestMicrocode(TreeCase):
    def setUp(self):
        super().setUp()
        self.write("/proc/cpuinfo", "vendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 9 9900X\n")
        self.write("/sys/devices/system/cpu/cpu0/microcode/version", "0xb404023\n")

    def test_restricted_dmesg_unprivileged_is_unknown(self):
        # The distinction this check exists for: not being ALLOWED to look is
        # not the same as looking and finding nothing.
        self.write("/proc/sys/kernel/dmesg_restrict", "1\n")
        freshcheck.IS_ROOT = False
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["status"], "unknown")
        self.assertIn("restricted", result["summary"].lower())

    def test_loaded_microcode_is_ok(self):
        self.write("/proc/sys/kernel/dmesg_restrict", "0\n")
        self.stub_run({"dmesg": (0, "[    0.000000] microcode: Current revision: 0x0b404023\n")})
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["status"], "ok")

    def test_no_microcode_line_warns_with_a_distro_specific_fix(self):
        self.write("/proc/sys/kernel/dmesg_restrict", "0\n")
        self.stub_run({"dmesg": (0, "[    0.000000] Linux version 6.10.1\n")})
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["fix"], "sudo pacman -S amd-ucode")

    def test_intel_gets_the_intel_package(self):
        self.write("/proc/cpuinfo", "vendor_id\t: GenuineIntel\n")
        self.write("/proc/sys/kernel/dmesg_restrict", "0\n")
        self.stub_run({"dmesg": (0, "nothing relevant\n")})
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["fix"], "sudo pacman -S intel-ucode")

    def test_missing_sysfs_version_is_unknown(self):
        (self.root / "sys/devices/system/cpu/cpu0/microcode/version").unlink()
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["status"], "unknown")

    def test_restricted_dmesg_as_root_still_reads(self):
        self.write("/proc/sys/kernel/dmesg_restrict", "1\n")
        freshcheck.IS_ROOT = True
        self.stub_run({"dmesg": (0, "microcode: updated early\n")})
        result = freshcheck.check_microcode(ctx())
        self.assertEqual(result["status"], "ok")


# --------------------------------------------------------------------- trim


class TestTrim(TreeCase):
    def test_rotational_only_is_skipped_not_failed(self):
        # A spinning-rust machine has nothing to trim. Reporting that as a
        # failure would be noise; reporting it as ok would be a false pass.
        self.write("/sys/block/sda/queue/rotational", "1\n")
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "skipped")

    def test_zram_does_not_count_as_an_ssd(self):
        # zram reports non-rotational. Counting it would invent an SSD on a
        # machine that has none.
        self.write("/sys/block/zram0/queue/rotational", "0\n")
        self.write("/sys/block/sda/queue/rotational", "1\n")
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "skipped")

    def test_timer_enabled_is_ok(self):
        self.write("/sys/block/nvme0n1/queue/rotational", "0\n")
        self.write("/etc/fstab", "UUID=abc / ext4 defaults 0 1\n")
        self.stub_run(
            {
                "systemd-detect-virt": (0, "none\n"),
                "systemctl is-enabled fstrim.timer": (0, "enabled\n"),
            }
        )
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "ok")

    def test_discard_plus_timer_is_a_warning_not_a_failure(self):
        self.write("/sys/block/nvme0n1/queue/rotational", "0\n")
        self.write("/etc/fstab", "UUID=abc / ext4 defaults,discard,noatime 0 1\n")
        self.stub_run(
            {
                "systemd-detect-virt": (0, "none\n"),
                "systemctl is-enabled fstrim.timer": (0, "enabled\n"),
            }
        )
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("edundant", " ".join(result["detail"]))

    def test_no_trim_at_all_warns(self):
        self.write("/sys/block/nvme0n1/queue/rotational", "0\n")
        self.write("/etc/fstab", "UUID=abc / ext4 defaults 0 1\n")
        self.stub_run(
            {
                "systemd-detect-virt": (0, "none\n"),
                "systemctl is-enabled fstrim.timer": (1, "disabled\n"),
            }
        )
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["fix"], "sudo systemctl enable --now fstrim.timer")

    def test_virtual_machine_is_skipped(self):
        self.write("/sys/block/vda/queue/rotational", "0\n")
        self.stub_run({"systemd-detect-virt": (0, "kvm\n")})
        result = freshcheck.check_trim(ctx())
        self.assertEqual(result["status"], "skipped")
        self.assertIn("kvm", result["summary"])


# ------------------------------------------------------------------ journal


class TestJournal(TreeCase):
    def test_cap_in_a_dropin_is_found(self):
        # Reading only journald.conf is the common bug: it misreports a
        # correctly configured system as having no cap at all.
        self.write("/etc/systemd/journald.conf", "[Journal]\n#SystemMaxUse=\n")
        self.write("/etc/systemd/journald.conf.d/00-size.conf", "[Journal]\nSystemMaxUse=500M\n")
        result = freshcheck.check_journal(ctx())
        self.assertEqual(result["status"], "ok")
        self.assertIn("500M", result["summary"])
        self.assertIn("00-size.conf", " ".join(result["detail"]))

    def test_dropin_overrides_the_main_file(self):
        self.write("/etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=4G\n")
        self.write("/etc/systemd/journald.conf.d/99-smaller.conf", "[Journal]\nSystemMaxUse=200M\n")
        result = freshcheck.check_journal(ctx())
        self.assertIn("200M", result["summary"])

    def test_commented_setting_is_not_treated_as_configured(self):
        self.write("/etc/systemd/journald.conf", "[Journal]\n#SystemMaxUse=4G\n")
        result = freshcheck.check_journal(ctx())
        self.assertIn("no explicit cap", result["summary"])

    def test_large_uncapped_journal_warns(self):
        # Lower the threshold rather than writing a real gigabyte to disk.
        saved = freshcheck.JOURNAL_WARN_BYTES
        try:
            freshcheck.JOURNAL_WARN_BYTES = 1024
            self.write("/etc/systemd/journald.conf", "[Journal]\n")
            directory = self.root / "var/log/journal/machine"
            directory.mkdir(parents=True)
            (directory / "system.journal").write_bytes(b"x" * 4096)
            result = freshcheck.check_journal(ctx())
            self.assertEqual(result["status"], "warn")
            self.assertIn("SystemMaxUse", result["fix"])
        finally:
            freshcheck.JOURNAL_WARN_BYTES = saved

    def test_small_uncapped_journal_is_not_a_warning(self):
        self.write("/etc/systemd/journald.conf", "[Journal]\n")
        directory = self.root / "var/log/journal/machine"
        directory.mkdir(parents=True)
        (directory / "system.journal").write_bytes(b"x" * 4096)
        result = freshcheck.check_journal(ctx())
        self.assertEqual(result["status"], "ok")

    def test_journal_usage_is_summed(self):
        self.write("/etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=500M\n")
        directory = self.root / "var/log/journal/machine"
        directory.mkdir(parents=True)
        (directory / "a.journal").write_bytes(b"x" * 2048)
        (directory / "b.journal").write_bytes(b"x" * 2048)
        result = freshcheck.check_journal(ctx())
        self.assertIn("4.0 KiB", " ".join(result["detail"]))


# --------------------------------------------------------------------- swap


class TestSwap(TreeCase):
    def setUp(self):
        super().setUp()
        self.write("/proc/meminfo", "MemTotal:       32768000 kB\n")

    def test_zram_with_high_swappiness_is_correct(self):
        # The case a naive tool gets backwards. zram compresses into RAM, so
        # swapping is cheap and 180 is the recommended value, not a fault.
        self.write("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0\tpartition\t8388608\t0\t100\n")
        self.write("/proc/sys/vm/swappiness", "180\n")
        self.mkdir("/sys/block/zram0")
        result = freshcheck.check_swap(ctx())
        self.assertEqual(result["status"], "ok")
        self.assertIn("180", result["summary"])

    def test_zram_with_default_swappiness_warns(self):
        self.write("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0\tpartition\t8388608\t0\t100\n")
        self.write("/proc/sys/vm/swappiness", "60\n")
        self.mkdir("/sys/block/zram0")
        result = freshcheck.check_swap(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("180", result["fix"])

    def test_disk_swap_with_zram_tuning_warns(self):
        self.write("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t8388608\t0\t-2\n")
        self.write("/proc/sys/vm/swappiness", "180\n")
        result = freshcheck.check_swap(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("60", result["fix"])

    def test_disk_swap_with_default_swappiness_is_ok(self):
        self.write("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t8388608\t0\t-2\n")
        self.write("/proc/sys/vm/swappiness", "60\n")
        result = freshcheck.check_swap(ctx())
        self.assertEqual(result["status"], "ok")

    def test_no_swap_warns(self):
        self.write("/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n")
        self.write("/proc/sys/vm/swappiness", "60\n")
        result = freshcheck.check_swap(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("No swap", result["summary"])


# ---------------------------------------------------------------------- cpu


class TestCpu(TreeCase):
    def cpufreq(self, **values):
        for name, value in values.items():
            self.write(f"/sys/devices/system/cpu/cpu0/cpufreq/{name}", f"{value}\n")

    def test_amd_pstate_epp_powersave_with_performance_epp_is_ok(self):
        # The headline case. This is the CORRECT configuration on a current
        # Ryzen, and flagging it would teach the user to distrust the tool.
        self.cpufreq(
            scaling_driver="amd_pstate-epp",
            scaling_governor="powersave",
            energy_performance_preference="performance",
        )
        self.write("/sys/devices/system/cpu/amd_pstate/status", "active\n")
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "ok")
        self.assertIn("correct configuration", " ".join(result["detail"]))

    def test_hyphenated_driver_spelling_is_accepted(self):
        self.cpufreq(
            scaling_driver="amd-pstate-epp",
            scaling_governor="powersave",
            energy_performance_preference="balance_performance",
        )
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "ok")

    def test_epp_biased_to_efficiency_warns(self):
        self.cpufreq(
            scaling_driver="amd_pstate-epp",
            scaling_governor="powersave",
            energy_performance_preference="power",
        )
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "warn")

    def test_acpi_cpufreq_powersave_really_is_a_problem(self):
        # Same governor name, opposite verdict, because on this driver it
        # genuinely pins the CPU near its minimum frequency.
        self.cpufreq(scaling_driver="acpi-cpufreq", scaling_governor="powersave")
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("minimum frequency", " ".join(result["detail"]))

    def test_acpi_cpufreq_schedutil_is_ok(self):
        self.cpufreq(scaling_driver="acpi-cpufreq", scaling_governor="schedutil")
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "ok")

    def test_intel_pstate_performance_is_ok(self):
        self.cpufreq(
            scaling_driver="intel_pstate",
            scaling_governor="performance",
            energy_performance_preference="performance",
        )
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "ok")

    def test_no_cpufreq_is_unknown(self):
        result = freshcheck.check_cpu(ctx())
        self.assertEqual(result["status"], "unknown")


# --------------------------------------------------------------------- time


class TestTime(TreeCase):
    def test_unsynchronised_clock_warns(self):
        self.stub_run({"timedatectl show": (0, "NTP=no\nNTPSynchronized=no\nLocalRTC=no\nTimezone=UTC\n")})
        results = freshcheck.check_time(ctx())
        sync = [r for r in results if r["id"] == "time-sync"][0]
        self.assertEqual(sync["status"], "warn")
        self.assertEqual(sync["fix"], "sudo timedatectl set-ntp true")

    def test_local_rtc_is_reported_not_flagged(self):
        # Dual-boot machines set this deliberately. Calling it broken would be
        # wrong, so it is reported at ok with the tradeoff explained.
        self.stub_run(
            {"timedatectl show": (0, "NTP=yes\nNTPSynchronized=yes\nLocalRTC=yes\nTimezone=Europe/London\n")}
        )
        results = freshcheck.check_time(ctx())
        rtc = [r for r in results if r["id"] == "time-rtc"][0]
        self.assertEqual(rtc["status"], "ok")
        self.assertIn("Windows-compatible", " ".join(rtc["detail"]))

    def test_utc_rtc_is_ok(self):
        self.stub_run(
            {"timedatectl show": (0, "NTP=yes\nNTPSynchronized=yes\nLocalRTC=no\nTimezone=UTC\n")}
        )
        results = freshcheck.check_time(ctx())
        self.assertEqual({r["status"] for r in results}, {"ok"})

    def test_no_systemd_is_skipped(self):
        result = freshcheck.check_time(ctx(systemd=False))
        self.assertEqual(result["status"], "skipped")


# --------------------------------------------------------------- filesystem


class TestFilesystem(TreeCase):
    def use(self, per_suffix, default):
        """Stub disk_usage: longest matching path suffix wins, else default."""

        def fake(path):
            text = str(path).replace("\\", "/")
            for suffix in sorted(per_suffix, key=len, reverse=True):
                if text.endswith(suffix):
                    return per_suffix[suffix]
            return default

        freshcheck.disk_usage = fake

    def test_healthy_filesystems_are_ok(self):
        self.write("/proc/mounts", "/dev/sda1 / ext4 rw 0 0\n")
        self.use({}, (100 * 1024**3, 60 * 1024**3))
        result = freshcheck.check_filesystem(ctx())
        self.assertEqual(result["status"], "ok")

    def test_boot_is_held_to_a_stricter_bar_than_root(self):
        # 15% free is fine on / and a warning on /boot, because a full /boot
        # makes a kernel update fail partway.
        self.write("/proc/mounts", "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /boot ext4 rw 0 0\n")
        self.use(
            {"/boot": (512 * 1024**2, 77 * 1024**2)},  # 15% free
            (100 * 1024**3, 15 * 1024**3),  # 15% free
        )
        result = freshcheck.check_filesystem(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("/boot", result["summary"])
        self.assertNotIn("/ is", result["summary"])

    def test_critically_full_boot_is_a_failure(self):
        self.write("/proc/mounts", "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /boot ext4 rw 0 0\n")
        self.use(
            {"/boot": (512 * 1024**2, 20 * 1024**2)},  # 4% free
            (100 * 1024**3, 60 * 1024**3),
        )
        result = freshcheck.check_filesystem(ctx())
        self.assertEqual(result["status"], "fail")
        self.assertIn("initramfs", " ".join(result["detail"]))

    def test_esp_is_picked_up_from_mounts(self):
        self.write(
            "/proc/mounts",
            "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /boot/efi vfat rw 0 0\n",
        )

        self.use(
            {"/boot/efi": (300 * 1024**2, 30 * 1024**2)},  # 10% free
            (100 * 1024**3, 60 * 1024**3),
        )
        result = freshcheck.check_filesystem(ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIn("/boot/efi", result["summary"])


# -------------------------------------------------------------- failed units


class TestFailedUnits(TreeCase):
    def test_no_failed_units_is_ok(self):
        self.stub_run({"systemctl --failed": (0, "")})
        result = freshcheck.check_failed_units(ctx())
        self.assertEqual(result["status"], "ok")

    def test_failed_units_are_listed(self):
        self.stub_run(
            {
                "systemctl --failed": (
                    1,
                    "nfs-server.service loaded failed failed NFS server\n"
                    "fstrim.service loaded failed failed Discard unused blocks\n",
                )
            }
        )
        result = freshcheck.check_failed_units(ctx())
        self.assertEqual(result["status"], "fail")
        self.assertIn("2 failed", result["summary"])
        self.assertIn("nfs-server.service", " ".join(result["detail"]))

    def test_no_systemd_is_skipped(self):
        result = freshcheck.check_failed_units(ctx(systemd=False))
        self.assertEqual(result["status"], "skipped")


# ---------------------------------------------------------------- boot time


class TestBootTime(TreeCase):
    def test_boot_time_is_informational_only(self):
        self.stub_run(
            {
                "systemd-analyze time": (0, "Startup finished in 3.1s (kernel) + 8.2s (userspace) = 11.3s\n"),
                "systemd-analyze blame": (0, "5.100s NetworkManager-wait-online.service\n1.200s dev-sda1.device\n"),
            }
        )
        result = freshcheck.check_boot_time(ctx())
        # A slow unit is not automatically a problem, so this must never
        # contribute to the exit code.
        self.assertEqual(result["status"], "info")
        self.assertNotIn(result["status"], freshcheck.EXIT_STATUSES)
        self.assertIn("NetworkManager-wait-online", " ".join(result["detail"]))


# ------------------------------------------------------------------- runner


class TestRunner(TreeCase):
    def test_a_crashing_check_does_not_take_down_the_run(self):
        saved = list(freshcheck.CHECKS)
        try:
            def boom(_ctx):
                raise RuntimeError("synthetic explosion")

            freshcheck.CHECKS[:] = [
                {"id": "boom", "title": "Exploding check", "fn": boom},
                {"id": "fine", "title": "Fine check", "fn": lambda c: freshcheck.make("fine", "ok", "all good")},
            ]
            _, results = freshcheck.run_checks(["boom", "fine"])
            statuses = {r["check"]: r["status"] for r in results}
            self.assertEqual(statuses["boom"], "unknown")
            self.assertEqual(statuses["fine"], "ok")
        finally:
            freshcheck.CHECKS[:] = saved

    def test_unknown_does_not_affect_the_exit_code(self):
        saved = list(freshcheck.CHECKS)
        try:
            freshcheck.CHECKS[:] = [
                {"id": "u", "title": "U", "fn": lambda c: freshcheck.make("u", "unknown", "cannot tell")},
                {"id": "s", "title": "S", "fn": lambda c: freshcheck.make("s", "skipped", "n/a")},
                {"id": "i", "title": "I", "fn": lambda c: freshcheck.make("i", "info", "fyi")},
            ]
            report = freshcheck.build_report(
                _Args(only=[], skip=[])
            )
            self.assertEqual(report["exit_code"], 0)
        finally:
            freshcheck.CHECKS[:] = saved

    def test_warn_sets_exit_code_one(self):
        saved = list(freshcheck.CHECKS)
        try:
            freshcheck.CHECKS[:] = [
                {"id": "w", "title": "W", "fn": lambda c: freshcheck.make("w", "warn", "hmm")}
            ]
            report = freshcheck.build_report(_Args(only=[], skip=[]))
            self.assertEqual(report["exit_code"], 1)
        finally:
            freshcheck.CHECKS[:] = saved

    def test_only_and_skip_select_checks(self):
        saved = list(freshcheck.CHECKS)
        try:
            freshcheck.CHECKS[:] = [
                {"id": "a", "title": "A", "fn": lambda c: freshcheck.make("a", "ok", "a")},
                {"id": "b", "title": "B", "fn": lambda c: freshcheck.make("b", "ok", "b")},
            ]
            report = freshcheck.build_report(_Args(only=["a"], skip=[]))
            self.assertEqual([r["id"] for r in report["results"]], ["a"])
            report = freshcheck.build_report(_Args(only=[], skip=["a"]))
            self.assertEqual([r["id"] for r in report["results"]], ["b"])
        finally:
            freshcheck.CHECKS[:] = saved

    def test_skipped_never_renders_as_a_pass(self):
        saved = list(freshcheck.CHECKS)
        try:
            freshcheck.CHECKS[:] = [
                {"id": "s", "title": "S", "fn": lambda c: freshcheck.make("s", "skipped", "does not apply here")}
            ]
            report = freshcheck.build_report(_Args(only=[], skip=[]))
            self.assertEqual(report["counts"]["ok"], 0)
            self.assertEqual(report["counts"]["skipped"], 1)

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                freshcheck.render(freshcheck.Out(color=False), report)
            text = buffer.getvalue()
            self.assertIn("Not applicable", text)
            # The finding must not appear under the passed heading.
            passed_section = text.split("Passed")[1] if "Passed" in text else ""
            self.assertNotIn("does not apply here", passed_section)
        finally:
            freshcheck.CHECKS[:] = saved


class _Args:
    def __init__(self, only, skip):
        self.only = only
        self.skip = skip


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
        self.assertEqual(freshcheck.safe_text("naïve"), "na\\xefve")
        self.assertEqual(freshcheck.rule_char(), "-")


if __name__ == "__main__":
    unittest.main(verbosity=2)
