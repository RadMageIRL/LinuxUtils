#!/usr/bin/env python3
"""
Tests for logi-rx.

    python3 -m unittest discover -s logi-rx/tests -t logi-rx/tests -v
    ./logi-rx/tests/test_logi_rx.py

Standard library only, same rule as the tools.

logi-rx is the only tool in this repo that writes to the system, which inverts
the usual risk ordering, so the write paths get the most attention here:
--apply is checked for idempotency, the generated udev rule is checked for
pinning the specific product ID rather than every Logitech device, and --revert
is checked for refusing to delete a file it did not write.

Three harnesses, matching the shape of the real system:

  * a synthetic sysfs tree with the real /sys/devices/pci.../usbN/1-3 layout
    behind /sys/bus/usb/devices symlinks, so root_hub_for() and
    pci_controller_for() are exercised rather than stubbed
  * /proc/bus/input/devices fixtures covering keyboard-only, pointer, and
    non-Logitech blocks
  * an evdev byte stream, fed from a file everywhere and from a real FIFO on
    platforms that have them
"""

import importlib.util
import json
import os
import pathlib
import shutil
import struct
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# logi-rx.py is not an importable module name, so load it by path. Register it
# in sys.modules and reuse an existing entry: without that, every loader gets a
# private copy of the module, and anything that patches a module-level constant
# from outside (the mutation-testing harness) silently patches a copy the tests
# never see. That failure mode looks exactly like a suite with nothing to catch.
if "logi_rx" in sys.modules:
    logi_rx = sys.modules["logi_rx"]
else:
    _spec = importlib.util.spec_from_file_location("logi_rx", ROOT / "logi-rx.py")
    logi_rx = importlib.util.module_from_spec(_spec)
    sys.modules["logi_rx"] = logi_rx
    _spec.loader.exec_module(logi_rx)


# Building a realistic sysfs tree needs two things the host may not provide:
# directory symlinks (the kernel exposes /sys/bus/usb/devices as symlinks into
# /sys/devices) and colons in directory names (every PCI address has two, and
# pci_controller_for's regex genuinely requires them, so a colon-free stand-in
# would not exercise the code under test). Both hold on Linux, which is where
# this tool runs; a Windows host skips these rather than testing a fiction.
_probe = pathlib.Path(tempfile.mkdtemp())
try:
    (_probe / "target").mkdir()
    os.symlink(_probe / "target", _probe / "link", target_is_directory=True)
    HAVE_SYMLINKS = True
except OSError:  # pragma: no cover - platform dependent
    HAVE_SYMLINKS = False
try:
    (_probe / "pci0000:00").mkdir()
    HAVE_COLON_PATHS = True
except OSError:  # pragma: no cover - platform dependent
    HAVE_COLON_PATHS = False
shutil.rmtree(_probe, ignore_errors=True)

REAL_SYSFS = HAVE_SYMLINKS and HAVE_COLON_PATHS
SYSFS_REASON = "needs directory symlinks and colons in path names (Linux)"

HAVE_FIFO = hasattr(os, "mkfifo")

CONTROLLER = "0000:00:14.0"
RECEIVER_ATTRS = {
    "idVendor": "046d",
    "idProduct": "c52b",
    "product": "USB Receiver",
    "busnum": "1",
    "devnum": "4",
    "speed": "12",
    "power/control": "auto",
    "power/wakeup": "disabled",
}


class Args:
    def __init__(self, **kw):
        self.apply = kw.get("apply", False)
        self.revert = kw.get("revert", False)
        self.watch = kw.get("watch", False)
        self.duration = kw.get("duration", 1)
        self.gap_ms = kw.get("gap_ms", None)
        self.device = kw.get("device", None)
        self.json = kw.get("json", False)
        self.no_color = kw.get("no_color", True)


class TreeCase(unittest.TestCase):
    """Builds a synthetic system tree and restores the module seams."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="logi-rx-test-"))
        self._saved = (
            logi_rx.SYSROOT,
            logi_rx.PLATFORM,
            logi_rx.IS_ROOT,
            logi_rx.run,
        )
        logi_rx.SYSROOT = self.root
        logi_rx.PLATFORM = "linux"
        logi_rx.IS_ROOT = False
        logi_rx.run = lambda cmd, timeout=30: (0, "", None)

    def tearDown(self):
        logi_rx.SYSROOT, logi_rx.PLATFORM, logi_rx.IS_ROOT, logi_rx.run = self._saved
        shutil.rmtree(self.root, ignore_errors=True)

    # -- tree construction

    def write(self, path, content):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def read(self, path):
        return (self.root / path.lstrip("/")).read_text(encoding="utf-8")

    def exists(self, path):
        return (self.root / path.lstrip("/")).exists()

    def add_usb_device(self, real_path, link_name, attrs):
        """Create a device at its real /sys/devices location and symlink it into
        /sys/bus/usb/devices, exactly as the kernel does."""
        device = self.root / real_path.lstrip("/")
        device.mkdir(parents=True, exist_ok=True)
        for key, value in attrs.items():
            attr = device / key
            attr.parent.mkdir(parents=True, exist_ok=True)
            attr.write_text(value, encoding="utf-8")
        link = self.root / "sys/bus/usb/devices" / link_name
        link.parent.mkdir(parents=True, exist_ok=True)
        if HAVE_SYMLINKS:
            os.symlink(device, link, target_is_directory=True)
        else:  # pragma: no cover - platform dependent
            shutil.copytree(device, link)
        return device

    def build_standard_tree(self, receiver_attrs=None, controller=CONTROLLER):
        """usb1 (480 Mbps) carrying the receiver, usb2 (10000 Mbps) carrying an
        external SSD, both behind the same PCI host controller."""
        base = f"/sys/devices/pci0000:00/{controller}"
        self.add_usb_device(
            f"{base}/usb1",
            "usb1",
            {"idVendor": "1d6b", "idProduct": "0002", "product": "xHCI Host Controller",
             "speed": "480", "maxchild": "12", "busnum": "1", "devnum": "1"},
        )
        self.add_usb_device(
            f"{base}/usb2",
            "usb2",
            {"idVendor": "1d6b", "idProduct": "0003", "product": "xHCI Host Controller",
             "speed": "10000", "maxchild": "4", "busnum": "2", "devnum": "1"},
        )
        self.add_usb_device(
            f"{base}/usb1/1-3",
            "1-3",
            dict(receiver_attrs if receiver_attrs is not None else RECEIVER_ATTRS),
        )
        return self.receiver()

    def add_webcam(self, controller=CONTROLLER):
        self.add_usb_device(
            f"/sys/devices/pci0000:00/{controller}/usb1/1-5",
            "1-5",
            {"idVendor": "046d", "idProduct": "0825", "product": "HD Webcam C270",
             "busnum": "1", "devnum": "6", "speed": "480"},
        )

    def add_superspeed_neighbour(self, controller=CONTROLLER):
        self.add_usb_device(
            f"/sys/devices/pci0000:00/{controller}/usb2/2-1",
            "2-1",
            {"idVendor": "0bc2", "idProduct": "231a", "product": "Portable SSD",
             "busnum": "2", "devnum": "3", "speed": "10000"},
        )

    def receiver(self):
        found = logi_rx.find_receivers()
        return found[0] if found else None

    def ctx(self, apply=False, receiver=None):
        return {
            "receiver": receiver or self.receiver(),
            "apply": apply,
            "applied": [],
        }


# --------------------------------------------------------------- discovery


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestDiscovery(TreeCase):
    def test_receiver_is_found(self):
        self.build_standard_tree()
        found = logi_rx.find_receivers()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "1-3")
        self.assertEqual(found[0]["pid"], "c52b")
        self.assertTrue(found[0]["known"])
        self.assertEqual(found[0]["label"], "Unifying Receiver")

    def test_receiver_outranks_another_logitech_device(self):
        # A webcam is also 046d. The receiver has to win, or the audit runs
        # against the wrong device.
        self.build_standard_tree()
        self.add_webcam()
        found = logi_rx.find_receivers()
        self.assertEqual(len(found), 2)
        self.assertEqual(found[0]["name"], "1-3")

    def test_device_flag_selects_the_other_device(self):
        self.build_standard_tree()
        self.add_webcam()
        report = logi_rx.build_report(Args(device="1-5"))
        self.assertEqual(report["receiver"]["name"], "1-5")
        self.assertEqual(report["receiver"]["product"], "HD Webcam C270")

    def test_other_logitech_devices_are_reported(self):
        self.build_standard_tree()
        self.add_webcam()
        report = logi_rx.build_report(Args())
        self.assertEqual([d["name"] for d in report["other_logitech_devices"]], ["1-5"])

    def test_usb_interfaces_are_not_mistaken_for_devices(self):
        self.build_standard_tree()
        # "1-3:1.0" is an interface, not a device, and must be skipped.
        interface = self.root / "sys/bus/usb/devices/1-3:1.0"
        interface.mkdir(parents=True)
        (interface / "idVendor").write_text("046d")
        self.assertEqual([d["name"] for d in logi_rx.find_receivers()], ["1-3"])


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestTopology(TreeCase):
    def test_root_hub_resolves_through_the_symlink(self):
        receiver = self.build_standard_tree()
        hub = logi_rx.root_hub_for(receiver["path"])
        self.assertIsNotNone(hub)
        self.assertEqual(hub.name, "usb1")

    def test_pci_controller_resolves_through_the_symlink(self):
        receiver = self.build_standard_tree()
        self.assertEqual(logi_rx.pci_controller_for(receiver["path"]), CONTROLLER)

    def test_topology_is_informational_not_a_finding(self):
        self.build_standard_tree()
        result = logi_rx.check_topology(self.ctx())
        self.assertEqual(result["status"], "info")
        self.assertNotIn(result["status"], logi_rx.EXIT_STATUSES)

    def test_topology_keeps_the_usb2_versus_usb3_disclaimer(self):
        # The tool must never claim to detect the physical port generation.
        self.build_standard_tree()
        result = logi_rx.check_topology(self.ctx())
        joined = " ".join(result["detail"])
        self.assertIn("does NOT tell you whether the physical port", joined)

    def test_topology_lists_both_root_hubs(self):
        self.build_standard_tree()
        joined = " ".join(logi_rx.check_topology(self.ctx())["detail"])
        self.assertIn("usb1", joined)
        self.assertIn("usb2", joined)
        self.assertIn("receiver is here", joined)


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestSiblings(TreeCase):
    def test_superspeed_neighbour_is_reported(self):
        self.build_standard_tree()
        self.add_superspeed_neighbour()
        result = logi_rx.check_siblings(self.ctx())
        self.assertEqual(result["status"], "info")
        joined = " ".join(result["detail"])
        self.assertIn("Portable SSD", joined)
        self.assertIn("SuperSpeed", joined)

    def test_neighbour_correlation_is_never_a_finding(self):
        # It is adjacent evidence, not a diagnosis, and must not affect the
        # exit code or read as a fault.
        self.build_standard_tree()
        self.add_superspeed_neighbour()
        result = logi_rx.check_siblings(self.ctx())
        self.assertNotIn(result["status"], logi_rx.EXIT_STATUSES)
        self.assertIn("correlation and not a diagnosis", " ".join(result["detail"]))

    def test_a_full_speed_neighbour_is_listed_but_not_called_superspeed(self):
        # A USB 2 webcam on the same controller is a neighbour, but it is not a
        # broadband noise source and must not be reported as one. Only
        # SuperSpeed signalling sits on top of 2.4 GHz.
        self.build_standard_tree()
        self.add_webcam()
        result = logi_rx.check_siblings(self.ctx())
        joined = " ".join(result["detail"])
        self.assertIn("HD Webcam C270", joined)
        self.assertNotIn("SuperSpeed", result["summary"])
        self.assertNotIn("SuperSpeed", joined)

    def test_device_on_a_different_controller_is_not_listed(self):
        self.build_standard_tree()
        self.add_usb_device(
            "/sys/devices/pci0000:00/0000:00:1d.0/usb3/3-1",
            "3-1",
            {"idVendor": "0bc2", "idProduct": "231a", "product": "Other Controller SSD",
             "busnum": "3", "devnum": "2", "speed": "10000"},
        )
        result = logi_rx.check_siblings(self.ctx())
        self.assertNotIn("Other Controller SSD", " ".join(result["detail"]))

    def test_lone_receiver_says_so(self):
        # The standard tree has a SuperSpeed root hub (usb2) on the same
        # controller, and the receiver is still alone: root hubs are not
        # neighbours.
        self.build_standard_tree()
        result = logi_rx.check_siblings(self.ctx())
        self.assertEqual(result["status"], "info")
        self.assertIn("Nothing else", result["summary"])

    def test_root_hubs_are_not_counted_as_neighbours(self):
        # Every modern xHCI controller exposes a SuperSpeed root hub. Counting
        # those would make this check fire on essentially every machine, which
        # is how a finding becomes noise people learn to skip past.
        self.build_standard_tree()
        result = logi_rx.check_siblings(self.ctx())
        self.assertNotIn("SuperSpeed", result["summary"])
        self.assertNotIn("usb2", " ".join(result["detail"]))


# ------------------------------------------------------- /proc/bus/input


KEYBOARD_BLOCK = """I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech K400 Plus"
P: Phys=usb-0000:00:14.0-3/input2:1
H: Handlers=sysrq kbd leds event4
B: EV=120013
"""

POINTER_BLOCK = """I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech K400 Plus Touchpad"
P: Phys=usb-0000:00:14.0-3/input2:2
H: Handlers=mouse1 event5
B: EV=17
"""

OTHER_MOUSE_BLOCK = """I: Bus=0003 Vendor=1532 Product=0084 Version=0111
N: Name="Razer DeathAdder"
P: Phys=usb-0000:00:14.0-1/input0
H: Handlers=mouse0 event3
B: EV=17
"""


class TestProcInput(TreeCase):
    def test_pointer_interface_is_selected(self):
        self.write(
            "/proc/bus/input/devices", KEYBOARD_BLOCK + "\n" + POINTER_BLOCK
        )
        node, name = logi_rx.find_pointer_event_device()
        self.assertEqual(node, "/dev/input/event5")
        self.assertEqual(name, "Logitech K400 Plus Touchpad")

    def test_keyboard_only_interface_is_skipped(self):
        # It is the same vendor and product, listed first, and has no mouse
        # handler. Selecting it would produce a run with no motion at all.
        self.write("/proc/bus/input/devices", KEYBOARD_BLOCK)
        self.assertEqual(logi_rx.find_pointer_event_device(), (None, None))

    def test_non_logitech_pointer_is_ignored(self):
        self.write("/proc/bus/input/devices", OTHER_MOUSE_BLOCK)
        self.assertEqual(logi_rx.find_pointer_event_device(), (None, None))

    def test_logitech_pointer_wins_over_another_vendor(self):
        self.write(
            "/proc/bus/input/devices",
            OTHER_MOUSE_BLOCK + "\n" + KEYBOARD_BLOCK + "\n" + POINTER_BLOCK,
        )
        node, _ = logi_rx.find_pointer_event_device()
        self.assertEqual(node, "/dev/input/event5")

    def test_missing_file_returns_no_match(self):
        self.assertEqual(logi_rx.find_pointer_event_device(), (None, None))


# ------------------------------------------------------------- power state


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestPowerAttributes(TreeCase):
    def test_autosuspend_already_disabled_is_ok(self):
        attrs = dict(RECEIVER_ATTRS, **{"power/control": "on"})
        self.build_standard_tree(attrs)
        self.assertEqual(logi_rx.check_autosuspend(self.ctx())["status"], "ok")

    def test_autosuspend_enabled_is_a_warning(self):
        self.build_standard_tree()
        result = logi_rx.check_autosuspend(self.ctx())
        self.assertEqual(result["status"], "warn")
        self.assertIsNotNone(result["fix"])

    def test_autosuspend_not_exposed_is_skipped_not_a_warning(self):
        attrs = {k: v for k, v in RECEIVER_ATTRS.items() if k != "power/control"}
        self.build_standard_tree(attrs)
        result = logi_rx.check_autosuspend(self.ctx())
        self.assertEqual(result["status"], "skipped")

    def test_wakeup_enabled_is_ok(self):
        attrs = dict(RECEIVER_ATTRS, **{"power/wakeup": "enabled"})
        self.build_standard_tree(attrs)
        self.assertEqual(logi_rx.check_wakeup(self.ctx())["status"], "ok")

    def test_wakeup_disabled_is_a_warning(self):
        self.build_standard_tree()
        result = logi_rx.check_wakeup(self.ctx())
        self.assertEqual(result["status"], "warn")

    def test_wakeup_not_exposed_is_skipped_not_a_warning(self):
        # The distinction the five-status model exists for. A device that never
        # advertised remote wakeup has no setting to change, so warning about
        # it sends the user hunting for something that does not exist.
        attrs = {k: v for k, v in RECEIVER_ATTRS.items() if k != "power/wakeup"}
        self.build_standard_tree(attrs)
        result = logi_rx.check_wakeup(self.ctx())
        self.assertEqual(result["status"], "skipped")
        self.assertNotIn(result["status"], logi_rx.EXIT_STATUSES)


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestApply(TreeCase):
    def test_apply_writes_both_attributes(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = True
        report = logi_rx.build_report(Args(apply=True))
        self.assertIn("power/control = on", report["applied"])
        self.assertIn("power/wakeup = enabled", report["applied"])
        receiver = self.receiver()
        self.assertEqual(logi_rx.read_attr(receiver["path"], "power/control"), "on")
        self.assertEqual(logi_rx.read_attr(receiver["path"], "power/wakeup"), "enabled")

    def test_apply_is_idempotent(self):
        # The second pass over an already-fixed tree must report ok and write
        # nothing. A tool that rewrites on every run is one you cannot put in a
        # cron job or run twice by accident.
        self.build_standard_tree()
        logi_rx.IS_ROOT = True
        first = logi_rx.build_report(Args(apply=True))
        self.assertTrue(first["applied"])

        second = logi_rx.build_report(Args(apply=True))
        self.assertEqual(second["applied"], [])
        statuses = {r["check"]: r["status"] for r in second["results"]}
        self.assertEqual(statuses["autosuspend"], "ok")
        self.assertEqual(statuses["wakeup"], "ok")
        self.assertEqual(statuses["udev"], "ok")
        self.assertEqual(second["exit_code"], logi_rx.NO_FINDINGS)

    def test_apply_without_root_determines_nothing(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = False
        report = logi_rx.build_report(Args(apply=True))
        self.assertEqual(report["error"], "needs-root")
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)

    def test_read_only_by_default(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = True
        report = logi_rx.build_report(Args())
        self.assertEqual(report["applied"], [])
        receiver = self.receiver()
        self.assertEqual(logi_rx.read_attr(receiver["path"], "power/control"), "auto")
        self.assertFalse(self.exists(logi_rx.UDEV_RULE))


# ---------------------------------------------------------------- udev rule


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestUdev(TreeCase):
    def test_rule_pins_the_detected_product_id(self):
        # Matching all of 046d would apply the rule to webcams and headsets too.
        receiver = self.build_standard_tree()
        rule = logi_rx.build_rule(receiver)
        self.assertIn('ATTR{idProduct}=="c52b"', rule)
        self.assertIn('ATTR{idVendor}=="046d"', rule)
        self.assertNotIn('ATTR{idProduct}=="*"', rule)
        self.assertIn(logi_rx.MANAGED_MARKER, rule)

    def test_missing_rule_is_a_warning(self):
        self.build_standard_tree()
        result = logi_rx.check_udev(self.ctx())
        self.assertEqual(result["status"], "warn")

    def test_matching_rule_is_ok(self):
        receiver = self.build_standard_tree()
        self.write(logi_rx.UDEV_RULE, logi_rx.build_rule(receiver))
        self.assertEqual(logi_rx.check_udev(self.ctx())["status"], "ok")

    def test_rule_for_a_different_receiver_is_a_warning(self):
        receiver = self.build_standard_tree()
        stale = logi_rx.build_rule(dict(receiver, pid="c548"))
        self.write(logi_rx.UDEV_RULE, stale)
        self.assertEqual(logi_rx.check_udev(self.ctx())["status"], "warn")

    def test_apply_writes_a_rule_pinned_to_this_receiver(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = True
        logi_rx.build_report(Args(apply=True))
        written = self.read(logi_rx.UDEV_RULE)
        self.assertIn('ATTR{idProduct}=="c52b"', written)


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestRevert(TreeCase):
    def test_revert_removes_a_managed_rule(self):
        receiver = self.build_standard_tree()
        self.write(logi_rx.UDEV_RULE, logi_rx.build_rule(receiver))
        logi_rx.IS_ROOT = True
        result = logi_rx.revert()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(self.exists(logi_rx.UDEV_RULE))

    def test_revert_refuses_to_delete_a_foreign_rule(self):
        # A file at that path this tool did not write is not this tool's to
        # remove. Deleting it would be destroying someone else's configuration.
        self.build_standard_tree()
        self.write(logi_rx.UDEV_RULE, '# hand written\nACTION=="add", SUBSYSTEM=="usb"\n')
        logi_rx.IS_ROOT = True
        result = logi_rx.revert()
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(self.exists(logi_rx.UDEV_RULE))

    def test_revert_with_no_rule_is_skipped(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = True
        self.assertEqual(logi_rx.revert()["status"], "skipped")

    def test_revert_without_root_determines_nothing(self):
        self.build_standard_tree()
        logi_rx.IS_ROOT = False
        report = logi_rx.build_report(Args(revert=True))
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)


# ---------------------------------------------------------------- ACPI


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestAcpi(TreeCase):
    HEADER = "Device\tS-state\t  Status   Sysfs node\n"

    def test_absent_file_is_skipped(self):
        self.build_standard_tree()
        self.assertEqual(logi_rx.check_acpi(self.ctx())["status"], "skipped")

    def test_matching_entry_enabled_is_ok(self):
        self.build_standard_tree()
        self.write(
            logi_rx.PROC_ACPI_WAKEUP,
            self.HEADER + f"XHC0\t  S3\t*enabled   pci:{CONTROLLER}\n",
        )
        result = logi_rx.check_acpi(self.ctx())
        self.assertEqual(result["status"], "ok")

    def test_matching_entry_disabled_is_a_failure(self):
        self.build_standard_tree()
        self.write(
            logi_rx.PROC_ACPI_WAKEUP,
            self.HEADER + f"XHC0\t  S3\t*disabled  pci:{CONTROLLER}\n",
        )
        result = logi_rx.check_acpi(self.ctx())
        self.assertEqual(result["status"], "fail")
        self.assertIn("TOGGLE", " ".join(result["detail"]))

    def test_no_matching_entry_is_informational(self):
        self.build_standard_tree()
        self.write(
            logi_rx.PROC_ACPI_WAKEUP,
            self.HEADER + "PEG0\t  S4\t*disabled  pci:0000:00:01.0\n",
        )
        result = logi_rx.check_acpi(self.ctx())
        self.assertEqual(result["status"], "info")
        self.assertNotIn(result["status"], logi_rx.EXIT_STATUSES)

    def test_unreadable_file_is_unknown_not_a_failure(self):
        self.build_standard_tree()
        (self.root / logi_rx.PROC_ACPI_WAKEUP.lstrip("/")).mkdir(parents=True)
        self.assertEqual(logi_rx.check_acpi(self.ctx())["status"], "unknown")


# -------------------------------------------------------------- battery


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestBattery(TreeCase):
    def add_battery(self, name="hidpp_battery_0", **attrs):
        for key, value in attrs.items():
            self.write(f"{logi_rx.POWER_SUPPLY}/{name}/{key}", value)

    def test_no_power_supply_class_is_skipped(self):
        self.build_standard_tree()
        self.assertEqual(logi_rx.check_battery(self.ctx())["status"], "skipped")

    def test_no_hidpp_battery_is_skipped_not_a_failure(self):
        self.build_standard_tree()
        self.write(f"{logi_rx.POWER_SUPPLY}/AC/online", "1")
        result = logi_rx.check_battery(self.ctx())
        self.assertEqual(result["status"], "skipped")
        self.assertIn("alkaline", " ".join(result["detail"]))

    def test_healthy_capacity_is_ok(self):
        self.build_standard_tree()
        self.add_battery(model_name="K400 Plus", capacity="85", status="Discharging")
        result = logi_rx.check_battery(self.ctx())
        self.assertEqual(result["status"], "ok")
        self.assertIn("85%", " ".join(result["detail"]))

    def test_low_capacity_is_a_warning(self):
        self.build_standard_tree()
        self.add_battery(model_name="K400 Plus", capacity="12")
        self.assertEqual(logi_rx.check_battery(self.ctx())["status"], "warn")

    def test_capacity_level_only_low_is_a_warning(self):
        # Some devices report a level word and no percentage at all.
        self.build_standard_tree()
        self.add_battery(model_name="M185", capacity_level="Low")
        self.assertEqual(logi_rx.check_battery(self.ctx())["status"], "warn")

    def test_capacity_level_only_full_is_ok(self):
        self.build_standard_tree()
        self.add_battery(model_name="M185", capacity_level="Full")
        self.assertEqual(logi_rx.check_battery(self.ctx())["status"], "ok")


# ------------------------------------------------------------ kernel module


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestModule(TreeCase):
    def test_loaded_module_is_ok(self):
        self.build_standard_tree()
        self.write(logi_rx.PROC_MODULES, "hid_logitech_dj 32768 0 - Live 0x0000\n")
        self.assertEqual(logi_rx.check_module(self.ctx())["status"], "ok")

    def test_missing_module_is_a_failure(self):
        self.build_standard_tree()
        self.write(logi_rx.PROC_MODULES, "usbhid 65536 0 - Live 0x0000\n")
        result = logi_rx.check_module(self.ctx())
        self.assertEqual(result["status"], "fail")
        self.assertIn("modprobe", result["fix"])

    def test_builtin_module_is_ok(self):
        self.build_standard_tree()
        self.write(logi_rx.PROC_MODULES, "usbhid 65536 0 - Live 0x0000\n")
        (self.root / logi_rx.SYS_MODULE_DJ.lstrip("/")).mkdir(parents=True)
        self.assertEqual(logi_rx.check_module(self.ctx())["status"], "ok")

    def test_unreadable_proc_modules_is_unknown(self):
        self.build_standard_tree()
        self.assertEqual(logi_rx.check_module(self.ctx())["status"], "unknown")


# ------------------------------------------------------- watch: analysis


REL_X = logi_rx.REL_X


def samples_from(spec, start=1000.0):
    """Build (timestamp, code, delta) samples from (interval_s, delta) pairs."""
    now = start
    out = []
    for interval, delta in spec:
        now += interval
        out.append((now, REL_X, delta))
    return out


def steady(count, delta=30, interval=0.008):
    return [(interval, delta)] * count


class TestAnalyse(unittest.TestCase):
    """Pure analysis. No clock, no I/O, no receiver."""

    def test_no_samples_yields_no_threshold(self):
        report = logi_rx.analyse([])
        self.assertEqual(report["motion_events"], 0)
        self.assertIsNone(report["threshold_ms"])
        self.assertIsNone(report["threshold_source"])

    def test_too_few_samples_refuses_to_calibrate(self):
        # A fabricated threshold from an unstable median is worse than saying
        # the run was too short.
        report = logi_rx.analyse(samples_from(steady(10)))
        self.assertIsNone(report["threshold_source"])
        self.assertIsNone(report["threshold_ms"])
        self.assertEqual(report["gaps"], [])

    def test_threshold_calibrates_to_the_device_report_rate(self):
        report = logi_rx.analyse(samples_from(steady(200, interval=0.008)))
        self.assertEqual(report["threshold_source"], "calibrated")
        self.assertAlmostEqual(report["median_gap_ms"], 8.0, places=3)
        self.assertAlmostEqual(
            report["threshold_ms"], 8.0 * logi_rx.GAP_MULTIPLIER, places=3
        )

    def test_a_faster_device_calibrates_to_a_tighter_threshold(self):
        # The whole reason for calibrating: a 1000 Hz mouse and a 125 Hz
        # receiver must not be judged against the same millisecond figure.
        slow = logi_rx.analyse(samples_from(steady(200, interval=0.008)))
        fast = logi_rx.analyse(samples_from(steady(200, interval=0.001)))
        self.assertLess(fast["threshold_ms"], slow["threshold_ms"])
        self.assertAlmostEqual(fast["threshold_ms"], 1.0 * logi_rx.GAP_MULTIPLIER, places=3)

    def test_explicit_gap_ms_disables_calibration(self):
        report = logi_rx.analyse(samples_from(steady(200)), gap_ms=100.0)
        self.assertEqual(report["threshold_source"], "explicit")
        self.assertEqual(report["threshold_ms"], 100.0)

    def test_explicit_gap_ms_works_even_when_too_short_to_calibrate(self):
        report = logi_rx.analyse(samples_from(steady(10)), gap_ms=50.0)
        self.assertEqual(report["threshold_source"], "explicit")

    def test_clean_run_has_no_gaps(self):
        report = logi_rx.analyse(samples_from(steady(200)))
        self.assertEqual(report["dropouts"], 0)
        self.assertEqual(report["pauses"], 0)

    def test_ordinary_jitter_is_not_flagged(self):
        # Real inter-event intervals are never exactly the median. The
        # multiplier exists to leave room for ordinary scheduling jitter, and a
        # threshold set too close to the median would report a healthy link as
        # dropping hundreds of reports.
        spec = []
        for index in range(200):
            spec.append((0.006 if index % 2 else 0.010, 30))
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["dropouts"], 0)
        self.assertEqual(report["pauses"], 0)
        self.assertGreater(report["threshold_ms"], report["worst_ms"])

    def test_axis_codes_are_separated(self):
        samples = [
            (1000.0, logi_rx.REL_X, 5),
            (1000.008, logi_rx.REL_Y, 7),
            (1000.016, logi_rx.REL_X, 5),
        ]
        report = logi_rx.analyse(samples)
        self.assertEqual(report["axis_counts"], {"x": 2, "y": 1})


class TestGapClassification(unittest.TestCase):
    """The velocity classifier.

    A user pause tapers: deltas shrink toward zero, gap, deltas ramp back up.
    A dropout does not: full-velocity motion, gap, full-velocity motion."""

    def test_abrupt_gap_on_both_sides_is_a_dropout(self):
        spec = steady(60) + [(0.200, 30)] + steady(60)
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["dropouts"], 1)
        self.assertEqual(report["pauses"], 0)

    def test_tapered_gap_is_a_pause_not_a_dropout(self):
        spec = (
            steady(60)
            + [(0.008, 8), (0.008, 4), (0.008, 2)]
            + [(0.500, 2)]
            + [(0.008, 4), (0.008, 8)]
            + steady(60)
        )
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["pauses"], 1)
        self.assertEqual(report["dropouts"], 0)

    def test_taper_in_with_abrupt_out_is_a_dropout(self):
        # Half a taper is not a pause. The pointer came back at full speed,
        # which means the link, not the hand, was the thing that stopped.
        spec = (
            steady(60)
            + [(0.008, 8), (0.008, 4), (0.008, 2)]
            + [(0.200, 30)]
            + steady(60)
        )
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["dropouts"], 1)
        self.assertEqual(report["pauses"], 0)

    def test_slow_deliberate_motion_is_not_mistaken_for_a_pause(self):
        # Every delta is small, but consistently so. An absolute velocity floor
        # would call this a pause; a floor relative to the session's own median
        # correctly calls it a dropout.
        spec = steady(60, delta=3) + [(0.200, 3)] + steady(60, delta=3)
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["dropouts"], 1)
        self.assertEqual(report["pauses"], 0)

    def test_fast_flick_on_both_sides_is_a_dropout(self):
        spec = steady(60, delta=80) + [(0.200, 80)] + steady(60, delta=80)
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["dropouts"], 1)

    def test_pauses_and_dropouts_are_counted_separately(self):
        spec = (
            steady(60)
            + [(0.008, 8), (0.008, 4), (0.008, 2)]
            + [(0.500, 2)]
            + [(0.008, 4), (0.008, 8)]
            + steady(60)
            + [(0.200, 30)]
            + steady(60)
        )
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["pauses"], 1)
        self.assertEqual(report["dropouts"], 1)
        kinds = [gap["classification"] for gap in report["gaps"]]
        self.assertEqual(kinds, ["pause", "dropout"])

    def test_only_the_edge_samples_decide(self):
        # A window mean over the whole run would be dominated by the fast
        # samples and would misread this taper as a dropout.
        spec = (
            steady(60, delta=100)
            + [(0.008, 20), (0.008, 6), (0.008, 1)]
            + [(0.400, 1)]
            + [(0.008, 6), (0.008, 20)]
            + steady(60, delta=100)
        )
        report = logi_rx.analyse(samples_from(spec))
        self.assertEqual(report["pauses"], 1)

    def test_classification_reports_the_velocities_it_used(self):
        spec = steady(60) + [(0.200, 30)] + steady(60)
        gap = logi_rx.analyse(samples_from(spec))["gaps"][0]
        self.assertAlmostEqual(gap["velocity_before"], 30.0, places=6)
        self.assertAlmostEqual(gap["velocity_after"], 30.0, places=6)
        self.assertGreater(gap["gap_ms"], 100)


# --------------------------------------------------------- watch: findings


class TestWatchResults(unittest.TestCase):
    def test_no_motion_is_unknown_not_a_pass(self):
        results = logi_rx.watch_results(logi_rx.analyse([]), "dev", "/dev/input/event5")
        self.assertEqual(results[0]["status"], "unknown")
        self.assertNotIn(results[0]["status"], logi_rx.EXIT_STATUSES)

    def test_too_short_to_calibrate_is_unknown(self):
        report = logi_rx.analyse(samples_from(steady(10)))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        self.assertEqual(results[0]["status"], "unknown")
        self.assertIn("Too few motion events", results[0]["summary"])

    def test_clean_run_is_ok_and_reports_the_derived_threshold(self):
        report = logi_rx.analyse(samples_from(steady(200)))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        self.assertEqual(results[0]["status"], "ok")
        joined = " ".join(results[0]["detail"])
        self.assertIn("calibrated to this device", joined)

    def test_dropouts_are_a_failure_and_name_rfscan(self):
        # The two tools answer halves of one question, and rfscan already names
        # logi-rx --watch as its ground truth. The reference has to be mutual.
        spec = steady(60) + [(0.200, 30)] + steady(60)
        report = logi_rx.analyse(samples_from(spec))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        dropouts = [r for r in results if r["id"] == "watch-dropouts"][0]
        self.assertEqual(dropouts["status"], "fail")
        self.assertIn("rfscan", " ".join(dropouts["detail"]))

    def test_pauses_are_reported_separately_and_are_not_findings(self):
        spec = (
            steady(60)
            + [(0.008, 8), (0.008, 4), (0.008, 2)]
            + [(0.500, 2)]
            + [(0.008, 4), (0.008, 8)]
            + steady(60)
        )
        report = logi_rx.analyse(samples_from(spec))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        pauses = [r for r in results if r["id"] == "watch-pauses"][0]
        self.assertEqual(pauses["status"], "info")
        self.assertNotIn(pauses["status"], logi_rx.EXIT_STATUSES)
        dropouts = [r for r in results if r["id"] == "watch-dropouts"][0]
        self.assertEqual(dropouts["status"], "ok")


# ------------------------------------------------------- watch: the reader


def encode_event(seconds, etype, code, value):
    whole = int(seconds)
    micros = int(round((seconds - whole) * 1_000_000))
    return struct.pack(logi_rx.EVENT_FMT, whole, micros, etype, code, value)


class TestReadEvents(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="logi-rx-evdev-"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_struct_parsing_from_a_stream(self):
        path = self.dir / "events"
        with open(path, "wb") as handle:
            handle.write(encode_event(1000.000, logi_rx.EV_REL, logi_rx.REL_X, 5))
            handle.write(encode_event(1000.008, logi_rx.EV_REL, logi_rx.REL_Y, -3))
        with open(path, "rb") as handle:
            samples = logi_rx.read_events(handle, duration=1, blocking=True)
        self.assertEqual(len(samples), 2)
        self.assertAlmostEqual(samples[0][0], 1000.0, places=5)
        self.assertEqual(samples[0][2], 5)
        self.assertEqual(samples[1][1], logi_rx.REL_Y)
        self.assertEqual(samples[1][2], -3)

    def test_key_events_are_not_counted_as_motion(self):
        # EV_KEY on a touchpad is a click. Counting it as movement would make a
        # motionless run look like a healthy one.
        EV_KEY = 0x01
        path = self.dir / "events"
        with open(path, "wb") as handle:
            handle.write(encode_event(1000.000, EV_KEY, 272, 1))
            handle.write(encode_event(1000.004, EV_KEY, 272, 0))
            handle.write(encode_event(1000.008, logi_rx.EV_REL, logi_rx.REL_X, 9))
        with open(path, "rb") as handle:
            samples = logi_rx.read_events(handle, duration=1, blocking=True)
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0][2], 9)

    def test_non_axis_rel_events_are_ignored(self):
        REL_WHEEL = 0x08
        path = self.dir / "events"
        with open(path, "wb") as handle:
            handle.write(encode_event(1000.0, logi_rx.EV_REL, REL_WHEEL, 1))
            handle.write(encode_event(1000.008, logi_rx.EV_REL, logi_rx.REL_X, 4))
        with open(path, "rb") as handle:
            samples = logi_rx.read_events(handle, duration=1, blocking=True)
        self.assertEqual([s[1] for s in samples], [logi_rx.REL_X])

    def test_a_truncated_trailing_record_is_ignored(self):
        path = self.dir / "events"
        with open(path, "wb") as handle:
            handle.write(encode_event(1000.0, logi_rx.EV_REL, logi_rx.REL_X, 4))
            handle.write(b"\x00" * (logi_rx.EVENT_SIZE - 3))
        with open(path, "rb") as handle:
            samples = logi_rx.read_events(handle, duration=1, blocking=True)
        self.assertEqual(len(samples), 1)

    @unittest.skipUnless(HAVE_FIFO, "needs os.mkfifo")
    def test_reads_a_live_fifo_stream(self):
        path = self.dir / "fifo"
        os.mkfifo(path)
        spec = steady(60) + [(0.200, 30)] + steady(60)

        def writer():
            with open(path, "wb") as handle:
                now = 1000.0
                for interval, delta in spec:
                    now += interval
                    handle.write(encode_event(now, logi_rx.EV_REL, logi_rx.REL_X, delta))
                handle.flush()

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            with open(path, "rb") as handle:
                samples = logi_rx.read_events(handle, duration=5, blocking=True)
        finally:
            thread.join(timeout=10)

        self.assertEqual(len(samples), len(spec))
        report = logi_rx.analyse(samples)
        self.assertEqual(report["dropouts"], 1)
        self.assertEqual(report["threshold_source"], "calibrated")


# ------------------------------------------------------------- exit codes


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestExitCodes(TreeCase):
    """1 means, and only means, a finding to act on. Anything that reached no
    verdict is 2. Matches rfscan and freshcheck."""

    def test_not_linux_is_could_not_determine(self):
        logi_rx.PLATFORM = "win32"
        report = logi_rx.build_report(Args())
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)

    def test_no_logitech_device_is_could_not_determine(self):
        self.write("/sys/bus/usb/devices/usb1/idVendor", "1d6b")
        report = logi_rx.build_report(Args())
        self.assertEqual(report["error"], "no-device")
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)

    def test_unknown_device_name_is_could_not_determine(self):
        self.build_standard_tree()
        report = logi_rx.build_report(Args(device="9-9"))
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)

    def test_findings_exit_one(self):
        self.build_standard_tree()
        report = logi_rx.build_report(Args())
        self.assertTrue(any(r["status"] in logi_rx.EXIT_STATUSES for r in report["results"]))
        self.assertEqual(report["exit_code"], logi_rx.FINDINGS)

    def test_clean_system_exits_zero(self):
        receiver = self.build_standard_tree(
            dict(RECEIVER_ATTRS, **{"power/control": "on", "power/wakeup": "enabled"})
        )
        self.write(logi_rx.UDEV_RULE, logi_rx.build_rule(receiver))
        self.write(logi_rx.PROC_MODULES, "hid_logitech_dj 32768 0 - Live 0x0000\n")
        report = logi_rx.build_report(Args())
        self.assertEqual(report["counts"]["warn"], 0)
        self.assertEqual(report["counts"]["fail"], 0)
        self.assertEqual(report["exit_code"], logi_rx.NO_FINDINGS)

    def test_watch_with_no_pointer_is_could_not_determine(self):
        self.build_standard_tree()
        report = logi_rx.build_report(Args(watch=True))
        self.assertEqual(report["exit_code"], logi_rx.COULD_NOT_DETERMINE)

    def test_watch_permission_denied_is_could_not_determine(self):
        results = [
            logi_rx.make("watch", "unknown", "Permission denied reading /dev/input/event5")
        ]
        self.assertNotIn(results[0]["status"], logi_rx.EXIT_STATUSES)

    def test_watch_dropouts_exit_one(self):
        spec = steady(60) + [(0.200, 30)] + steady(60)
        report = logi_rx.analyse(samples_from(spec))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        self.assertTrue(any(r["status"] in logi_rx.EXIT_STATUSES for r in results))

    def test_watch_clean_run_has_no_findings(self):
        report = logi_rx.analyse(samples_from(steady(200)))
        results = logi_rx.watch_results(report, "dev", "/dev/input/event5")
        self.assertFalse(any(r["status"] in logi_rx.EXIT_STATUSES for r in results))


# ------------------------------------------------------- rendering / json


@unittest.skipUnless(REAL_SYSFS, SYSFS_REASON)
class TestRenderAndJson(TreeCase):
    def test_skipped_never_renders_under_a_passing_heading(self):
        import contextlib
        import io

        attrs = {k: v for k, v in RECEIVER_ATTRS.items() if k != "power/wakeup"}
        self.build_standard_tree(attrs)
        report = logi_rx.build_report(Args())
        self.assertTrue(any(r["status"] == "skipped" for r in report["results"]))

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            logi_rx.render(logi_rx.Out(color=False), report)
        text = buffer.getvalue()
        self.assertIn("Not applicable", text)
        passed = text.split("Passed")[1] if "Passed" in text else ""
        self.assertNotIn("does not support remote wakeup", passed)

    def test_json_report_is_valid_and_complete(self):
        self.build_standard_tree()
        report = logi_rx.build_report(Args())
        blob = json.dumps(report, indent=2, sort_keys=True, default=str)
        loaded = json.loads(blob)
        self.assertEqual(loaded["tool"], "logi-rx")
        self.assertEqual(loaded["mode"], "audit")
        self.assertTrue(loaded["results"])
        for entry in loaded["results"]:
            self.assertIn(entry["status"], logi_rx.STATUS_ORDER)
            for key in ("id", "check", "status", "summary", "detail", "fix"):
                self.assertIn(key, entry)

    def test_json_watch_payload_carries_threshold_and_gaps(self):
        # This is what makes the A/B port comparison mechanical: save a run,
        # move the dongle, diff the two.
        spec = steady(60) + [(0.200, 30)] + steady(60)
        analysis = logi_rx.analyse(samples_from(spec))
        blob = json.loads(json.dumps(analysis, default=str))
        self.assertEqual(blob["threshold_source"], "calibrated")
        self.assertIn("threshold_ms", blob)
        self.assertEqual(len(blob["gaps"]), 1)
        self.assertEqual(blob["gaps"][0]["classification"], "dropout")


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
        self.assertEqual(logi_rx.safe_text("naïve"), "na\\xefve")
        self.assertEqual(logi_rx.rule_char(), "-")


if __name__ == "__main__":
    unittest.main(verbosity=2)
