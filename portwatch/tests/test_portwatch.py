#!/usr/bin/env python3
"""
Tests for portwatch.

    python3 -m unittest discover -s portwatch/tests -t portwatch/tests -v
    ./portwatch/tests/test_portwatch.py

Standard library only, same rule as the tools.

Two things here are easy to get silently wrong, so they get the most attention.

The first is hex address decoding. /proc/net prints each 32-bit word
little-endian, so 0100007F is 127.0.0.1; read big-endian it is 1.0.0.127, which
is a perfectly plausible address and completely incorrect. Nothing downstream
would notice.

The second is the diff's idea of identity. A service moving from 127.0.0.1:8080
to 0.0.0.0:8080 has just become reachable from the network, and rendering that
as one disappearance plus one appearance loses precisely the thing worth
knowing.
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
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))

import portwatch  # noqa: E402

FIXED_NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
BTIME = 1786000000


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class Args:
    def __init__(self, **kw):
        self.save = kw.get("save", False)
        self.diff = kw.get("diff", None)
        self.list = kw.get("list", False)
        self.unix = kw.get("unix", False)
        self.all = kw.get("all", False)
        self.json = kw.get("json", False)
        self.no_color = kw.get("no_color", True)


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="portwatch-test-"))
        self.state = pathlib.Path(tempfile.mkdtemp(prefix="portwatch-state-"))
        self._saved = (
            portwatch.SYSROOT,
            portwatch.PLATFORM,
            portwatch.IS_ROOT,
            portwatch.NOW,
            portwatch.STATE_DIR,
        )
        portwatch.SYSROOT = self.root
        portwatch.PLATFORM = "linux"
        portwatch.IS_ROOT = False
        portwatch.NOW = FIXED_NOW
        portwatch.STATE_DIR = self.state
        self.install_proc_net()

    def tearDown(self):
        (
            portwatch.SYSROOT,
            portwatch.PLATFORM,
            portwatch.IS_ROOT,
            portwatch.NOW,
            portwatch.STATE_DIR,
        ) = self._saved
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.state, ignore_errors=True)

    def write(self, path, content):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def install_proc_net(self):
        self.write("/proc/net/tcp", fixture("proc-net-tcp.txt"))
        self.write("/proc/net/tcp6", fixture("proc-net-tcp6.txt"))
        self.write("/proc/net/udp", fixture("proc-net-udp.txt"))
        self.write("/proc/net/udp6", fixture("proc-net-udp6.txt"))
        self.write("/proc/net/unix", fixture("proc-net-unix.txt"))
        self.write(portwatch.PORT_RANGE_FILE, fixture("ip_local_port_range.txt"))
        self.write("/proc/stat", f"cpu 0 0 0 0\nbtime {BTIME}\nprocesses 100\n")

    def add_process(self, pid, name, cmdline, inodes, uid=0, start_ticks=1000,
                    cgroup="0::/system.slice/example.service"):
        base = f"/proc/{pid}"
        self.write(f"{base}/comm", name + "\n")
        self.write(f"{base}/cmdline", "\0".join(cmdline) + "\0")
        self.write(f"{base}/status", f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        tail = " ".join(["0"] * 18)
        self.write(f"{base}/stat", f"{pid} ({name}) S {tail} {start_ticks} 0 0 0\n")
        self.write(f"{base}/cgroup", cgroup + "\n")
        fd_dir = self.root / base.lstrip("/") / "fd"
        fd_dir.mkdir(parents=True, exist_ok=True)
        for index, inode in enumerate(inodes):
            os.symlink(f"socket:[{inode}]", fd_dir / str(index + 3))

    def deny_process(self, pid):
        """A /proc/<pid> whose fd directory cannot be listed, which is what an
        unprivileged run sees for everybody else's processes."""
        base = f"/proc/{pid}"
        self.write(f"{base}/comm", "secret\n")
        # No fd directory at all: iterdir raises, which is the same observable
        # outcome as EACCES and does not need real permission bits.


# ----------------------------------------------------------- address decode


class TestAddressDecode(unittest.TestCase):
    def test_ipv4_is_little_endian_per_word(self):
        self.assertEqual(portwatch.decode_v4("0100007F"), "127.0.0.1")

    def test_naive_big_endian_read_would_be_plausible_and_wrong(self):
        # The failure this guards: 1.0.0.127 is a valid-looking address and
        # nothing downstream would flag it.
        import socket as socket_module
        import struct

        naive = socket_module.inet_ntoa(struct.pack(">I", int("0100007F", 16)))
        self.assertEqual(naive, "1.0.0.127")
        self.assertNotEqual(portwatch.decode_v4("0100007F"), naive)

    def test_wildcard_and_ports(self):
        self.assertEqual(portwatch.decode_v4("00000000"), "0.0.0.0")
        self.assertEqual(portwatch.split_endpoint("0100007F:1F90"), ("0100007F", 8080))

    def test_ipv6_four_word_reassembly(self):
        self.assertEqual(portwatch.decode_v6("0" * 32), "::")
        self.assertEqual(
            portwatch.decode_v6("00000000000000000000000001000000"), "::1"
        )

    def test_ipv4_mapped_is_normalised_to_ipv4(self):
        # Left alone, a dual-stack listener becomes a second distinct listener
        # and every diff carries a phantom pair.
        address, family = portwatch.decode_address("0000000000000000FFFF00000100007F")
        self.assertEqual(address, "127.0.0.1")
        self.assertEqual(family, "ipv4-mapped")

    def test_family_is_reported_for_each_width(self):
        self.assertEqual(portwatch.decode_address("0100007F")[1], "ipv4")
        self.assertEqual(portwatch.decode_address("0" * 32)[1], "ipv6")

    def test_unrecognised_width_raises(self):
        with self.assertRaises(ValueError):
            portwatch.decode_address("ABC")

    def test_wildcard_and_loopback_helpers(self):
        self.assertTrue(portwatch.is_wildcard("0.0.0.0"))
        self.assertTrue(portwatch.is_wildcard("::"))
        self.assertFalse(portwatch.is_wildcard("127.0.0.1"))
        self.assertTrue(portwatch.is_loopback("127.0.0.1"))
        self.assertTrue(portwatch.is_loopback("::1"))
        self.assertFalse(portwatch.is_loopback("0.0.0.0"))


# ------------------------------------------------------------ /proc parsing


class TestProcNetParser(unittest.TestCase):
    def setUp(self):
        self.tcp, self.tcp_skipped = portwatch.parse_proc_net(
            fixture("proc-net-tcp.txt"), "tcp"
        )
        self.udp, self.udp_skipped = portwatch.parse_proc_net(
            fixture("proc-net-udp.txt"), "udp"
        )

    def test_only_state_0a_is_listening(self):
        ports = sorted(entry["port"] for entry in self.tcp)
        self.assertEqual(ports, [22, 53, 8080])

    def test_established_and_time_wait_are_excluded(self):
        # 8B1B is an outbound connection and 1F91 is TIME_WAIT. Neither is a
        # service waiting for anything.
        self.assertNotIn(35611, [entry["port"] for entry in self.tcp])
        self.assertNotIn(8081, [entry["port"] for entry in self.tcp])

    def test_addresses_decode_correctly(self):
        by_port = {entry["port"]: entry for entry in self.tcp}
        self.assertEqual(by_port[8080]["address"], "127.0.0.1")
        self.assertEqual(by_port[22]["address"], "0.0.0.0")

    def test_inode_and_uid_are_captured(self):
        by_port = {entry["port"]: entry for entry in self.tcp}
        self.assertEqual(by_port[8080]["inode"], 100001)
        self.assertEqual(by_port[22]["uid"], 0)

    def test_malformed_line_is_skipped_and_counted(self):
        self.assertEqual(self.tcp_skipped, 1)

    def test_udp_bound_with_no_peer_is_included(self):
        ports = sorted(entry["port"] for entry in self.udp)
        self.assertEqual(ports, [53, 68, 59844])

    def test_udp_with_a_peer_is_excluded(self):
        # An outbound DNS query socket is bound, but it is not a service.
        self.assertNotIn(50000, [entry["port"] for entry in self.udp])

    def test_udp_is_labelled_as_not_a_listen_state(self):
        # UDP has no listen state, so the concepts are labelled differently
        # rather than being flattened together.
        self.assertTrue(all(not entry["tcp_listening"] for entry in self.udp))
        self.assertTrue(all(entry["tcp_listening"] for entry in self.tcp))

    def test_ipv6_table_parses_and_normalises(self):
        sockets, _ = portwatch.parse_proc_net(fixture("proc-net-tcp6.txt"), "tcp6")
        by_port = {entry["port"]: entry for entry in sockets}
        self.assertEqual(by_port[22]["address"], "::")
        self.assertEqual(by_port[8080]["address"], "127.0.0.1")
        self.assertEqual(by_port[8080]["family"], "ipv4-mapped")
        self.assertEqual(by_port[5353]["address"], "::1")

    def test_unix_listening_only(self):
        sockets, _ = portwatch.parse_proc_net_unix(fixture("proc-net-unix.txt"))
        paths = sorted(entry["address"] for entry in sockets)
        self.assertEqual(paths, ["/run/docker.sock", "/run/systemd/private"])
        self.assertNotIn("/run/dbus/system_bus_socket", paths)


# ------------------------------------------------------------- attribution


class TestAttribution(TreeCase):
    def test_inode_resolves_to_the_owning_process(self):
        self.add_process(4242, "nginx", ["/usr/bin/nginx", "-g", "daemon off;"], [100001])
        owners, scanned, denied = portwatch.socket_owners()
        self.assertIn(100001, owners)
        self.assertEqual(owners[100001]["pid"], 4242)
        self.assertEqual(owners[100001]["name"], "nginx")
        self.assertEqual(denied, 0)

    def test_cmdline_is_split_on_nul(self):
        self.add_process(4242, "nginx", ["/usr/bin/nginx", "-g", "daemon off;"], [100001])
        owners, _, _ = portwatch.socket_owners()
        self.assertEqual(
            owners[100001]["cmdline"], ["/usr/bin/nginx", "-g", "daemon off;"]
        )

    def test_start_time_is_captured(self):
        # Without it, "the same service restarted" and "a different process now
        # holds this port" look identical.
        self.add_process(4242, "nginx", ["nginx"], [100001], start_ticks=5000)
        owners, _, _ = portwatch.socket_owners()
        self.assertEqual(owners[100001]["start_ticks"], 5000)
        self.assertAlmostEqual(
            owners[100001]["start_epoch"],
            BTIME + 5000 / portwatch.clock_ticks(),
            places=3,
        )

    def test_stat_parsing_survives_a_comm_containing_spaces(self):
        self.add_process(4243, "we ird (proc)", ["thing"], [100002], start_ticks=777)
        owners, _, _ = portwatch.socket_owners()
        self.assertEqual(owners[100002]["start_ticks"], 777)

    def test_uid_is_read_from_status(self):
        self.add_process(4242, "nginx", ["nginx"], [100001], uid=33)
        owners, _, _ = portwatch.socket_owners()
        self.assertEqual(owners[100001]["uid"], 33)

    def test_cgroup_is_reported_without_resolving_container_names(self):
        self.add_process(
            4244, "app", ["app"], [100003],
            cgroup="0::/system.slice/docker-abc123.scope",
        )
        owners, _, _ = portwatch.socket_owners()
        entry = owners[100003]
        self.assertEqual(entry["cgroup"], "/system.slice/docker-abc123.scope")
        self.assertTrue(entry["in_container"])
        # No attempt is made to name the container.
        self.assertNotIn("container_name", entry)

    def test_unit_like_cgroup_is_distinguished(self):
        self.add_process(1, "systemd", ["systemd"], [100001],
                         cgroup="0::/system.slice/sshd.service")
        self.add_process(2, "shell", ["bash"], [100002], cgroup="0::/")
        owners, _, _ = portwatch.socket_owners()
        self.assertTrue(owners[100001]["unit_like"])
        self.assertFalse(owners[100002]["unit_like"])

    def test_unreadable_fd_directory_is_counted_as_denied(self):
        self.add_process(4242, "mine", ["mine"], [100001])
        self.deny_process(9999)
        owners, scanned, denied = portwatch.socket_owners()
        self.assertEqual(denied, 1)
        self.assertEqual(scanned, 1)
        self.assertIn(100001, owners)


class TestUnprivilegedLimitation(TreeCase):
    def test_socket_is_found_but_owner_is_unattributed(self):
        self.deny_process(9999)
        report = portwatch.build_report(Args())
        listeners = report["snapshot"]["listeners"]
        by_port = {item["port"]: item for item in listeners if item["protocol"] == "tcp"}
        self.assertIn(22, by_port)
        self.assertIsNone(by_port[22]["owner"])

    def test_limitation_is_stated_loudly_not_rendered_as_absence(self):
        # unknown because we could not look is categorically different from
        # unknown because there is nothing there.
        self.deny_process(9999)
        report = portwatch.build_report(Args())
        finding = [r for r in report["results"] if r["check"] == "attribution"]
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0]["status"], "unknown")
        joined = " ".join(finding[0]["detail"])
        self.assertIn("not a statement that", joined)
        self.assertIn("sudo portwatch", finding[0]["fix"])

    def test_limitation_appears_in_json_too(self):
        self.deny_process(9999)
        report = portwatch.build_report(Args())
        payload = json.loads(json.dumps(report, default=str))
        self.assertEqual(payload["snapshot"]["processes_denied"], 1)
        self.assertFalse(payload["snapshot"]["captured_as_root"])

    def test_root_run_makes_no_such_claim(self):
        portwatch.IS_ROOT = True
        self.add_process(4242, "nginx", ["nginx"], [100001])
        report = portwatch.build_report(Args())
        self.assertFalse([r for r in report["results"] if r["check"] == "attribution"])


# --------------------------------------------------------------- ephemeral


class TestEphemeral(TreeCase):
    def test_range_is_read_not_hardcoded(self):
        self.write(portwatch.PORT_RANGE_FILE, "10000\t20000\n")
        self.assertEqual(portwatch.ephemeral_range(), (10000, 20000))

    def test_fallback_when_unreadable(self):
        # The literal is deliberate. Comparing against EPHEMERAL_FALLBACK would
        # be self-referential and would pass for any value of it, including one
        # wide enough to swallow every real service.
        (self.root / portwatch.PORT_RANGE_FILE.lstrip("/")).unlink()
        self.assertEqual(portwatch.ephemeral_range(), (32768, 60999))

    def test_fallback_does_not_swallow_well_known_services(self):
        # The behavioural half: whatever the fallback is, ports 22 and 53 have
        # to survive it, or an unreadable sysctl silently empties the report.
        (self.root / portwatch.PORT_RANGE_FILE.lstrip("/")).unlink()
        report = portwatch.build_report(Args())
        ports = [item["port"] for item in report["snapshot"]["listeners"]]
        self.assertIn(22, ports)
        self.assertIn(53, ports)
        self.assertNotIn(59844, ports)

    def test_ephemeral_sockets_are_filtered_by_default(self):
        report = portwatch.build_report(Args())
        ports = [item["port"] for item in report["snapshot"]["listeners"]]
        self.assertNotIn(59844, ports)

    def test_suppression_is_counted_and_reported_never_silent(self):
        # A silent filter is a place for a real finding to hide.
        report = portwatch.build_report(Args())
        self.assertEqual(report["snapshot"]["ephemeral_suppressed"], 1)
        finding = [r for r in report["results"] if r["check"] == "ephemeral"]
        self.assertEqual(len(finding), 1)
        self.assertIn("32768-60999", finding[0]["summary"])
        self.assertEqual(finding[0]["fix"], "portwatch --all")

    def test_all_flag_includes_them(self):
        report = portwatch.build_report(Args(all=True))
        ports = [item["port"] for item in report["snapshot"]["listeners"]]
        self.assertIn(59844, ports)
        self.assertEqual(report["snapshot"]["ephemeral_suppressed"], 0)

    def test_a_changed_range_changes_what_is_filtered(self):
        self.write(portwatch.PORT_RANGE_FILE, "5000\t60000\n")
        report = portwatch.build_report(Args())
        ports = [item["port"] for item in report["snapshot"]["listeners"]]
        self.assertNotIn(5353, ports)
        self.assertIn(22, ports)


class TestUnixSockets(TreeCase):
    def test_unix_sockets_are_off_by_default(self):
        report = portwatch.build_report(Args())
        self.assertFalse([i for i in report["snapshot"]["listeners"] if i["protocol"] == "unix"])

    def test_unix_flag_includes_listening_sockets(self):
        report = portwatch.build_report(Args(unix=True))
        paths = sorted(
            i["address"] for i in report["snapshot"]["listeners"] if i["protocol"] == "unix"
        )
        self.assertEqual(paths, ["/run/docker.sock", "/run/systemd/private"])


# --------------------------------------------------------------- snapshots


class TestSnapshots(TreeCase):
    def test_schema_round_trips(self):
        self.add_process(4242, "nginx", ["nginx"], [100001])
        report = portwatch.build_report(Args(save=True))
        path = pathlib.Path(report["saved_to"])
        self.assertTrue(path.exists())
        loaded = portwatch.load_snapshot(path)
        self.assertEqual(loaded["version"], portwatch.SCHEMA_VERSION)
        self.assertEqual(
            [i["port"] for i in loaded["listeners"]],
            [i["port"] for i in report["snapshot"]["listeners"]],
        )

    def test_snapshot_records_whether_it_was_captured_as_root(self):
        portwatch.IS_ROOT = True
        report = portwatch.build_report(Args(save=True))
        loaded = portwatch.load_snapshot(pathlib.Path(report["saved_to"]))
        self.assertTrue(loaded["captured_as_root"])

    def test_current_schema_version_is_one(self):
        # Pinned to a literal on purpose. Bumping the schema is a deliberate
        # act that invalidates every stored baseline, so it should have to
        # change this line and the README rather than passing silently.
        self.assertEqual(portwatch.SCHEMA_VERSION, 1)

    def test_a_snapshot_from_any_other_version_is_refused(self):
        path = self.state / "future.json"
        path.write_text(
            json.dumps({"version": portwatch.SCHEMA_VERSION + 1, "listeners": []}),
            encoding="utf-8",
        )
        with self.assertRaises(portwatch.SnapshotError):
            portwatch.load_snapshot(path)

    def test_unknown_version_is_refused_with_a_clear_message(self):
        # Parsing an unknown layout optimistically produces a diff whose errors
        # all look like real findings.
        path = self.state / "bad.json"
        path.write_text(json.dumps({"version": 99, "listeners": []}), encoding="utf-8")
        with self.assertRaises(portwatch.SnapshotError) as caught:
            portwatch.load_snapshot(path)
        message = str(caught.exception)
        self.assertIn("99", message)
        self.assertIn(str(portwatch.SCHEMA_VERSION), message)
        self.assertIn("--save", message)

    def test_missing_version_is_refused(self):
        path = self.state / "old.json"
        path.write_text(json.dumps({"listeners": []}), encoding="utf-8")
        with self.assertRaises(portwatch.SnapshotError):
            portwatch.load_snapshot(path)

    def test_invalid_json_is_refused(self):
        path = self.state / "junk.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(portwatch.SnapshotError):
            portwatch.load_snapshot(path)

    def test_state_dir_uses_xdg_state_home(self):
        portwatch.STATE_DIR = None
        saved = os.environ.get("XDG_STATE_HOME")
        try:
            os.environ["XDG_STATE_HOME"] = "/tmp/xdgstate"
            # State, not config: these are captured machine state, not settings.
            self.assertEqual(
                portwatch.state_dir(), pathlib.Path("/tmp/xdgstate") / "portwatch"
            )
        finally:
            if saved is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = saved
            portwatch.STATE_DIR = self.state

    def test_list_shows_stored_snapshots(self):
        portwatch.build_report(Args(save=True))
        report = portwatch.build_report(Args(list=True))
        self.assertEqual(len(report["snapshots"]), 1)


# -------------------------------------------------------------------- diff


def listener(protocol, address, port, owner=None, inode=1):
    return {
        "protocol": protocol,
        "address": address,
        "family": "ipv4",
        "port": port,
        "state": "0A",
        "tcp_listening": True,
        "uid": 0,
        "inode": inode,
        "owner": owner,
    }


def owner(name, cmdline, pid=100, start_epoch=1000.0, cgroup="/system.slice/x.service"):
    return {
        "pid": pid,
        "name": name,
        "cmdline": cmdline,
        "uid": 0,
        "start_ticks": 1,
        "start_epoch": start_epoch,
        "cgroup": cgroup,
        "in_container": False,
        "unit_like": True,
    }


def snapshot(listeners, as_root=False):
    return {
        "version": portwatch.SCHEMA_VERSION,
        "captured_at": FIXED_NOW.isoformat(),
        "captured_as_root": as_root,
        "listeners": listeners,
    }


class TestDiff(unittest.TestCase):
    def test_appeared(self):
        events, _ = portwatch.diff_snapshots(
            snapshot([]), snapshot([listener("tcp", "0.0.0.0", 8080)])
        )
        self.assertEqual([e["change"] for e in events], ["appeared"])

    def test_disappeared(self):
        events, _ = portwatch.diff_snapshots(
            snapshot([listener("tcp", "0.0.0.0", 8080)]), snapshot([])
        )
        self.assertEqual([e["change"] for e in events], ["disappeared"])

    def test_owner_changed(self):
        before = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("python", ["python", "app.py"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual([e["change"] for e in events], ["owner-changed"])
        self.assertEqual(events[0]["from_owner"], "nginx")
        self.assertEqual(events[0]["to_owner"], "python app.py")

    def test_restarted_is_same_cmdline_different_pid(self):
        before = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"], pid=100, start_epoch=1.0))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"], pid=200, start_epoch=9.0))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual([e["change"] for e in events], ["restarted"])
        self.assertEqual((events[0]["from_pid"], events[0]["to_pid"]), (100, 200))

    def test_restarted_is_not_a_finding(self):
        # Services restart. A tool that flagged every one would teach you to
        # skip past it.
        self.assertNotIn("restarted", portwatch.EXIT_STATUSES)
        before = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"], pid=100, start_epoch=1.0))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"], pid=200, start_epoch=9.0))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        results = portwatch.observations(events, snapshot(after))
        self.assertEqual(results, [])

    def test_unchanged_produces_nothing(self):
        same = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"]))]
        events, _ = portwatch.diff_snapshots(snapshot(same), snapshot(list(same)))
        self.assertEqual(events, [])

    def test_rebound_is_one_event_not_an_appear_plus_a_disappear(self):
        # The highest-signal thing this tool can report: a local-only service
        # just became reachable from the network.
        before = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change"], "rebound")
        self.assertEqual(events[0]["from_address"], "127.0.0.1")
        self.assertEqual(events[0]["to_address"], "0.0.0.0")
        self.assertTrue(events[0]["newly_reachable"])
        self.assertTrue(events[0]["owner_verified"])

    def test_rebound_the_other_direction_is_not_newly_reachable(self):
        before = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual(events[0]["change"], "rebound")
        self.assertFalse(events[0]["newly_reachable"])

    def test_different_processes_on_the_same_port_are_not_a_rebind(self):
        before = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("python", ["python", "app.py"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual(
            sorted(e["change"] for e in events), ["appeared", "disappeared"]
        )

    def test_unattributed_rebind_is_paired_but_marked_unverified(self):
        before = [listener("tcp", "127.0.0.1", 8080)]
        after = [listener("tcp", "0.0.0.0", 8080)]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual(events[0]["change"], "rebound")
        self.assertFalse(events[0]["owner_verified"])

    def test_different_ports_are_never_paired_as_a_rebind(self):
        before = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "0.0.0.0", 9090, owner("nginx", ["nginx"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        self.assertEqual(
            sorted(e["change"] for e in events), ["appeared", "disappeared"]
        )

    def test_identity_key_is_protocol_address_port(self):
        item = listener("tcp", "0.0.0.0", 8080)
        self.assertEqual(portwatch.listener_key(item), ("tcp", "0.0.0.0", 8080))


class TestObservations(unittest.TestCase):
    def test_exposure_change_is_reported_as_an_observation(self):
        before = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        after = [listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"]))]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        results = portwatch.observations(events, snapshot(after))
        exposure = [r for r in results if r["check"] == "exposure"][0]
        self.assertEqual(exposure["status"], "info")
        self.assertNotIn(exposure["status"], portwatch.EXIT_STATUSES)

    def test_new_process_outside_a_unit_is_noted_without_judgement(self):
        rogue = owner("thing", ["./thing"], cgroup="/")
        rogue["unit_like"] = False
        after = [listener("tcp", "0.0.0.0", 9999, rogue)]
        events, _ = portwatch.diff_snapshots(snapshot([]), snapshot(after))
        results = portwatch.observations(events, snapshot(after))
        unmanaged = [r for r in results if r["check"] == "unmanaged"][0]
        self.assertEqual(unmanaged["status"], "info")
        self.assertIn("Not inherently wrong", " ".join(unmanaged["detail"]))

    def test_no_observation_ranks_or_scores_anything(self):
        rogue = owner("thing", ["./thing"], cgroup="/")
        rogue["unit_like"] = False
        before = [listener("tcp", "127.0.0.1", 8080, owner("nginx", ["nginx"]))]
        after = [
            listener("tcp", "0.0.0.0", 8080, owner("nginx", ["nginx"])),
            listener("tcp", "0.0.0.0", 9999, rogue),
        ]
        events, _ = portwatch.diff_snapshots(snapshot(before), snapshot(after))
        results = portwatch.observations(events, snapshot(after))
        self.assertTrue(results)
        for result in results:
            self.assertEqual(result["status"], "info")
            text = (result["summary"] + " " + " ".join(result["detail"])).lower()
            for word in ("suspicious", "risk", "severity", "score", "malicious", "threat"):
                self.assertNotIn(word, text)


class TestRootMismatch(TreeCase):
    def make_baseline(self, as_root, listeners):
        path = self.state / f"base-{as_root}.json"
        path.write_text(json.dumps(snapshot(listeners, as_root=as_root)), encoding="utf-8")
        return path

    def test_privileged_baseline_against_unprivileged_run_is_flagged(self):
        # Every attributed listener becomes unattributed, which would render as
        # a wall of ownership changes that are entirely an artefact.
        base = self.make_baseline(True, [listener("tcp", "0.0.0.0", 22, owner("sshd", ["sshd"]))])
        portwatch.IS_ROOT = False
        report = portwatch.build_report(Args(diff=str(base)))
        self.assertEqual(report["error"], "root-mismatch")
        finding = [r for r in report["results"] if r["check"] == "root-mismatch"][0]
        self.assertEqual(finding["status"], "unknown")
        self.assertIn("suppressed", " ".join(finding["detail"]))

    def test_ownership_classes_are_suppressed_on_mismatch(self):
        base = self.make_baseline(True, [listener("tcp", "0.0.0.0", 22, owner("sshd", ["sshd"]))])
        portwatch.IS_ROOT = False
        report = portwatch.build_report(Args(diff=str(base)))
        classes = {e["change"] for e in report["events"]}
        self.assertNotIn("owner-changed", classes)
        self.assertNotIn("restarted", classes)

    def test_appeared_and_disappeared_survive_a_mismatch(self):
        # Those do not depend on being able to see the owner.
        base = self.make_baseline(True, [listener("tcp", "10.0.0.1", 9999, owner("x", ["x"]))])
        portwatch.IS_ROOT = False
        report = portwatch.build_report(Args(diff=str(base)))
        self.assertIn("disappeared", {e["change"] for e in report["events"]})

    def test_matching_privileges_are_not_flagged(self):
        base = self.make_baseline(False, [])
        portwatch.IS_ROOT = False
        report = portwatch.build_report(Args(diff=str(base)))
        self.assertNotEqual(report["error"], "root-mismatch")


# ------------------------------------------------------------- exit codes


class TestExitCodes(TreeCase):
    def test_plain_run_exits_zero(self):
        self.assertEqual(portwatch.build_report(Args())["exit_code"], portwatch.NO_CHANGES)

    def test_diff_with_no_baseline_exits_two_and_names_save(self):
        report = portwatch.build_report(Args(diff=""))
        self.assertEqual(report["error"], "no-baseline")
        self.assertEqual(report["exit_code"], portwatch.COULD_NOT_DETERMINE)
        finding = [r for r in report["results"] if r["check"] == "baseline"][0]
        self.assertEqual(finding["fix"], "portwatch --save")

    def test_diff_with_no_changes_exits_zero(self):
        portwatch.build_report(Args(save=True))
        report = portwatch.build_report(Args(diff=""))
        self.assertEqual(report["events"], [])
        self.assertEqual(report["exit_code"], portwatch.NO_CHANGES)

    def test_diff_with_changes_exits_one(self):
        portwatch.build_report(Args(save=True))
        # Drop a listener so the next capture differs.
        self.write("/proc/net/tcp", "\n".join(
            fixture("proc-net-tcp.txt").splitlines()[:2]) + "\n")
        report = portwatch.build_report(Args(diff=""))
        self.assertTrue(report["events"])
        self.assertEqual(report["exit_code"], portwatch.CHANGES_FOUND)

    def test_unparseable_snapshot_exits_two(self):
        path = self.state / "junk.json"
        path.write_text("{not json", encoding="utf-8")
        report = portwatch.build_report(Args(diff=str(path)))
        self.assertEqual(report["exit_code"], portwatch.COULD_NOT_DETERMINE)

    def test_unreadable_proc_net_exits_two(self):
        for name in ("tcp", "tcp6", "udp", "udp6"):
            (self.root / "proc/net" / name).unlink()
        report = portwatch.build_report(Args())
        self.assertEqual(report["error"], "proc-unreadable")
        self.assertEqual(report["exit_code"], portwatch.COULD_NOT_DETERMINE)

    def test_root_mismatch_exits_two(self):
        path = self.state / "base.json"
        path.write_text(json.dumps(snapshot([], as_root=True)), encoding="utf-8")
        report = portwatch.build_report(Args(diff=str(path)))
        self.assertEqual(report["exit_code"], portwatch.COULD_NOT_DETERMINE)

    def test_not_linux_exits_two(self):
        portwatch.PLATFORM = "win32"
        self.assertEqual(
            portwatch.build_report(Args())["exit_code"], portwatch.COULD_NOT_DETERMINE
        )

    def test_save_exits_zero(self):
        report = portwatch.build_report(Args(save=True))
        self.assertEqual(report["exit_code"], portwatch.NO_CHANGES)
        self.assertIsNotNone(report["saved_to"])


# --------------------------------------------------------- render and json


class TestRenderAndJson(TreeCase):
    def render_text(self, report):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            portwatch.render(portwatch.Out(color=False), report)
        return buffer.getvalue()

    def test_current_view_groups_dual_stack_pairs(self):
        # tcp 127.0.0.1:8080 and tcp6 ::ffff:127.0.0.1:8080 are one service.
        self.add_process(4242, "nginx", ["nginx"], [100001, 100011])
        report = portwatch.build_report(Args())
        groups = portwatch.group_listeners(report["snapshot"]["listeners"])
        port_8080 = [g for g in groups if g["port"] == 8080]
        self.assertEqual(len(port_8080), 1)

    def test_unattributed_listeners_on_one_port_are_not_merged_blindly(self):
        # Two specific addresses sharing a port are not a dual-stack pair, and
        # merging them would invent one service where there may be two. Only
        # the loopback and wildcard pairs are equivalent.
        groups = portwatch.group_listeners(
            [
                listener("tcp", "10.0.0.1", 53),
                listener("tcp", "10.0.0.2", 53),
            ]
        )
        self.assertEqual(len(groups), 2)

    def test_loopback_pair_is_merged_even_when_unattributed(self):
        groups = portwatch.group_listeners(
            [listener("udp", "127.0.0.1", 323), listener("udp6", "::1", 323)]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0]["addresses"]), ["127.0.0.1", "::1"])

    def test_wildcard_pair_is_merged(self):
        groups = portwatch.group_listeners(
            [listener("tcp", "0.0.0.0", 22), listener("tcp6", "::", 22)]
        )
        self.assertEqual(len(groups), 1)

    def test_current_view_marks_unattributed_owners(self):
        self.deny_process(9999)
        report = portwatch.build_report(Args())
        self.assertIn("not attributed", self.render_text(report))

    def test_diff_view_renders_rebound_as_one_line(self):
        # Baseline from the real fixture, then move port 8080 from loopback to
        # the wildcard so exactly one thing has changed.
        portwatch.build_report(Args(save=True))
        moved = fixture("proc-net-tcp.txt").replace("0100007F:1F90", "00000000:1F90")
        self.write("/proc/net/tcp", moved)
        report = portwatch.build_report(Args(diff=""))
        changes = [e["change"] for e in report["events"]]
        self.assertEqual(changes, ["rebound"])
        text = self.render_text(report)
        self.assertIn("REBOUND", text)
        self.assertIn("127.0.0.1 -> 0.0.0.0", text)
        self.assertIn("now reachable from the network", text)

    def test_output_disclaims_risk_scoring(self):
        report = portwatch.build_report(Args())
        text = self.render_text(report).lower()
        self.assertIn("does not rank", text)
        self.assertIn("chronicle", text)

    def test_json_has_no_scoring_keys(self):
        portwatch.build_report(Args(save=True))
        report = portwatch.build_report(Args(diff=""))
        payload = json.loads(json.dumps(report, default=str))

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

        forbidden = {"risk", "score", "severity", "suspicious", "threat", "confidence"}
        self.assertEqual(keys(payload) & forbidden, set())

    def test_json_is_valid_and_carries_the_snapshot(self):
        report = portwatch.build_report(Args())
        payload = json.loads(json.dumps(report, default=str))
        self.assertEqual(payload["tool"], "portwatch")
        self.assertEqual(payload["snapshot"]["version"], portwatch.SCHEMA_VERSION)
        for item in payload["snapshot"]["listeners"]:
            for key in ("protocol", "address", "port", "family", "inode"):
                self.assertIn(key, item)

    def test_change_classes_are_the_documented_set(self):
        portwatch.build_report(Args(save=True))
        self.write("/proc/net/tcp", "\n".join(
            fixture("proc-net-tcp.txt").splitlines()[:2]) + "\n")
        report = portwatch.build_report(Args(diff=""))
        for event in report["events"]:
            self.assertIn(event["change"], portwatch.CHANGE_CLASSES)


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
        self.assertEqual(portwatch.safe_text("naïve"), "na\\xefve")
        self.assertEqual(portwatch.rule_char(), "-")


if __name__ == "__main__":
    unittest.main(verbosity=2)
