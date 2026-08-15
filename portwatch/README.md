# portwatch

Snapshot listening sockets, diff against a baseline, report what changed.

`ss -tlnp` tells you what is listening right now. Nothing tells you what changed
since last week. "Port 8080 appeared on Tuesday, owned by a process that was not
here before" is a question you have on any machine you did not personally set
up, and there is no good answer for it.

Standard library only. No dependencies.

## No risk scoring

This tool reports what changed and does not rank it.

There is no risk score, no severity, and no "suspicious" label, because it has
no idea what your machine is for. A new listener on `0.0.0.0` is a deployment on
one box and an incident on another, and only you know which. A tool that guessed
would produce confident output that is wrong in a direction you cannot check.

Observations are reported as observations, at `info`, and a test asserts the
JSON contains no key named `risk`, `score`, `severity`, `suspicious`, `threat`
or `confidence`. Same constraint as `chronicle`'s adjacency rule, for the same
reason.

## Read-only with respect to system state

It writes snapshot files. That is the only thing it writes. It never kills a
process, closes a socket, or touches a firewall, and where an action is implied
the command is printed rather than run.

## Quick start

```sh
portwatch                     # what is listening now
portwatch --save              # write a baseline snapshot
portwatch --diff              # compare now against the latest baseline
portwatch --diff FILE         # against a specific snapshot
portwatch --list              # stored snapshots
portwatch --json
```

Pairs with `chronicle`, which answers the same question on a different axis:
what changed on this machine, and when.

## The data source

`/proc/net/{tcp,tcp6,udp,udp6}` read directly, not `ss`. `ss` output is a
formatting target rather than an API: its columns move between iproute2
versions and it truncates process names.

Three things in that format are easy to get silently wrong:

**Addresses are hex, little-endian per 32-bit word.** `0100007F` is
`127.0.0.1`. Read big-endian it is `1.0.0.127`, which is a perfectly plausible
address and completely incorrect, and nothing downstream would notice. Ports are
big-endian in the same line. Both directions are asserted by tests, including
the wrong one.

**IPv6 is four 32-bit words**, each little-endian, reassembled before
`inet_ntop`. **IPv4-mapped addresses** (`::ffff:127.0.0.1`) are how a dual-stack
listener appears and are normalised to plain IPv4; left alone the same service
becomes two distinct listeners and every diff carries a phantom pair.

**TCP listening is state `0A`** and nothing else. UDP has no listen state, so
"listening" there means bound with no peer. Those are different concepts and are
labelled differently rather than flattened together: each socket carries
`tcp_listening` saying which one it is.

`--unix` adds `/proc/net/unix` listening sockets. Off by default because a
typical machine has dozens and they would drown the table, but a new socket in
`/run` is a real signal.

## Process attribution and the root problem

Socket inodes are mapped to processes by scanning `/proc/*/fd/*` for
`socket:[<inode>]` symlinks. Per process it records name, full cmdline (which is
NUL-separated and needs splitting), UID, cgroup, and **start time**, which is
what distinguishes "the same service restarted" from "a different process now
holds this port". Those look identical without it.

**An unprivileged run can only read its own processes' file descriptors.** So it
identifies every socket correctly and attributes ownership only for your own
processes. Everything else is a listener with no owner.

That is reported loudly, in both human and JSON output, as a limit of what the
run could see rather than a statement that those sockets are unowned. It is the
freshcheck distinction applied to a data source: `unknown` because we could not
look is categorically different from `unknown` because there is nothing there.
The count of unreadable processes is in the JSON as `processes_denied`, and the
command to re-run with privileges is printed.

No workaround is attempted and it does not shell out to `sudo ss`.

The cgroup path is reported because a container's listener is a meaningfully
different finding from a host service. Container names are not resolved; the
path is what you get.

## Snapshots

JSON under `$XDG_STATE_HOME/portwatch/`, falling back to
`~/.local/state/portwatch/`. **State, not config**: these are captured machine
state the tool produced, not settings a human wrote, and `~/.config` would be
the wrong directory for them.

Every snapshot carries a `version` and a `captured_as_root` boolean.

**Version:** a snapshot from any other schema version is refused with a message
naming both versions and `--save`, rather than parsed optimistically. Parsing an
unknown layout produces a diff whose errors all look like real findings.

**Privilege:** diffing a root-captured baseline against an unprivileged run turns
every attributed listener into an unattributed one. That would render as a wall
of ownership changes which are entirely an artefact of how the two snapshots were
taken, and it is the single most likely way this tool could produce confusing
output. So the mismatch is detected and stated, the ownership-dependent classes
are suppressed, and the run exits 2. Appeared, disappeared and rebound are still
reported: those do not depend on seeing the owner.

## What makes two listeners the same

The identity key is `(protocol, local address, port)`. Everything else is a
property that can change while it remains the same listener, and the change
classes describe exactly those:

| Class | Meaning | Finding? |
|-------|---------|----------|
| `appeared` | Key not in the baseline | reported |
| `disappeared` | Key not in the current run | reported |
| `rebound` | Same process and port, different bind address | reported |
| `owner-changed` | Same key, different process name or cmdline | reported |
| `restarted` | Same key and cmdline, different PID and start time | listed, not a finding |

`restarted` is deliberately informational. Services restart, and a tool that
flagged every routine restart would teach you to ignore it.

**`rebound` is one event, not a disappearance plus an appearance.**
`127.0.0.1:8080` becoming `0.0.0.0:8080` means a local-only service just became
reachable from the network, which is the highest-signal thing this tool can
report. Splitting it into two events loses precisely that.

A disappearance and an appearance are paired as a rebind only when they share a
protocol and port **and** the process identity matches. When neither side could
be attributed, which is the normal case unprivileged, they are still paired but
the event carries `owner_verified: false` and says so in the output, rather than
asserting a sameness that was never established.

## Ephemeral ports

The range comes from `/proc/sys/net/ipv4/ip_local_port_range`, read at runtime
rather than hardcoded, because distros and sysctl tuning both move it. Outbound
UDP source ports land there and are pure noise in a diff.

**They are filtered, never silently.** The count suppressed and the range used
are both reported, and `--all` includes them. A silent filter is a place for a
real finding to hide.

## Output

The current view is sorted by port and collapses the IPv4 and IPv6 rows of one
dual-stack service into a single line. Only the loopback pair
(`127.0.0.1`/`::1`) and the wildcard pair (`0.0.0.0`/`::`) count as equivalent:
two specific addresses that merely share a port are listed separately, because
merging them would invent one service where there may be two. The grouping is
display only, and the diff uses the full key, so nothing it does can hide a
change.

The diff view is grouped by change class, appeared first, and each entry states
what changed rather than only that something did.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Ran, and the diff found nothing (or no diff was asked for) |
| `1` | The diff found changes |
| `2` | Could not determine |

`2` covers: not Linux, `/proc/net/*` unreadable, `--diff` with no stored
baseline, an unparseable or wrong-version snapshot, and a privilege mismatch
that makes the diff untrustworthy.

`--diff` with no baseline is `2` rather than `1`, and the message names
`--save`. The convention matches `logi-rx`, `rfscan`, `freshcheck` and
`chronicle`, documented in the root README.

## Options

| Flag | Description |
|------|-------------|
| `--save` | Write a baseline snapshot |
| `--diff [FILE]` | Compare against the latest baseline, or a named snapshot |
| `--list` | List stored snapshots |
| `--unix` | Include unix domain sockets |
| `--all` | Include ephemeral-range sockets |
| `--json` | Machine-readable output |
| `--no-color` | Disable coloured output |

## JSON output

| Key | Type | Meaning |
|-----|------|---------|
| `tool` | string | Always `"portwatch"` |
| `linux` / `root` | bool | Platform check, and whether the run was privileged |
| `mode` | string | `show`, `save`, `diff`, or `list` |
| `snapshot` | object | The current capture, see below |
| `baseline` / `baseline_path` | object\|null, string\|null | The snapshot compared against |
| `saved_to` | string\|null | Path written under `--save` |
| `snapshots` | array | Paths, under `--list` |
| `events` | array | Change events, see below |
| `results` | array | Findings: `id`, `check`, `status`, `summary`, `detail`, `fix` |
| `counts` | object | Count per status |
| `error` | string\|null | `not-linux`, `proc-unreadable`, `no-baseline`, `bad-snapshot`, `root-mismatch`, `save-failed` |
| `exit_code` | int | Matches the process exit code |

The `snapshot` object: `version`, `captured_at`, `captured_as_root`,
`ephemeral_range`, `ephemeral_suppressed`, `include_unix`, `include_ephemeral`,
`parse_skipped`, `unreadable`, `processes_scanned`, `processes_denied`, and
`listeners`.

Each listener: `protocol`, `address`, `family` (`ipv4`, `ipv6`, `ipv4-mapped`,
`unix`), `port`, `state`, `tcp_listening`, `uid`, `inode`, and `owner` (null when
unattributed). An owner carries `pid`, `name`, `cmdline`, `uid`, `start_ticks`,
`start_epoch`, `cgroup`, `in_container`, `unit_like`.

Each event: `change` (one of the five classes), `key` (`protocol|address|port`),
and `baseline` and/or `current`. A `rebound` also carries `from_address`,
`to_address`, `owner_verified` and `newly_reachable`.

## Tests

```sh
python3 -m unittest discover -s portwatch/tests -t portwatch/tests -v
```

`/proc/net/*` are plain text and fixture cleanly. Covered explicitly, because
these are the cases where a naive implementation is wrong without looking wrong:
the hex decode in both directions, IPv6 four-word reassembly, IPv4-mapped
normalisation, state `0A` selection, inode-to-PID resolution through a synthetic
`/proc/<pid>/fd` tree, the unprivileged limitation, a root-captured baseline
diffed against an unprivileged run, every change class with `rebound` asserted
to be one event, ephemeral filtering against a synthetic range, `--diff` with no
baseline, and a snapshot whose version this build does not understand.

Every tuning constant is pinned by a mutation test, and the suite passes the
name-versus-assertion audit used on the other four tools.

## Scope

v0.1 is TCP and UDP over v4 and v6, process attribution, snapshot and diff, with
unix sockets behind a flag. Watching continuously, alerting, firewall
correlation and remote hosts are later or never.
