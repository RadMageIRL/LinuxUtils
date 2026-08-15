# freshcheck

Post-install and post-update audit for a Linux machine. The checklist you would
otherwise run from memory on a new box, plus the handful of failure modes whose
symptoms point nowhere near their cause.

Standard library only. No dependencies.

## Read-only, permanently

There is no `--apply` and no write path anywhere in this tool. Every finding
prints the exact command that would fix it, and `freshcheck` runs none of them.
That is a deliberate design constraint rather than an unfinished feature: it is
what makes the tool safe to point at a machine you do not own.

It also runs fully without root. Any check that genuinely needs privilege
degrades to "could not determine" with an explanation, never to a false pass.
The distinction between "I looked and it is fine" and "I was not allowed to
look" is load-bearing throughout.

## Quick start

```sh
./freshcheck.py                    # audit everything
./freshcheck.py --json             # machine-readable, for cron
./freshcheck.py --only kernel      # one check
./freshcheck.py --skip boot-time   # everything but one
```

## What it checks

### 1. Running kernel vs installed modules

The highest-value check here, and the reason the tool exists.

After an update replaces the kernel package, the module tree for the
*currently running* kernel is deleted. `modprobe` then fails for anything not
already loaded: USB devices stop enumerating on hotplug, VirtualBox breaks,
filesystems refuse to mount. None of those error messages mention the kernel,
which is what makes this the single most common "my box went weird and I do not
know why" event.

Both `/usr/lib/modules` and `/lib/modules` are checked, since Arch uses the
former with `/lib` as a symlink while others use the latter directly. The two
are deduplicated by resolved path so a symlinked layout is not reported twice.

**Two findings, two severities, deliberately not collapsed:**

- **Running kernel's modules are missing** is a `fail`. The system is actively
  degraded right now.
- **A newer kernel is installed than the one running** is a `warn`. That is
  routine after an update, and is flagged only so the reboot is a decision
  rather than a surprise.

Version comparison splits into numeric and alphabetic runs, because a string
comparison puts 6.9 above 6.10 and would invert the verdict on every kernel
update past `.9`. A trailing sentinel keeps a release ahead of its own release
candidate, which a naive prefix comparison also gets backwards.

### 2. Microcode

*Installed* and *loaded* are different questions. A package sitting on disk
proves nothing: if its image is not wired into the bootloader as an initrd
before the main initramfs, it is never read.

The running revision comes from
`/sys/devices/system/cpu/cpu0/microcode/version`, but that alone cannot
distinguish a factory revision from an updated one. Confirming an early load
means reading the kernel ring buffer.

**`dmesg` is restricted by default on many distros** (`kernel.dmesg_restrict=1`).
`freshcheck` checks `/proc/sys/kernel/dmesg_restrict` first and reports
`unknown` when it is restricted and the run is unprivileged. Reporting "not
loaded" when the tool was simply not allowed to look would be the exact false
negative this check exists to prevent.

The fix command is vendor-aware and distro-aware: `amd-ucode` against
`intel-ucode`, via `pacman`, `apt`, `dnf` or `zypper` as appropriate.

### 3. TRIM

Only meaningful where there is a real SSD, so the check looks for
`/sys/block/*/queue/rotational` equal to `0`. **zram and loop devices also
report non-rotational**, and counting them would invent an SSD on a machine
that does not have one, so those name prefixes are excluded.

Skipped entirely under virtualisation. Guest-side discard may pass through to
the host or may be a no-op depending on how the backing store was configured,
and that is not something the guest can determine about itself.

`systemctl is-enabled fstrim.timer` is cross-checked against `discard` in
`/etc/fstab`:

| Timer | `discard` | Verdict |
|-------|-----------|---------|
| enabled | no | `ok` |
| enabled | yes | `warn`, redundant |
| disabled | yes | `warn`, works but costs throughput |
| disabled | no | `warn`, no trim at all |

The redundant case is a **warning, not a failure**. Continuous discard does
trim; it just issues one on every delete, which is a measurable throughput cost
on many SSDs. Periodic trim via the timer is the current recommended default.

### 4. Journal size

`journald`'s default cap is 10% of the filesystem, which on a large root
partition is gigabytes of logs nobody asked for.

Reads `/etc/systemd/journald.conf` **and `/etc/systemd/journald.conf.d/*.conf`
drop-ins**, with last-one-wins semantics and drop-ins applied after the main
file. Reading only the main file is the common bug here, and it misreports a
correctly configured system as having no cap at all.

Current on-disk usage is measured by summing `/var/log/journal`.

### 5. Swap and zram

Reports presence, type, and size relative to RAM, from `/proc/swaps` and
`/proc/meminfo`.

**The nuance that makes this worth writing:** if swap is zram, a *high*
`vm.swappiness` is correct. zram compresses into RAM, so swapping is cheap and
the kernel should prefer it over reclaiming page cache. 180 is the commonly
recommended value against a default of 60. A tool that flagged 180 as a problem
would be actively wrong, so the advice branches on which kind of swap you have:

| Swap | swappiness | Verdict |
|------|-----------|---------|
| zram | >= 100 | `ok`, correct pairing |
| zram | < 100 | `warn`, tuned for disk |
| disk | >= 100 | `warn`, tuned for zram |
| disk | default | `ok` |
| none | any | `warn` |

### 6. CPU scaling

**The governor alone is not a verdict.**

On `amd_pstate-epp` and `intel_pstate` in active mode, the `powersave` governor
paired with a `performance` energy-performance preference is the **correct**
configuration, and is what a current Ryzen will be running. The governor name
is misleading in that mode: the hardware picks frequencies and the EPP is what
biases it. Flagging that as a problem would be wrong, and would teach you to
ignore the tool.

So the driver is read first and the verdict branches on it:

- **Active/EPP mode** (detected by the presence of the
  `energy_performance_preference` attribute, which is more reliable across
  kernel versions than matching driver-name spellings): the governor and EPP
  are judged **as a pair**. `powersave` + `performance` or
  `balance_performance` is `ok`. `powersave` + `power` is a `warn`, reasonable
  on a laptop on battery and questionable on a desktop.
- **`acpi-cpufreq` / passive mode**: the classic semantics apply and
  `powersave` genuinely does pin the CPU near its minimum frequency. Same
  governor name, opposite verdict.

`/sys/devices/system/cpu/amd_pstate/status` is reported when present.

### 7. Time sync and RTC

`timedatectl show`. An unsynchronised clock is a `warn`: drift breaks TLS
certificate validation and package signature checks long before it becomes
visible as a wrong clock.

The RTC mode is **reported, not judged**. Local time is the Windows-compatible
setting and is almost certainly deliberate on a dual-boot machine, where the
alternative skews the clock by the timezone offset on every switch. It is a
choice, not an error, so it is reported at `ok` with the tradeoff explained
rather than flagged as broken.

### 8. Filesystem headroom

`/`, `/boot`, `/var` and the ESP if separate, via `os.statvfs`. Uses `f_bavail`
rather than `f_bfree`, since blocks reserved for root are not available to the
user whose disk is filling up and counting them would overstate headroom on
exactly the systems where headroom matters.

**`/boot` is held to a stricter bar** (warn below 20% free, fail below 10%,
against 10% and 5% for the others). It is typically small, every kernel update
writes a new initramfs into it, and a full `/boot` makes an update fail
*partway*. A kernel installed with no matching initramfs is a much worse state
than an update that refused to start.

### 9. Failed units

`systemctl --failed`. The cheapest check here and it catches a surprising
amount.

### 10. Boot time

`systemd-analyze time` and the top entries from `blame`. **Purely
informational.** It carries the `info` status, is never a pass or a failure,
and never affects the exit code, because a slow unit is not automatically a
problem.

## Statuses

| Status | Meaning | Affects exit code |
|--------|---------|-------------------|
| `ok` | Checked and fine | no |
| `warn` | Worth fixing | **yes** |
| `fail` | Actively broken | **yes** |
| `unknown` | Could not determine, usually for want of root | no |
| `skipped` | Does not apply to this machine | no |
| `info` | Reported without judgement | no |

`skipped` is a distinct status precisely so that a check which does not apply
can never be mistaken for a pass. It has its own group in the output and its
own count in the summary.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No warnings or failures |
| `1` | Warnings or failures found |
| `2` | Not running on Linux |

**`unknown` deliberately does not affect the exit code.** An unprivileged run
legitimately cannot answer several of these questions, and a routine audit
should not look like a failure just because it was not run as root. If you want
unknowns to be actionable in a cron job, filter on `status` in the JSON output
rather than on the exit code.

`rfscan` in this repo draws the same line: exit `1` means an actionable
finding, and anything that produced no answer is `2`. Both tools answer the
question the same way, so a cron job can treat them alike.

## Options

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable output |
| `--no-color` | Disable coloured output |
| `--only CHECK` | Run only these checks. Repeatable and comma-separated. |
| `--skip CHECK` | Skip these checks. Repeatable and comma-separated. |

Check ids: `kernel`, `microcode`, `trim`, `journal`, `swap`, `cpu`, `time`,
`filesystem`, `failed-units`, `boot-time`. An unrecognised id is an error that
lists the valid ones rather than silently doing nothing.

## JSON output

Emits the full report. This is the output someone will build a cron job around,
so the schema is meant to stay stable.

| Key | Type | Meaning |
|-----|------|---------|
| `tool` | string | Always `"freshcheck"` |
| `linux` | bool | Whether the platform check passed |
| `distro` | object\|null | `id`, `id_like` (array), `pretty_name` |
| `kernel` | string\|null | Running kernel release |
| `root` | bool\|null | Whether the run was privileged |
| `results` | array | One entry per finding, see below |
| `counts` | object | Count per status |
| `exit_code` | int | Matches the process exit code |

Each entry in `results`:

| Key | Type | Meaning |
|-----|------|---------|
| `id` | string | Unique finding id, e.g. `kernel-modules` |
| `check` | string | The check that produced it, e.g. `kernel` |
| `title` | string | Human-readable check name |
| `status` | string | `ok`, `warn`, `fail`, `unknown`, `skipped`, `info` |
| `summary` | string | One-line verdict |
| `detail` | array | Explanation lines, may be empty |
| `fix` | string\|null | The command that would fix it, never run |

A single check can produce more than one finding, which is why `id` and `check`
are separate: the kernel check emits `kernel-modules` and, when relevant,
`kernel-reboot-pending`. `--only` and `--skip` operate on `check`.

## Structure

The checks are a registry of independent functions, each returning one result
or a list of them. The runner iterates, renders, and aggregates.

Each check is wrapped in its own try/except, so one check crashing cannot take
down the run. The exception is reported as `unknown` for that check alone and
labelled as a bug in `freshcheck` rather than a finding about your system.

## Tests

```sh
python3 -m unittest discover -s freshcheck/tests -t freshcheck/tests -v
```

Every filesystem read goes through `sysp()` and every external command through
`run()`, so the tests build a synthetic `/proc`, `/sys` and `/etc` in a tempdir,
point `SYSROOT` at it, and stub `run()`. That makes all of these reachable
without root and without a real machine sitting in a broken state.

Covered explicitly, because these are the cases where a naive implementation
reports the opposite of the truth:

- Running kernel's module dir missing, the degraded case
- Newer kernel installed with the running one intact, the routine case
- `amd_pstate-epp` with `powersave` + `performance` EPP reports **ok**
- `acpi-cpufreq` with `powersave` reports **warn**, same governor, opposite verdict
- zram swap with `vm.swappiness=180` reports **ok**
- `dmesg_restrict=1` unprivileged reports **unknown**, not a failure
- A journald cap set only in a `.conf.d/` drop-in is found
- A rotational-only system reports TRIM **skipped**, not failed
- zram is not counted as an SSD
- A skipped check never renders under the passed heading
- A crashing check does not take down the rest of the run
