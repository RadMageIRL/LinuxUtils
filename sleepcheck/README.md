# sleepcheck

Audit whether a Linux machine is able and permitted to sleep, without asking it
to sleep or changing any setting.

`sleepcheck` answers the observable parts of “why did this machine not suspend?”:
the kernel states it offers, systemd policy, live inhibitor locks, firmware wake
sources, and recent sleep-service messages. It does **not** claim that an
enabled wake source caused a resume, or that an inhibitor is wrong for your
machine. Those are facts that need your context.

Standard library only. No dependencies.

## Read-only, permanently

There is no `--apply` and no write path. The tool never invokes suspend,
hibernate, or a wake-source toggle. Where a setting is actionable, it prints a
command or file to review and never runs it.

## Quick start

```sh
sleepcheck
sleepcheck --json
sleepcheck --only inhibitors
sleepcheck --skip journal
```

## What it checks

### Kernel states

Reads `/sys/power/state` and `/sys/power/mem_sleep`. `mem` means the kernel
advertises suspend; `disk` means it advertises hibernation. A missing `mem` is a
warning. The selected `s2idle` or `deep` variant is reported, not judged: both
are useful on different hardware.

Kernel hibernation capability is not proof that hibernation will complete; swap
and resume-device setup are separate questions. `freshcheck` in this repo
already reports swap context.

### systemd policy

Reads the effective `sleep.conf` from systemd's vendor, local, runtime, and
administrator configuration paths, plus lexical `sleep.conf.d/*.conf` drop-ins
with systemd's priority and last-one-wins semantics. `AllowSuspend=no` (and the equivalent hibernation settings) are
warnings because they explicitly prevent the requested transition. It also
reports the effective `HandleLidSwitch` policy as context rather than declaring
`ignore` broken: a docked laptop, desktop, and server have different correct
answers.

This v0.1 supports systemd only. If another init system is running, policy,
inhibitor and journal checks are marked `skipped` rather than guessed.

### Inhibitor locks

`systemd-inhibit --list` shows programs that are currently holding sleep,
idle, or shutdown locks. A live `block` lock is a warning because it can prevent
a sleep request now. The output names the holder and its stated reason; it does
not call the lock a bug. A video player or package transaction may be doing
exactly what it should.

### Firmware wake sources

Lists the enabled rows in `/proc/acpi/wakeup` when that ACPI table exists. This
is informational only. An enabled device is capable of waking the machine; it
is not evidence it did so. `logi-rx` covers wake configuration for Logitech
receivers specifically.

### Recent sleep-service journal events

Reads the last seven days of the systemd suspend, hibernate, hybrid-sleep, and
suspend-then-hibernate service journals. Messages containing failure wording
are warnings. The events are retained in `--json`; adjacent events do not imply
causation and the tool never identifies a wake source from them.

Journal access can be restricted to root or a journal-reading group. A failed
query is `unknown`, never a clean result.

## Statuses and exit codes

| Status | Meaning |
|---|---|
| `ok` | Checked and fine |
| `warn` | An explicit blocker or recent service failure worth reviewing |
| `unknown` | Could not determine |
| `skipped` | Does not apply to this machine |
| `info` | Context without judgement |

| Code | Meaning |
|---|---|
| `0` | Ran with no warnings |
| `1` | A warning was found |
| `2` | Not Linux |

`unknown`, `skipped`, and `info` do not share an exit code with a finding. This
matches the other tools in the repository: not being able to inspect a thing is
not proof it is healthy.

## Options

| Flag | Description |
|---|---|
| `--json` | Machine-readable output from the same gathered data |
| `--no-color` | Accepted for consistency with the other tools |
| `--only CHECK` | Run only these checks; repeatable and comma-separated |
| `--skip CHECK` | Skip checks; repeatable and comma-separated |

Check IDs: `states`, `policy`, `inhibitors`, `wake`, `journal`.

## JSON output

`--json` emits one object with `tool`, `linux`, `root`, `systemd`,
`sleep_states`, `mem_sleep_states`, `mem_sleep_selected`, `policy`,
`inhibitors`, `wake_sources`, `journal_events`, `journal_skipped`, `results`,
`counts`, `error`, and `exit_code`.

Each result has the repository-standard `id`, `check`, `title`, `status`,
`summary`, `detail`, and `fix` fields. Human and JSON output are rendered from
the same gather step.

## Tests

```sh
python3 -m unittest discover -s sleepcheck/tests -t sleepcheck/tests -v
```

The suite uses a synthetic `/proc`, `/sys`, `/etc`, and command runner. It pins
the distinctions that matter: an unavailable suspend state is not a pass;
drop-ins override the main systemd config; a non-blocking inhibitor is not
reported as a blocker; enabled wake sources are informational; inaccessible
journals are unknown rather than clean; and malformed journal records do not
erase valid ones.
