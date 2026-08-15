# chronicle

What changed on this machine, and when.

The other tools in this repo diagnose a subsystem or audit current state.
Nothing answers the temporal question, which is the one you actually have at
11pm when something that worked yesterday does not.

Standard library only. No dependencies.

## The idea

Every Linux box has a reconstructable history that nobody reconstructs, because
the pieces live in four places and none of them correlate: the package manager
log, the journal, `/etc` mtimes, and the kernel version across boots.

Individually each is readable and nearly useless. Merged into one timeline they
answer the question directly:

```
  Tue 2026-08-11
  14:00  pkg   47 packages upgraded (linux 6.11.4-1 -> 6.11.5-1, mkinitcpio 37-2 -> 38-1)
  14:00  etc   /etc/mkinitcpio.conf  (rewritten by the package transaction)
  14:00  etc!  /etc/pacman.conf.pacnew

  Wed 2026-08-12
  ──────────────────────────────────────────────────────────────────
  14:47  BOOT  boot -1 (kernel 6.11.4-arch1-1)
  ──────────────────────────────────────────────────────────────────
  17:15  BOOT  boot 0 (kernel 6.11.5-arch1-1)
  17:15  FAIL  systemd-modules-load.service
```

Nobody assembles this. That is the whole tool.

## Adjacency is not causation

A package upgrade an hour before a failure is temporally adjacent, and that is
all this tool knows.

There is deliberately **no "likely cause" field, no ranking of suspects, and no
severity attached to correlation**. Events are ordered and labelled. That is
the contract, and a test asserts the JSON schema contains no key named `cause`,
`suspect`, `culprit`, `confidence` or anything similar.

The reasoning is the same as `rfscan` refusing to convert nmcli's quality
percentage into a plausible-looking dBm figure: the moment a tool starts
inferring, its output stops being trustworthy and starts being a guess wearing
a confident font. You are much better at drawing the line than it is, and you
can only do that if the parts it is certain about stay certain.

## Read-only

There is no `--apply` and no write path. `--rollback-hint` prints a
`pacman -U` command and never runs it.

## Quick start

```sh
chronicle                          # last 7 days
chronicle --since "3 days ago"
chronicle --since 2026-08-01 --until 2026-08-10
chronicle --boot -1                # scope to the previous boot
chronicle --before-boot            # the window preceding the last failed boot
chronicle --verbose                # expand transactions to individual packages
chronicle --json
```

## Sources

### Package manager log

**v0.1 reads pacman only.** The reader sits behind a one-function interface,
`iter_package_events(path) -> (events, skipped)`, so dpkg and dnf can be added
later without restructuring anything above it.

On a system it cannot read, the package timeline is reported as **unavailable
rather than empty**. An unsupported source and a quiet one must not look the
same, and this tool does not claim support for package managers it has never
been tested against. Arch with no `pacman.log` is a third, distinct case: the
reader applies and the data is missing, so that is `unknown` rather than
`skipped`.

Transactions are grouped by pacman's own `transaction started` /
`transaction completed` delimiters, not by timestamp proximity. That is what
turns 47 individual log lines into one "47 packages upgraded" event, and it is
exact rather than heuristic.

Both timestamp formats pacman has used are parsed: the current
`[2026-08-11T15:00:12+0100]` and the older `[2015-09-16 15:47]`, which carries
no UTC offset and is read as local time. Unrecognised lines are skipped and
counted, never fatal. Pacman's own chatter (`Running 'pacman -Syu'`, warnings,
and the arbitrary output of package install scripts) is recognised and ignored
rather than counted, so the skipped figure keeps meaning "lines this reader
genuinely does not understand".

### Journal

`journalctl --output=json`, one JSON object per line. Unlike `iw scan dump`
this is a documented, stable interface, so it is not the fragile part.

Boot boundaries come from `journalctl --list-boots`, preferring JSON and
falling back to the text table that older systemd offers. `_BOOT_ID` is the
join key: it is what ties a unit failure to the boot it happened in. Kernel
version per boot is read from the kernel's own `Linux version` banner.

**Journal access is frequently restricted.** A non-root user who is not in
`systemd-journal` (or `adm`, or `wheel`, depending on distro) sees only their
own messages, and `journalctl` does not say so, it simply returns less.
`chronicle` checks group membership and reports the timeline as **partial**,
with the exact `usermod` command to fix it. Presenting a truncated journal as a
complete one is the failure this exists to prevent.

If systemd is absent the journal source is `skipped` and the package timeline
still works. The gate is systemd presence, not distro identity.

### `/etc` mtimes

Metadata only: file contents are never read.

Package upgrades rewrite config files, so most `/etc` changes in a window will
be *from* an upgrade rather than a human edit. An mtime falling inside a
package transaction window is marked as package-originated rather than listed
as an independent event, which is what stops the one edit that actually was a
human from being buried. The window extends a little past
`transaction completed`, because package install scripts run after the last log
line.

`.pacnew` and `.pacsave` files get their own callout and are never marked
package-originated: they mean a config you had customised was superseded and
the merge is still owed, which is the highest-signal thing in `/etc`.

## `--before-boot`

Finds the most recent failed boot and shows everything in the window *before*
it. That is the query you always want at 11pm and never have.

A boot counts as failed when **a unit failed during it, or the boot before it
recorded no clean shutdown**. That is a definition, stated plainly, and not a
claim about why anything happened. The reasons are printed with the result.

The unit failures that define the window are reported as exactly that, rather
than as events inside it: they happened at the boot that bounds the window, so
listing them as contents would contradict the timeline below them.

**If no failed boot is found the tool says so and exits 2.** It does not fall
back to the default window, because answering a question you did not ask is
worse than saying nothing.

## `--rollback-hint`

Lists packages that changed in the window and where their previous versions
live in `/var/cache/pacman/pkg/`, then prints the `pacman -U` command.

**The cache file is checked for existence before it is named.** `paccache` may
have cleared it, and pointing someone at a file that is not there is worse than
telling them it is gone. Packages whose cached version is missing are listed
separately as unrollable.

## Time windows

`--since` and `--until` accept:

| Form | Example |
|------|---------|
| ISO date | `2026-08-01` |
| ISO datetime | `2026-08-01T15:30` or `"2026-08-01 15:30"` |
| Keywords | `now`, `today`, `yesterday` |
| Relative | `3 days ago`, `2 weeks ago`, `6 hours ago` |

Units are seconds, minutes, hours, days, weeks and months; a month is 30 days
and is documented as approximate. Parsing is hand-rolled, because reaching for
a dependency to read "3 days ago" would break the stdlib-only rule for one of
the smallest problems here.

**Anything unparseable is rejected with the accepted forms listed.** Silently
defaulting to a window you did not ask for would make every result quietly
wrong rather than loudly absent.

## Options

| Flag | Description |
|------|-------------|
| `--since` | Window start |
| `--until` | Window end |
| `--boot N` | Scope to a boot index, e.g. `-1` |
| `--before-boot` | The window preceding the most recent failed boot |
| `--rollback-hint` | List cached previous versions and print the `pacman -U` command |
| `--verbose` | Expand transactions to individual packages |
| `--json` | Machine-readable output |
| `--no-color` | Disable coloured output |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Looked at everything, nothing worth attention |
| `1` | Something worth attention (failed units, `.pacnew` files awaiting a merge) |
| `2` | Could not determine |

`2` covers: not Linux, an unparseable window, `--until` before `--since`, an
unknown `--boot` index, `--before-boot` with no failed boot, and a run where
**nothing was found but not every source could be consulted**. That last case
matters: exiting 0 there would claim a clean window that was never fully
examined.

Finding something outranks a degraded source. A partial timeline that still
surfaced a failure is a positive result, not an inconclusive one, so it exits 1.

The convention matches `logi-rx`, `rfscan` and `freshcheck`, which is documented
in the root README.

## JSON output

| Key | Type | Meaning |
|-----|------|---------|
| `tool` | string | Always `"chronicle"` |
| `linux` | bool | Whether the platform check passed |
| `root` | bool | Whether the run was privileged |
| `window` | object\|null | `start`, `end`, `label`, and `failed_boot` under `--before-boot` |
| `events` | array | The timeline, sorted by `epoch`. See below. |
| `results` | array | Findings: `id`, `check`, `status`, `summary`, `detail`, `fix` |
| `sources` | object | Per source (`packages`, `journal`, `etc`): `status` and `detail` |
| `boots` | array | `index`, `boot_id`, `first_epoch`, `last_epoch` |
| `rollback_hints` | array | `name`, `from_version`, `to_version`, `cache_file`, `available` |
| `counts` | object | Count per status |
| `error` | string\|null | `not-linux`, `bad-window`, `no-failed-boot` |
| `exit_code` | int | Matches the process exit code |

Every event carries `timestamp` (ISO 8601), `epoch` (float), `source` and
`type`. Sources are `pacman`, `journal` and `etc`. Types and their extra fields:

| `type` | Source | Extra fields |
|--------|--------|--------------|
| `transaction` | pacman | `packages` (array of `action`/`name`/`old_version`/`new_version`), `counts`, `summary`, `caller`, `end_epoch` |
| `package` | pacman | Same shape, for a line outside any transaction |
| `boot` | journal | `boot_id`, `index`, `kernel` |
| `unit-failure` | journal | `unit`, `boot_id`, `message` |
| `config-change` | etc | `path`, `package_originated` |
| `pacnew` | etc | `path`, `package_originated` (always false) |

## Tests

```sh
python3 -m unittest discover -s chronicle/tests -t chronicle/tests -v
```

The pacman reader is the fragile part, the way `iw` output is in `rfscan`, so
the fixture spans both timestamp formats and contains a real 47-package
transaction, a removal, a downgrade, package-script chatter, and malformed
lines that must be skipped and counted.

The rest of the suite is about honesty rather than parsing: an unsupported
package manager and an empty log must not look the same, a restricted journal
must be reported as partial, systemd's absence must not cost the package
timeline, `--before-boot` with no failed boot must exit 2 rather than
substitute a window, and a missing rollback cache file must be reported as
missing.

Every tuning constant is pinned by a mutation test, and the suite passes the
name-versus-assertion audit used on the other three tools.

## Scope

v0.1 is pacman plus journal plus `/etc` mtimes, on systemd. dpkg and dnf
readers are later. Anything resembling causal inference is never.
