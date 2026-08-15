# rfscan

Map 2.4 GHz channel occupancy and recommend a quieter channel for your access
point.

Companion to [`logi-rx`](../logi-rx/). Between them they cover "my wireless
peripheral is flaky": `logi-rx` audits the receiver, `rfscan` audits the band
the receiver has to live in.

Standard library only. No dependencies.

## Read this before you trust the output

Two limits decide whether any of the numbers below are useful to you. Both are
printed by the tool itself on every run, not just documented here.

**A WiFi scan only sees WiFi.** It cannot see Bluetooth, USB 3 broadband noise,
microwave ovens, Zigbee, video senders, or proprietary HID receivers, including
the Logitech receiver you may be trying to diagnose. Those are the emitters
that most often wreck a 2.4 GHz peripheral link. A clean `rfscan` result does
**not** mean the band is clear. It means the band is clear *of WiFi*.

**A channel recommendation applies to the access point and to nothing else.**
Logitech Unifying, Bolt and Lightspeed use adaptive frequency hopping across
the whole 2.400 to 2.4835 GHz band. They do not sit on a channel, so there is
no channel setting on your mouse or keyboard to change. The only device you can
move is the AP.

The empirical ground truth for whether a change helped is `logi-rx --watch`:
scan, change the AP channel, then re-measure from the same spot and compare the
gap count. Everything `rfscan` produces is a hypothesis until that measurement
agrees with it.

## Quick start

```sh
./rfscan.py                  # cached scan, no root, connection undisturbed
./rfscan.py --json           # same data, machine-readable
./rfscan.py --band both      # include 5 GHz detail
sudo ./rfscan.py --active    # force a real scan (disrupts the connection)
```

Read-only. Always. Unlike `logi-rx` there is no `--apply`, because this tool
has no write path at all. `--active` is the only privileged mode and all it
does is ask the kernel to scan.

## Data sources

Three, tried in order of preference. Unprivileged and non-disruptive first. The
tool reports which one it used.

| Source | Root | Disruptive | Signal | Notes |
|--------|------|-----------|--------|-------|
| `iw dev X scan dump` | no | no | dBm | Default. Kernel's cached BSS list. |
| `nmcli device wifi list --rescan no` | no | no | quality % | Fallback when `iw` is absent. |
| `iw dev X scan` | yes | **yes** | dBm | Only via `--active`. |

**On the nmcli fallback:** nmcli's `SIGNAL` column is a 0 to 100 quality
percentage, not dBm. The two are not interchangeable, and the mapping is
driver-specific. Rather than derive a plausible-looking dBm figure and weight
every channel by it, `rfscan` reports weighting as unavailable, ranks channels
by AP count alone, and makes no recommendation. Install `iw` if you want the
weighted scoring.

**On cached data:** the kernel's cache can be stale, so the tool reports the
age range of the entries it found and warns when they are over two minutes old.
An empty cache is not an empty band. A freshly booted machine that has not
associated yet has nothing cached, and the tool says exactly that rather than
reporting "no networks found" as though the band were clear.

**On `--active`:** it transmits probe requests. It briefly stalls or
disassociates the connection, and on some drivers it drops the link entirely.
It is never the default and never runs implicitly.

## Interface discovery

Interfaces come from sysfs, not from parsing command output. An interface is
wireless if `/sys/class/net/<iface>/phy80211` exists, with
`/sys/class/net/<iface>/wireless` as the fallback for drivers predating
cfg80211.

When several exist the first one that is up is used, and the tool reports both
the choice and the alternatives. `--iface NAME` overrides. When none exist the
tool exits 2 rather than printing an empty histogram.

## Regulatory domain

Read from `iw reg get`, which works unprivileged. **`rfscan` never recommends a
channel outside the regulatory domain.**

Legal channels are derived from the reported frequency ranges rather than from
a hardcoded country table: a 20 MHz carrier is legal when the whole of its
centre +/-10 MHz fits inside a permitted range. That yields 1 to 11 for the US
(2402 to 2472), 1 to 13 for most of the EU, and 14 for Japan, without the tool
needing to know anything about those countries specifically.

If the domain is unset, or reports `00` (world), the tool falls back to the
1/6/11 set and says why. Channels outside that set may well be legal where you
are, but a tool that cannot confirm it should not recommend it.

Channels outside the domain are shown in the histogram marked unavailable
rather than omitted, with their AP count intact. A neighbour transmitting on a
channel you may not legally use still lands on top of the ones you can.

## The overlap model

2.4 GHz channel centres are 5 MHz apart, and a 20 MHz 802.11g/n carrier
occupies roughly +/-11 MHz. A transmitter on channel N therefore spills into
N+/-4 and is only genuinely non-overlapping at a separation of 5 or more. That
is the entire reason 1/6/11 is the standard set.

Scoring works like this:

1. **Convert dBm to linear power** with `mW = 10 ** (dBm / 10)`. dBm is a log
   scale. Summing or averaging dBm values directly is meaningless, and it is
   the single most common bug in tools of this kind. A -30 dBm AP puts out a
   thousand times the power of a -60 dBm one, and that ratio is the entire
   point of weighting.
2. **Spread each BSS's power across the channels it overlaps**, with a weight
   that falls off linearly with separation, reaching zero at 25 MHz.
3. **Sum per channel**, and report the weighted score alongside a raw AP count.

The falloff is computed in **frequency space, not channel-number space**. This
matters for channel 14, which sits 12 MHz above 13 rather than the usual 5;
subtracting channel numbers would overstate their overlap by more than a third.

A 40 MHz HT channel is modelled as two half-power 20 MHz carriers, one on the
primary and one on the secondary, read from the `HT operation` element's
secondary channel offset. When that element is absent the tool assumes 20 MHz
and **says so in the output** rather than assuming silently. When `HT
operation` is present and reports no secondary, 20 MHz is a reading rather than
an assumption and is not flagged.

**This is an approximation of the spectral mask, not a measurement.** The
scores rank channels against each other. They are not absolute figures and they
do not convert to anything physical.

Score and AP count can disagree, and the disagreement is the informative part:
six distant APs on channel 6 matter less than one loud neighbour on channel 1.
When they disagree, the score is the one to trust.

## The recommendation

The tool picks the quietest channel from the legal non-overlapping set, which
is 1/6/11, plus 13 where the regulatory domain permits it.

**Channel 13 is only taken when it is meaningfully quieter.** It is legal
across much of the world but not universally supported by client hardware, and
US-market devices in particular will simply not associate on it. When 13 wins
by less than 3 dB the tool takes the best of 1/6/11 instead and explains why.
When 13 genuinely is the recommendation, the tool flags the compatibility risk.

**When the improvement is marginal, the tool tells you not to bother.** The
threshold is 3 dB, a factor of two in power; below that the difference is
inside the noise of where the router happens to sit. A tool that always
recommends a change is a tool you learn to ignore.

The exception is a current channel outside the non-overlapping set. Sitting on
channel 2 harms you and both neighbouring groups at once, so that is worth
fixing even when the score barely moves.

When nothing at all is detected on the target channel, the improvement is
reported as unavailable rather than as a large finite number. There is no dB
figure against a zero denominator that is not invented.

## 5 GHz

Reported as a short informational section on every run, including when you
asked only about 2.4 GHz. Moving the AP's clients to 5 GHz is frequently a
bigger win than shuffling 2.4 GHz channels: it vacates the crowded band
entirely and leaves 2.4 GHz to the peripherals that have no alternative. A tool
that hid the better answer in order to respect a flag would not be helping.

5 GHz gets counts and the loudest signal per channel, with no weighting and no
recommendation. At 20 MHz spacing those channels do not overlap the way 2.4 GHz
ones do, and the model above would not describe them honestly.

When no 5 GHz networks are seen, the tool says that this may mean an empty band
or a 2.4-only radio, and that a scan cannot tell those apart.

## Options

| Flag | Description |
|------|-------------|
| `--iface NAME` | Force a wireless interface. |
| `--active` | Trigger a real scan instead of reading the cache. Requires root. Disrupts the connection. |
| `--json` | Machine-readable output. |
| `--no-color` | Disable coloured output. |
| `--band {2.4,5,both}` | Which band to report in detail. Default `2.4`. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scanned cleanly, no action needed |
| `1` | Congestion found and a move is worth making, or no data available |
| `2` | Not running on Linux, or no wireless interface |

## JSON output

`--json` emits the same data the human output is rendered from, as one flat
object. Both come from a single gather step, so they cannot drift apart.

| Key | Type | Meaning |
|-----|------|---------|
| `tool` | string | Always `"rfscan"` |
| `linux` | bool | Whether the platform check passed |
| `interface` | string\|null | Interface used |
| `interfaces_found` | array | All wireless interfaces, with `name`, `detected_via`, `operstate`, `up` |
| `source` | string\|null | `iw-scan-dump`, `iw-scan-active`, or `nmcli` |
| `source_privileged` | bool\|null | Whether the source needed root |
| `signal_metric` | string\|null | `dbm` or `quality_percent` |
| `weighting_available` | bool | False when signal is not in dBm |
| `band` | string | The `--band` value |
| `scan_age_ms` | object | `freshest` and `stalest`, or nulls |
| `regulatory` | object | `country`, `legal_channels_2ghz`, `reason`, `fell_back` |
| `associated` | object\|null | `bssid`, `ssid`, `freq`, `channel` |
| `channels_2ghz` | array | Per channel: `channel`, `freq`, `legal`, `ap_count`, `score`, `score_relative` |
| `channels_5ghz` | array | Per channel: `channel`, `ap_count`, `loudest_dbm` |
| `networks` | array | Every parsed BSS, see below |
| `network_count` | int | Length of `networks` |
| `unweighted_count` | int | Networks counted but not scored, for lack of a signal reading |
| `recommendation` | object\|null | See below |
| `caveats` | array | The limits above, as strings |
| `warnings` | array | Parse failures, stale data, fallbacks used |
| `error` | string\|null | `not-linux`, `no-wireless-interface`, `iface-not-found`, `active-scan-needs-root`, `empty-scan-cache`, `no-data` |
| `exit_code` | int | Matches the process exit code |

Each entry in `networks`:

| Key | Type | Meaning |
|-----|------|---------|
| `bssid` | string\|null | Lowercased |
| `ssid` | string\|null | Null when hidden |
| `hidden` | bool | Empty or all-NUL SSID |
| `freq` | number | MHz |
| `channel` | int | |
| `band` | string\|null | `2.4`, `5`, or `6` |
| `signal_dbm` | number\|null | Null from nmcli, and when the source omits it |
| `signal_quality` | int\|null | 0 to 100, nmcli only |
| `width_mhz` | int\|null | 20 or 40 on 2.4 GHz; null elsewhere, where width is not modelled |
| `width_assumed` | bool | True when 20 MHz was assumed rather than read |
| `secondary_channel` | int\|null | 40 MHz HT secondary |
| `last_seen_ms` | number\|null | Cache age for this BSS |
| `associated` | bool | Marked `-- associated` by `iw` |

The `recommendation` object:

| Key | Type | Meaning |
|-----|------|---------|
| `candidates` | array | Legal non-overlapping channels considered |
| `current_channel` | int\|null | Null when not associated on 2.4 GHz |
| `best_channel` | int\|null | Null when no ranking was possible |
| `improvement_db` | number\|null | Null when undefined against an empty channel |
| `worth_changing` | bool | Drives the exit code |
| `current_is_non_overlapping` | bool\|null | Whether the current channel is in the set |
| `prefers_standard_set` | bool | True when 13 was passed over for compatibility |
| `reason` | string | Plain-language explanation |

## Notes on parsing

`iw` output is not a stable API. Its format varies across versions and drivers,
so the parser skips what it does not recognise instead of insisting on a shape.
A BSS block that cannot be parsed is counted and reported, never fatal, and one
malformed block never costs you the rest of the scan. A block with no frequency
is dropped rather than guessed at, because there is no honest way to place it
on a channel.

Signal is only read when the line actually says `dBm`. Some drivers report a
unitless or percentage figure in that field, and treating it as dBm would
poison every score downstream.

Hidden networks are handled deliberately: `iw` renders them as a bare `SSID:`
line, which is otherwise indistinguishable from a sub-block heading like
`HT operation:`. Treating it as a heading silently loses every hidden network
on the band, so known field names are matched before the heading heuristic.

## Tests

```sh
python3 -m unittest discover -s rfscan/tests -t rfscan/tests -v
```

Standard library only, same rule as the tools. The suite runs the parser
against captured fixtures in `tests/fixtures/`, including a deliberately messy
one containing hidden SSIDs, non-ASCII SSIDs, a missing signal field, 40 MHz
APs offset in both directions, unrecognised elements, and two blocks with no
frequency at all. The regulatory fixtures cover US, DE, JP and the `00` world
domain, and assert the derived channel lists rather than the parse alone.
