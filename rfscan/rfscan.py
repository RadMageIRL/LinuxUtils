#!/usr/bin/env python3
"""
rfscan.py - 2.4 GHz channel occupancy scanner for Linux.

Companion to logi-rx. logi-rx audits the receiver; rfscan audits the band it
has to live in.

  * enumerates wireless interfaces from sysfs (no shelling out to find them)
  * reads the kernel's cached BSS list via `iw dev X scan dump` - no root, and
    it does not disturb the connection
  * falls back to nmcli when iw is absent, and says so, and refuses to
    fabricate dBm figures from nmcli's 0-100 quality percentage
  * weights each channel by LINEAR power, not by AP count, because one loud
    neighbour matters more than six distant ones
  * reads the regulatory domain and never recommends an illegal channel
  * recommends the least-contended non-overlapping channel, and says plainly
    when the improvement is too small to be worth the disruption

Read-only. Always. There is no --apply and no write path anywhere in this
tool; the only privileged mode is --active, which asks the kernel to scan.

    ./rfscan.py                  # cached scan, no root, does not disturb link
    ./rfscan.py --json           # same data, machine-readable
    sudo ./rfscan.py --active    # force a real scan (DISRUPTS the connection)
    ./rfscan.py --band both      # include 5 GHz detail

Two things this tool cannot do, stated up front because they determine whether
its output is useful to you at all:

  1. A WiFi scan only sees WiFi. Bluetooth, USB 3 broadband noise, microwave
     ovens, Zigbee and video senders are invisible to it. A clean result here
     does not mean the band is clear.
  2. Logitech Unifying/Bolt/Lightspeed hop across the whole band and do not
     sit on a channel. The only device a channel recommendation applies to is
     the access point.

No third-party dependencies.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

NET_CLASS = Path("/sys/class/net")

# 2.4 GHz channel plan. 1-13 are 5 MHz apart; 14 is the odd one out, sitting
# 12 MHz above 13 rather than 5, which is why overlap is computed in frequency
# space below rather than by subtracting channel numbers.
CHANNELS_2GHZ = list(range(1, 15))

# The standard non-overlapping set. 13 is added only where the regulatory
# domain permits it; see pick_candidates().
NON_OVERLAPPING = [1, 6, 11]

# A 20 MHz carrier is roughly +/-11 MHz around its centre, so energy from a
# transmitter 5 channels (25 MHz) away is treated as zero. Between those, fall
# off linearly. This is an approximation of the spectral mask, not a
# measurement - see README.
OVERLAP_SPAN_MHZ = 25.0

# Below this, moving the AP is not worth the disruption. 3 dB is a factor of
# two in power; anything less is inside the noise of where you put the router.
WORTH_CHANGING_DB = 3.0

BAR_WIDTH = 34
WRAP_WIDTH = 68


# ---------------------------------------------------------------- formatting


def wrap(text, width=WRAP_WIDTH):
    """Minimal greedy wrapper. This tool has more to explain than logi-rx does,
    and unwrapped explanation runs off the side of a terminal."""
    lines = []
    current = ""
    for word in text.split():
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def safe_text(text):
    """Render text printable on whatever encoding stdout actually has.

    An SSID is arbitrary bytes chosen by a stranger, and the console may be
    POSIX/ASCII: a cron job, a minimal container, anything under LC_ALL=C.
    Crashing on a neighbour's network name is not an acceptable failure mode,
    so unencodable characters are escaped rather than fatal."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode(encoding, "backslashreplace").decode(encoding, "replace")
    except LookupError:
        # The stream named an encoding this Python does not have. Escaping via
        # the same name would just raise again, so drop to plain ASCII.
        return text.encode("ascii", "backslashreplace").decode("ascii")


def emit(text=""):
    """print(), but it cannot die on an encoding it did not choose."""
    print(safe_text(text))


def rule_char():
    """The header underline, degraded to ASCII where the console cannot take
    a box-drawing character."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "─".encode(encoding)
        return "─"
    except (UnicodeEncodeError, LookupError):
        return "-"


class Out:
    """Tiny console formatter. Colour only when stdout is a terminal."""

    def __init__(self, color=True):
        self.color = color and sys.stdout.isatty()

    def _c(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def _tagged(self, code, tag, text, detail=None):
        lines = wrap(text)
        emit(f"  {self._c(code, tag)} {lines[0]}")
        for line in lines[1:]:
            emit(f"         {line}")
        if detail:
            for line in detail.splitlines():
                emit(f"         {self._c('90', line)}")

    def header(self, text):
        emit()
        emit(self._c("1;36", text))
        emit(self._c("36", rule_char() * len(text)))

    def ok(self, text, detail=None):
        self._tagged("32", "[ ok ]", text, detail)

    def warn(self, text, detail=None):
        self._tagged("33", "[warn]", text, detail)

    def fail(self, text, detail=None):
        self._tagged("31", "[fail]", text, detail)

    def info(self, text, detail=None):
        self._tagged("90", "[info]", text, detail)


# ------------------------------------------------------------ band arithmetic


def channel_to_freq(channel):
    """2.4 GHz channel number to centre frequency in MHz."""
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2412 + (channel - 1) * 5
    return None


def freq_to_channel(mhz):
    """Centre frequency in MHz to channel number, or None if unrecognised."""
    if mhz is None:
        return None
    m = int(round(mhz))
    if m == 2484:
        return 14
    if 2401 <= m <= 2473:
        channel = int(round((m - 2412) / 5.0)) + 1
        return channel if 1 <= channel <= 13 else None
    if 4900 <= m <= 5895:
        return int(round((m - 5000) / 5.0))
    return None


def band_of(mhz):
    """Which band a frequency belongs to, as a string key, or None."""
    if mhz is None:
        return None
    m = int(round(mhz))
    if 2400 <= m <= 2500:
        return "2.4"
    if 4900 <= m <= 5895:
        return "5"
    if 5925 <= m <= 7125:
        return "6"
    return None


def dbm_to_mw(dbm):
    """dBm is a log scale. Summing dBm values directly is meaningless; convert
    to linear power first. This is the whole basis of the weighting."""
    return 10.0 ** (dbm / 10.0)


# -------------------------------------------------------------- process calls


def run(cmd, timeout=20):
    """Run a command. Returns (rc, stdout, reason). rc is None if it could not
    be run at all, in which case reason says why."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, text=True, errors="replace"
        )
    except FileNotFoundError:
        return None, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return None, "", f"{' '.join(cmd)} timed out after {timeout}s"
    except OSError as exc:
        return None, "", str(exc)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return proc.returncode, proc.stdout, detail[0] if detail else "command failed"
    return 0, proc.stdout, None


def read_attr(base, name):
    """Read a sysfs attribute, returning None on any failure."""
    try:
        return (Path(base) / name).read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------- interface discovery


def wireless_interfaces():
    """Wireless interfaces from sysfs. An interface is wireless if it has a
    phy80211 link; the older `wireless` directory is the fallback for drivers
    that predate cfg80211."""
    found = []
    if not NET_CLASS.is_dir():
        return found
    for entry in sorted(NET_CLASS.iterdir()):
        if (entry / "phy80211").exists():
            kind = "phy80211"
        elif (entry / "wireless").exists():
            kind = "wireless"
        else:
            continue
        operstate = read_attr(entry, "operstate") or "unknown"
        found.append(
            {
                "name": entry.name,
                "detected_via": kind,
                "operstate": operstate,
                "up": operstate == "up",
            }
        )
    # Prefer an interface that is actually up, then fall back to name order.
    found.sort(key=lambda i: (0 if i["up"] else 1, i["name"]))
    return found


# ------------------------------------------------------------- iw scan parsing
#
# `iw` output is not a stable API. Its format varies across versions and
# drivers, so everything below is written to skip what it does not recognise
# rather than to insist on a shape. One malformed BSS must never abort a scan.

BSS_LINE = re.compile(r"^BSS\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})")
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")

# Keys that are fields even when they arrive with an empty value. This exists
# for exactly one reason: a hidden network prints as a bare `SSID:`, which is
# otherwise indistinguishable from a sub-block heading like `HT operation:`.
# Treating it as a heading silently loses every hidden network on the band.
FIELD_KEYS = {
    "ssid",
    "freq",
    "signal",
    "last seen",
    "ds parameter set",
    "primary channel",
    "secondary channel offset",
}


def decode_ssid(raw):
    """Turn iw's SSID rendering into a string, or None when hidden.

    iw prints printable UTF-8 as-is and escapes everything else as \\xNN. A
    hidden network shows either an empty SSID or a run of NUL bytes."""
    if raw is None:
        return None
    text = HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), raw)
    if text.strip("\x00").strip() == "":
        return None
    return text


def split_bss_blocks(text):
    """Split scan output into per-BSS line groups. Anything before the first
    BSS line is preamble and is dropped."""
    blocks = []
    current = None
    for line in text.splitlines():
        if BSS_LINE.match(line):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)
    return blocks


def _parse_number(value):
    """First numeric token in a string, as a float, or None."""
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(match.group(0)) if match else None


def parse_bss_block(lines):
    """Parse one BSS block. Returns a dict, or None if there is not enough
    here to be useful (no frequency means we cannot place it on a channel)."""
    head = BSS_LINE.match(lines[0])
    if not head:
        return None

    bss = {
        "bssid": head.group(1).lower(),
        "ssid": None,
        "hidden": True,
        "freq": None,
        "channel": None,
        "band": None,
        "signal_dbm": None,
        "signal_quality": None,
        "width_mhz": None,
        "secondary_channel": None,
        "last_seen_ms": None,
        "associated": "associated" in lines[0],
    }

    section = None
    saw_ht_operation = False
    for raw in lines[1:]:
        stripped = raw.strip()
        if not stripped:
            continue

        key, separator, value = stripped.partition(":")
        key = key.strip().lstrip("*").strip().lower()
        value = value.strip()

        # Track which sub-block we are in. `* primary channel:` appears under
        # HT operation, and lookalike keys appear under VHT/HE, so the section
        # matters. A bare `Foo:` opens a sub-block unless it is a known field
        # that legitimately carries an empty value.
        if separator and not value and not stripped.startswith("*"):
            if key not in FIELD_KEYS:
                section = key
                if section == "ht operation":
                    saw_ht_operation = True
                continue

        try:
            if key == "freq" and bss["freq"] is None:
                bss["freq"] = _parse_number(value)
            elif key == "signal":
                # "-45.00 dBm". Only trust it if it actually says dBm.
                if "dbm" in value.lower():
                    bss["signal_dbm"] = _parse_number(value)
            elif key == "ssid":
                bss["ssid"] = decode_ssid(value)
                bss["hidden"] = bss["ssid"] is None
            elif key == "last seen":
                bss["last_seen_ms"] = _parse_number(value)
            elif key == "ds parameter set":
                # "channel 6"
                number = _parse_number(value)
                if number is not None and bss["channel"] is None:
                    bss["channel"] = int(number)
            elif section == "ht operation" and key == "primary channel":
                number = _parse_number(value)
                if number is not None:
                    bss["channel"] = int(number)
            elif section == "ht operation" and key == "secondary channel offset":
                lowered = value.lower()
                if lowered.startswith("above"):
                    bss["secondary_offset"] = 1
                elif lowered.startswith("below"):
                    bss["secondary_offset"] = -1
        except (ValueError, TypeError):
            # A field we recognised but could not read. Drop the field, keep
            # the BSS.
            continue

    if bss["freq"] is None:
        # Without a frequency we cannot place this BSS on a channel at all.
        # Reporting it as channel-unknown would be worse than dropping it.
        return None

    bss["band"] = band_of(bss["freq"])
    from_freq = freq_to_channel(bss["freq"])
    if bss["channel"] is None:
        bss["channel"] = from_freq
    if bss["channel"] is None:
        return None

    offset = bss.pop("secondary_offset", None)
    if offset is not None and bss["band"] == "2.4":
        secondary = bss["channel"] + (4 * offset)
        if 1 <= secondary <= 14:
            bss["secondary_channel"] = secondary
            bss["width_mhz"] = 40
    if bss["width_mhz"] is not None:
        bss["width_assumed"] = False
    elif bss["band"] == "2.4":
        bss["width_mhz"] = 20
        # Only an assumption when there was no HT operation element to read. If
        # HT operation was present and said "no secondary", 20 MHz is a
        # reading, not a guess, and must not be reported as one.
        bss["width_assumed"] = not saw_ht_operation
    else:
        # Outside 2.4 GHz the width is not modelled, so claiming 20 MHz would
        # be asserting something never measured. Leave it unknown.
        bss["width_assumed"] = False

    return bss


def parse_iw_scan(text):
    """Parse `iw dev X scan dump` output. Returns (bss_list, skipped_count)."""
    networks = []
    skipped = 0
    for block in split_bss_blocks(text):
        try:
            parsed = parse_bss_block(block)
        except Exception:
            # Deliberately broad. An unparseable block is a data problem, not
            # a reason to lose the other fifty networks.
            skipped += 1
            continue
        if parsed is None:
            skipped += 1
        else:
            networks.append(parsed)
    return networks, skipped


def parse_iw_link(text):
    """Parse `iw dev X link` for the current association, or None."""
    if not text or text.strip().lower().startswith("not connected"):
        return None
    link = {"bssid": None, "ssid": None, "freq": None, "channel": None}
    head = re.search(r"Connected to ((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", text)
    if head:
        link["bssid"] = head.group(1).lower()
    for raw in text.splitlines():
        key, _, value = raw.strip().partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "ssid":
            link["ssid"] = decode_ssid(value)
        elif key == "freq":
            link["freq"] = _parse_number(value)
    if link["freq"] is not None:
        link["channel"] = freq_to_channel(link["freq"])
    if link["bssid"] is None and link["freq"] is None:
        return None
    return link


# ---------------------------------------------------------------- nmcli path


def split_terse(line):
    """Split an `nmcli -t` line. Colons inside values are backslash-escaped,
    which matters because every BSSID contains five of them."""
    fields = []
    current = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            current.append(line[index + 1])
            index += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    fields.append("".join(current))
    return fields


def parse_nmcli(text):
    """Parse nmcli terse wifi list output. Returns (bss_list, skipped_count).

    nmcli's SIGNAL is a 0-100 quality percentage, NOT dBm. It is deliberately
    stored in a differently named field so that nothing downstream can mistake
    the two and weight by a fabricated power figure."""
    networks = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = split_terse(line)
        if len(fields) < 5:
            skipped += 1
            continue
        ssid, bssid, chan, freq, signal = fields[0], fields[1], fields[2], fields[3], fields[4]
        try:
            freq_mhz = _parse_number(freq)
            channel = int(_parse_number(chan)) if _parse_number(chan) is not None else None
            if channel is None and freq_mhz is not None:
                channel = freq_to_channel(freq_mhz)
            if freq_mhz is None and channel is not None:
                freq_mhz = channel_to_freq(channel)
            if channel is None or freq_mhz is None:
                skipped += 1
                continue
            quality = _parse_number(signal)
            networks.append(
                {
                    "bssid": bssid.lower() or None,
                    "ssid": ssid or None,
                    "hidden": not ssid,
                    "freq": freq_mhz,
                    "channel": channel,
                    "band": band_of(freq_mhz),
                    "signal_dbm": None,
                    "signal_quality": int(quality) if quality is not None else None,
                    "width_mhz": 20,
                    "width_assumed": True,
                    "secondary_channel": None,
                    "last_seen_ms": None,
                    "associated": False,
                }
            )
        except (ValueError, TypeError):
            skipped += 1
    return networks, skipped


# ------------------------------------------------------------ regulatory domain


REG_COUNTRY = re.compile(r"^\s*country\s+([A-Z0-9]{2})\s*:")
REG_RANGE = re.compile(r"\(\s*(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*@")


def parse_reg(text):
    """Parse `iw reg get`. Returns (country, [(low_mhz, high_mhz), ...])."""
    country = None
    ranges = []
    for line in text.splitlines():
        match = REG_COUNTRY.match(line)
        if match:
            if country is not None:
                break  # first block only; later ones are per-phy duplicates
            country = match.group(1)
            continue
        if country is None:
            continue
        found = REG_RANGE.search(line)
        if found:
            try:
                ranges.append((float(found.group(1)), float(found.group(2))))
            except ValueError:
                continue
    return country, ranges


def legal_channels(country, ranges):
    """Which 2.4 GHz channels the regulatory domain permits.

    Derived from the frequency ranges rather than a country table: a 20 MHz
    carrier is legal if the whole +/-10 MHz fits inside a permitted range.
    That yields 1-11 for US (2402-2472), 1-13 for most of EU (2402-2482) and
    14 for Japan, without hardcoding any of them.

    Returns (channels, reason, fell_back)."""
    if country is None:
        return list(NON_OVERLAPPING), "regulatory domain unknown", True
    if country == "00":
        return (
            list(NON_OVERLAPPING),
            "domain is 00 (world), which is the driver's conservative default "
            "rather than a real country",
            True,
        )
    if not ranges:
        return (
            list(NON_OVERLAPPING),
            f"domain {country} reported no usable frequency ranges",
            True,
        )

    permitted = []
    for channel in CHANNELS_2GHZ:
        freq = channel_to_freq(channel)
        for low, high in ranges:
            if low <= freq - 10 and freq + 10 <= high:
                permitted.append(channel)
                break
    if not permitted:
        return (
            list(NON_OVERLAPPING),
            f"domain {country} permits no 2.4 GHz channels, which is almost "
            "certainly a parsing failure rather than the truth",
            True,
        )
    return permitted, f"derived from the {country} regulatory ranges", False


# ------------------------------------------------------------- occupancy model


def overlap_weight(freq_a, freq_b):
    """How much a carrier centred at freq_b spills into freq_a.

    Linear falloff to zero at 25 MHz separation. Computed in frequency space
    so that channel 14, which sits 12 MHz above channel 13 rather than 5, is
    handled correctly instead of being treated as one channel away."""
    distance = abs(freq_a - freq_b)
    if distance >= OVERLAP_SPAN_MHZ:
        return 0.0
    return (OVERLAP_SPAN_MHZ - distance) / OVERLAP_SPAN_MHZ


def occupancy_2ghz(networks):
    """Weighted score and AP count per 2.4 GHz channel.

    Score is a sum of LINEAR power (mW), spread across the channels each BSS
    overlaps. A 40 MHz AP is modelled as two half-power 20 MHz carriers, one
    on the primary and one on the secondary."""
    scores = {channel: 0.0 for channel in CHANNELS_2GHZ}
    counts = {channel: 0 for channel in CHANNELS_2GHZ}
    unweighted = 0

    for bss in networks:
        if bss["band"] != "2.4":
            continue
        channel = bss["channel"]
        if channel in counts:
            counts[channel] += 1

        if bss["signal_dbm"] is None:
            unweighted += 1
            continue

        power = dbm_to_mw(bss["signal_dbm"])
        if bss["secondary_channel"]:
            carriers = [(bss["channel"], 0.5), (bss["secondary_channel"], 0.5)]
        else:
            carriers = [(bss["channel"], 1.0)]

        for carrier_channel, share in carriers:
            carrier_freq = channel_to_freq(carrier_channel)
            if carrier_freq is None:
                continue
            for target in CHANNELS_2GHZ:
                weight = overlap_weight(channel_to_freq(target), carrier_freq)
                if weight > 0:
                    scores[target] += power * share * weight

    return scores, counts, unweighted


def occupancy_5ghz(networks):
    """5 GHz is informational only: per-channel counts and the loudest signal.
    No weighting or recommendation, because at 20 MHz spacing 5 GHz channels
    do not overlap the way 2.4 GHz ones do and the model above would not
    describe them honestly."""
    channels = {}
    for bss in networks:
        if bss["band"] != "5":
            continue
        entry = channels.setdefault(
            bss["channel"], {"channel": bss["channel"], "ap_count": 0, "loudest_dbm": None}
        )
        entry["ap_count"] += 1
        if bss["signal_dbm"] is not None:
            if entry["loudest_dbm"] is None or bss["signal_dbm"] > entry["loudest_dbm"]:
                entry["loudest_dbm"] = bss["signal_dbm"]
    return [channels[key] for key in sorted(channels)]


def pick_candidates(permitted):
    """The legal non-overlapping set to choose between.

    13 is included where legal: it is clear of 1 and 6, and in practice it is
    often the quietest channel in a domain that allows it precisely because
    most hardware ships defaulted to the 1/6/11 set."""
    candidates = [channel for channel in NON_OVERLAPPING if channel in permitted]
    if 13 in permitted:
        candidates.append(13)
    if not candidates:
        candidates = sorted(permitted)[:1]
    return candidates


def db_ratio(louder, quieter):
    """How many dB quieter `quieter` is than `louder`.

    Returns None when the ratio is undefined because nothing at all was
    detected on the quieter channel. Inventing a large finite number there
    would be reporting a measurement that was never made."""
    if louder <= 0 and quieter <= 0:
        return 0.0
    if quieter <= 0:
        return None
    if louder <= 0:
        return 0.0
    return 10.0 * math.log10(louder / quieter)


def recommend(scores, candidates, current_channel, weighting_available):
    """Choose a channel and decide whether the move is worth making."""
    result = {
        "candidates": candidates,
        "current_channel": current_channel,
        "best_channel": None,
        "improvement_db": None,
        "worth_changing": False,
        "current_is_non_overlapping": None,
        "prefers_standard_set": False,
        "reason": None,
    }
    if not candidates:
        result["reason"] = "no legal channel to recommend"
        return result
    if not weighting_available:
        result["reason"] = (
            "signal strength is unavailable from this data source, so channels "
            "cannot be ranked by power"
        )
        return result

    best = min(candidates, key=lambda channel: scores.get(channel, 0.0))

    # Channel 13 is legal in much of the world but not universally supported by
    # clients, particularly US-market hardware, which simply will not associate
    # on it. So take it only when it is meaningfully quieter than the best of
    # the universal 1/6/11 set, not when it wins by a rounding error between
    # two empty channels.
    if best not in NON_OVERLAPPING:
        standard = [c for c in candidates if c in NON_OVERLAPPING]
        if standard:
            standard_best = min(standard, key=lambda channel: scores.get(channel, 0.0))
            margin = db_ratio(scores.get(standard_best, 0.0), scores.get(best, 0.0))
            if margin is not None and margin < WORTH_CHANGING_DB:
                best = standard_best
                result["prefers_standard_set"] = True

    result["best_channel"] = best
    best_score = scores.get(best, 0.0)

    if current_channel is None:
        result["reason"] = (
            "not associated, so there is no current channel to compare against"
        )
        result["worth_changing"] = False
        return result

    result["current_is_non_overlapping"] = current_channel in candidates
    current_score = scores.get(current_channel, 0.0)

    if best == current_channel:
        result["improvement_db"] = 0.0
        result["reason"] = "already on the quietest legal non-overlapping channel"
        return result

    if best_score <= 0 and current_score <= 0:
        result["improvement_db"] = 0.0
        result["reason"] = "no measurable WiFi power on either channel"
        return result

    improvement = db_ratio(current_score, best_score)
    if improvement is None:
        # Genuinely nothing detected on the target channel. Reporting a finite
        # dB figure against a zero denominator would be inventing one.
        result["worth_changing"] = True
        result["reason"] = f"no WiFi power detected on channel {best} at all"
        return result
    result["improvement_db"] = round(improvement, 1)

    if not result["current_is_non_overlapping"]:
        # Sitting off the 1/6/11 grid harms you and both neighbours at once,
        # so this is worth fixing even when the score barely moves.
        result["worth_changing"] = True
        result["reason"] = (
            f"channel {current_channel} overlaps its neighbours; the "
            "non-overlapping set exists to avoid exactly that"
        )
    elif improvement >= WORTH_CHANGING_DB:
        result["worth_changing"] = True
        result["reason"] = f"{improvement:.1f} dB quieter than channel {current_channel}"
    else:
        result["worth_changing"] = False
        result["reason"] = (
            f"only {improvement:.1f} dB quieter than channel {current_channel}, "
            f"which is below the {WORTH_CHANGING_DB:.0f} dB worth-the-disruption "
            "threshold"
        )
    return result


# ------------------------------------------------------------- data gathering


def gather_scan(args, iface, result):
    """Acquire BSS data using the best available source.

    Preference order is unprivileged-and-non-disruptive first: cached iw dump,
    then nmcli, then an active scan only when explicitly asked for."""
    warnings = result["warnings"]

    if args.active:
        if os.geteuid() != 0:
            result["error"] = "active-scan-needs-root"
            return None, "--active requires root; re-run with sudo"
        rc, text, reason = run(["iw", "dev", iface, "scan"], timeout=45)
        if rc == 0:
            networks, skipped = parse_iw_scan(text)
            result["source"] = "iw-scan-active"
            result["source_privileged"] = True
            result["signal_metric"] = "dbm"
            if skipped:
                warnings.append(f"{skipped} BSS block(s) were unparseable and skipped")
            return networks, None
        return None, f"active scan failed: {reason}"

    rc, text, reason = run(["iw", "dev", iface, "scan", "dump"])
    if rc == 0:
        networks, skipped = parse_iw_scan(text)
        result["source"] = "iw-scan-dump"
        result["source_privileged"] = False
        result["signal_metric"] = "dbm"
        if skipped:
            warnings.append(f"{skipped} BSS block(s) were unparseable and skipped")
        return networks, None

    warnings.append(f"iw scan dump unavailable ({reason}); trying nmcli")

    rc, text, nm_reason = run(
        [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "--rescan",
            "no",
        ]
    )
    if rc == 0:
        networks, skipped = parse_nmcli(text)
        result["source"] = "nmcli"
        result["source_privileged"] = False
        result["signal_metric"] = "quality_percent"
        result["weighting_available"] = False
        if skipped:
            warnings.append(f"{skipped} nmcli row(s) were unparseable and skipped")
        return networks, None

    return None, f"no usable data source (iw: {reason}; nmcli: {nm_reason})"


def build_result(args):
    """Do all the work and return one dict. Both the human renderer and --json
    consume this, which is what keeps them from drifting apart."""
    result = {
        "tool": "rfscan",
        "linux": sys.platform == "linux",
        "interface": None,
        "interfaces_found": [],
        "source": None,
        "source_privileged": None,
        "signal_metric": None,
        "weighting_available": True,
        "band": args.band,
        "scan_age_ms": {"freshest": None, "stalest": None},
        "regulatory": {
            "country": None,
            "legal_channels_2ghz": [],
            "reason": None,
            "fell_back": None,
        },
        "associated": None,
        "channels_2ghz": [],
        "channels_5ghz": [],
        "networks": [],
        "network_count": 0,
        "unweighted_count": 0,
        "recommendation": None,
        "caveats": [
            "A WiFi scan only sees WiFi. Bluetooth, USB 3 broadband noise, "
            "microwave ovens, Zigbee, video senders and proprietary HID "
            "receivers (including the Logitech receiver you may be trying to "
            "diagnose) are all invisible to it. A clean result here does not "
            "mean the band is clear.",
            "Logitech Unifying, Bolt and Lightspeed use adaptive frequency "
            "hopping across the whole 2.400-2.4835 GHz band. They do not sit "
            "on a channel. Any channel recommendation here applies to the "
            "access point and to nothing else.",
            "Channel scores are modelled from an approximated spectral mask, "
            "not measured. They rank channels against each other; they are not "
            "absolute figures.",
            "The only ground truth for whether a change helped is measuring it: "
            "change the AP channel, then re-run logi-rx --watch from the same "
            "spot and compare the gap count.",
        ],
        "warnings": [],
        "error": None,
        "exit_code": 0,
    }

    if not result["linux"]:
        result["error"] = "not-linux"
        result["exit_code"] = 2
        return result

    interfaces = wireless_interfaces()
    result["interfaces_found"] = interfaces
    if not interfaces:
        result["error"] = "no-wireless-interface"
        result["exit_code"] = 2
        return result

    if args.iface:
        chosen = next((i for i in interfaces if i["name"] == args.iface), None)
        if chosen is None:
            result["error"] = "iface-not-found"
            result["exit_code"] = 2
            return result
    else:
        chosen = interfaces[0]
        if not chosen["up"]:
            result["warnings"].append(
                f"{chosen['name']} is {chosen['operstate']}, not up; cached scan "
                "results may be missing or stale"
            )
    result["interface"] = chosen["name"]

    # Regulatory domain. Unprivileged, and it constrains everything below.
    rc, reg_text, reg_reason = run(["iw", "reg", "get"])
    if rc == 0:
        country, ranges = parse_reg(reg_text)
    else:
        country, ranges = None, []
        result["warnings"].append(f"could not read regulatory domain ({reg_reason})")
    permitted, reason, fell_back = legal_channels(country, ranges)
    result["regulatory"] = {
        "country": country,
        "legal_channels_2ghz": permitted,
        "reason": reason,
        "fell_back": fell_back,
    }

    networks, error = gather_scan(args, chosen["name"], result)
    if networks is None:
        if result["error"] is None:
            # gather_scan did not classify this, so it is a generic acquisition
            # failure and the raw reason is the only detail available.
            result["error"] = "no-data"
            if error:
                result["warnings"].append(error)
        result["exit_code"] = 1
        return result

    result["networks"] = networks
    result["network_count"] = len(networks)

    if not networks:
        # An empty cache is not an empty band. Freshly booted machines that
        # have not scanned yet look exactly like this.
        result["error"] = "empty-scan-cache"
        result["exit_code"] = 1
        return result

    ages = [n["last_seen_ms"] for n in networks if n.get("last_seen_ms") is not None]
    if ages:
        result["scan_age_ms"] = {"freshest": min(ages), "stalest": max(ages)}

    # Current association.
    rc, link_text, _ = run(["iw", "dev", chosen["name"], "link"])
    if rc == 0:
        result["associated"] = parse_iw_link(link_text)
    if result["associated"] is None:
        marked = next((n for n in networks if n.get("associated")), None)
        if marked:
            result["associated"] = {
                "bssid": marked["bssid"],
                "ssid": marked["ssid"],
                "freq": marked["freq"],
                "channel": marked["channel"],
            }

    scores, counts, unweighted = occupancy_2ghz(networks)
    result["unweighted_count"] = unweighted
    if unweighted:
        result["warnings"].append(
            f"{unweighted} network(s) reported no signal strength and are counted "
            "but not weighted"
        )

    assumed = sum(1 for n in networks if n["band"] == "2.4" and n.get("width_assumed"))
    if assumed:
        result["warnings"].append(
            f"{assumed} network(s) did not report an HT secondary channel; assumed "
            "20 MHz width for those"
        )

    max_score = max(scores.values()) if scores else 0.0
    result["channels_2ghz"] = [
        {
            "channel": channel,
            "freq": channel_to_freq(channel),
            "legal": channel in permitted,
            "ap_count": counts[channel],
            "score": scores[channel],
            "score_relative": (
                round(100.0 * scores[channel] / max_score, 1) if max_score > 0 else 0.0
            ),
        }
        for channel in CHANNELS_2GHZ
    ]
    result["channels_5ghz"] = occupancy_5ghz(networks)

    current_channel = None
    if result["associated"] and result["associated"].get("channel"):
        if band_of(result["associated"].get("freq")) == "2.4":
            current_channel = result["associated"]["channel"]

    candidates = pick_candidates(permitted)
    result["recommendation"] = recommend(
        scores, candidates, current_channel, result["weighting_available"]
    )

    if result["recommendation"]["worth_changing"]:
        result["exit_code"] = 1
    return result


# ------------------------------------------------------------------ rendering


def fmt_ssid(bss):
    if bss.get("hidden") or not bss.get("ssid"):
        return "(hidden)"
    ssid = bss["ssid"]
    return ssid if len(ssid) <= 28 else ssid[:25] + "..."


def render_error(out, result):
    messages = {
        "not-linux": (
            "This script only works on Linux (it reads sysfs and talks to nl80211)",
            None,
        ),
        "no-wireless-interface": (
            "No wireless interface found",
            "Nothing in /sys/class/net has a phy80211 or wireless node. There is\n"
            "no radio here to scan with.",
        ),
        "iface-not-found": (
            "No wireless interface by that name",
            "Available: "
            + (", ".join(i["name"] for i in result["interfaces_found"]) or "none"),
        ),
        "active-scan-needs-root": (
            "--active requires root",
            "An active scan asks the kernel to transmit probe requests. Re-run\n"
            "with sudo, or drop --active to use the cached results.",
        ),
        "empty-scan-cache": (
            "The scan cache is empty - this does NOT mean the band is clear",
            "A machine that has just booted, or a radio that has not associated\n"
            "yet, has nothing cached to report. Either connect to a network, or\n"
            "run:  sudo rfscan --active",
        ),
        "no-data": ("No usable scan data", None),
    }
    text, detail = messages.get(result["error"], (f"Failed: {result['error']}", None))
    out.header("Result")
    out.fail(text, detail)
    for warning in result["warnings"]:
        out.info(warning)


def render_source(out, result):
    out.header("Interface and data source")
    out.info(f"Interface:  {result['interface']}")

    others = [i["name"] for i in result["interfaces_found"] if i["name"] != result["interface"]]
    if others:
        out.info(f"Also found: {', '.join(others)}  (override with --iface)")

    labels = {
        "iw-scan-dump": "iw scan dump (cached, unprivileged, link undisturbed)",
        "iw-scan-active": "iw scan (ACTIVE - this disturbed the connection)",
        "nmcli": "nmcli (cached, unprivileged)",
    }
    out.info(f"Source:     {labels.get(result['source'], result['source'])}")
    out.info(f"Networks:   {result['network_count']}")

    freshest = result["scan_age_ms"]["freshest"]
    stalest = result["scan_age_ms"]["stalest"]
    if freshest is not None:
        out.info(f"Cache age:  {freshest / 1000.0:.1f}s to {stalest / 1000.0:.1f}s old")
        if stalest > 120000:
            out.warn(
                "Some entries are over two minutes old",
                "Cached results linger after an AP goes away. Re-run with --active\n"
                "for a current picture, at the cost of disrupting the link.",
            )
    else:
        out.info("Cache age:  not reported by this source")

    if not result["weighting_available"]:
        out.warn(
            "This source reports signal as a 0-100 quality percentage, not dBm",
            "Quality percentages are driver-specific and not convertible to power\n"
            "without inventing a figure, so channels are ranked by AP count only\n"
            "and no recommendation is made. Install `iw` for weighted scoring.",
        )


def render_regulatory(out, result):
    out.header("Regulatory domain")
    reg = result["regulatory"]
    country = reg["country"] or "unknown"
    channels = reg["legal_channels_2ghz"]
    span = f"{min(channels)}-{max(channels)}" if channels else "none"
    out.info(f"Domain:     {country}")
    out.info(f"Legal 2.4:  channels {span}")
    if reg["fell_back"]:
        out.warn(
            f"Falling back to the 1/6/11 set: {reg['reason']}",
            "Channels outside that set may well be legal where you are, but this\n"
            "tool will not recommend one it cannot confirm.",
        )
    else:
        out.info(f"Source:     {reg['reason']}")


def render_histogram(out, result):
    out.header("2.4 GHz occupancy")

    weighted = result["weighting_available"]
    current = None
    if result["recommendation"]:
        current = result["recommendation"]["current_channel"]

    rows = result["channels_2ghz"]
    if weighted:
        peak = max((row["score_relative"] for row in rows), default=0.0)
        label = "occupancy (power-weighted)"
        emit(f"  {'ch':>3}  freq  {label:<{BAR_WIDTH}}  {'score':>5}  APs")
    else:
        peak = max((row["ap_count"] for row in rows), default=0)
        label = "occupancy (AP count only)"
        emit(f"  {'ch':>3}  freq  {label:<{BAR_WIDTH}}  APs")
    emit()

    for row in rows:
        channel = row["channel"]
        magnitude = row["score_relative"] if weighted else row["ap_count"]
        if not row["legal"]:
            # Pad before colouring: escape codes have width on the terminal of
            # zero but length in the string, so padding a coloured value breaks
            # the column alignment of every row around it.
            label = f"{'not permitted in this domain':<{BAR_WIDTH}}"
            marker = "  <-- current" if channel == current else ""
            # The AP count is still shown. A neighbour transmitting on a channel
            # you may not legally use still lands on top of the ones you can.
            tail = f"      -  {row['ap_count']:>3}" if weighted else f"  {row['ap_count']:>3}"
            emit(f"  {channel:>3}  {row['freq']}  {out._c('90', label)}{tail}{marker}")
            continue

        filled = int(round(BAR_WIDTH * magnitude / peak)) if peak > 0 else 0
        bar = "#" * filled
        marker = "  <-- current" if channel == current else ""
        if weighted:
            tail = f"  {row['score_relative']:>5.1f}  {row['ap_count']:>3}"
        else:
            # Without weighting the score column would just repeat the AP count.
            tail = f"  {row['ap_count']:>3}"
        line = f"  {channel:>3}  {row['freq']}  {bar:<{BAR_WIDTH}}{tail}{marker}"
        if channel == current:
            emit(out._c("1", line))
        else:
            emit(line)

    if weighted:
        emit()
        out.info(
            "Score is summed linear power spread across overlapping channels, "
            "normalised to the busiest channel."
        )
        out.info(
            "Score and AP count can disagree. When they do, trust the score: one "
            "loud neighbour outweighs six distant ones."
        )


def render_offenders(out, result):
    loudest = [
        bss
        for bss in result["networks"]
        if bss["band"] == "2.4" and bss["signal_dbm"] is not None
    ]
    if not loudest:
        return
    loudest.sort(key=lambda bss: bss["signal_dbm"], reverse=True)

    out.header("Loudest 2.4 GHz networks")
    for bss in loudest[:8]:
        width = f"{bss['width_mhz']}MHz" if not bss.get("width_assumed") else "20MHz?"
        emit(
            f"  {bss['signal_dbm']:>7.1f} dBm  ch {bss['channel']:>2}  "
            f"{width:<7} {fmt_ssid(bss)}"
        )
    if len(loudest) > 8:
        out.info(f"{len(loudest) - 8} more not shown")


def render_recommendation(out, result):
    out.header("Recommendation")
    rec = result["recommendation"]
    if rec is None:
        out.info("No recommendation available")
        return

    if rec["best_channel"] is None:
        out.warn(f"No channel recommended: {rec['reason']}")
        return

    out.info(f"Candidates: {'/'.join(str(c) for c in rec['candidates'])} (legal, non-overlapping)")
    if rec.get("prefers_standard_set"):
        out.info(
            "Channel 13 scored marginally lower but was not chosen: it is legal "
            "here yet not universally supported by clients, and the difference "
            "was not large enough to be worth the compatibility risk."
        )
    elif rec["best_channel"] == 13:
        out.warn(
            "Channel 13 is the recommendation, and it is legal in this domain",
            "Some client hardware, US-market devices in particular, will not\n"
            "associate on 13 at all. Check your devices can see the AP after\n"
            "the change before assuming it worked.",
        )

    if rec["current_channel"] is None:
        out.info(f"Quietest legal non-overlapping channel: {rec['best_channel']}")
        out.info(rec["reason"])
    elif rec["worth_changing"]:
        if rec["improvement_db"] is None:
            out.warn(f"Move the AP from channel {rec['current_channel']} to {rec['best_channel']}")
            out.info(rec["reason"])
        else:
            out.warn(
                f"Move the AP from channel {rec['current_channel']} to "
                f"{rec['best_channel']}  ({rec['improvement_db']:+.1f} dB quieter)"
            )
            out.info(rec["reason"])
    else:
        out.ok(f"Stay on channel {rec['current_channel']}")
        out.info(rec["reason"])
        out.info(
            "A tool that always recommends a change is a tool you learn to "
            "ignore. This is not worth the disruption."
        )

    if rec["worth_changing"]:
        emit()
        emit("  This applies to the ACCESS POINT and to nothing else.")
        emit("  Logitech Unifying, Bolt and Lightspeed hop across the entire")
        emit("  2.400-2.4835 GHz band and never sit on a channel, so there is no")
        emit("  channel setting on your mouse or keyboard to change.")
        emit()
        emit("  Then prove it helped, from the same spot you sit in:")
        emit("      logi-rx --watch")
        emit("  A drop in the gap count is the only real evidence.")


def render_5ghz(out, result):
    out.header("5 GHz")
    rows = result["channels_5ghz"]
    if not rows:
        out.info("No 5 GHz networks seen.")
        out.info(
            "That may mean the band is empty, or that this radio is 2.4-only. A "
            "scan cannot tell those apart, so I will not guess."
        )
        return

    total = sum(row["ap_count"] for row in rows)
    out.info(f"{total} network(s) across {len(rows)} channel(s)")
    for row in rows[:10]:
        loudest = f"{row['loudest_dbm']:.1f} dBm" if row["loudest_dbm"] is not None else "no signal reading"
        emit(f"    ch {row['channel']:>3}  {row['ap_count']:>2} AP(s)  loudest {loudest}")
    if len(rows) > 10:
        out.info(f"{len(rows) - 10} more channel(s) not shown")

    emit()
    if total <= 3:
        out.ok("5 GHz looks lightly used here")
        out.info(
            "Moving the AP's clients to 5 GHz is usually a bigger win than "
            "shuffling 2.4 GHz channels: it vacates the crowded band entirely, "
            "and it leaves 2.4 GHz to the peripherals that have no alternative."
        )
    else:
        out.info(
            "Even where 5 GHz is busy, moving laptops and phones to it frees "
            "2.4 GHz for the devices that cannot use anything else."
        )


def render_caveats(out, result):
    out.header("What this cannot see")
    for index, caveat in enumerate(result["caveats"]):
        # The first two are the load-bearing ones: they decide whether the
        # numbers above mean anything at all. They get warn styling, not info.
        style = out.warn if index < 2 else out.info
        style(caveat)
    if result["warnings"]:
        emit()
        for warning in result["warnings"]:
            out.info(warning)


def render(out, result):
    if result["error"]:
        render_error(out, result)
        return
    render_source(out, result)
    render_regulatory(out, result)
    if result["band"] in ("2.4", "both"):
        render_histogram(out, result)
        render_offenders(out, result)
        render_recommendation(out, result)
    # 5 GHz is always shown. Even when the user asked only about 2.4, "move to
    # 5 GHz" is frequently the better answer than any channel shuffle, and a
    # tool that hides the better answer to respect a flag is not helping.
    render_5ghz(out, result)
    render_caveats(out, result)


# ------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="Map 2.4 GHz channel occupancy and recommend a quieter AP channel.",
        epilog=(
            "Read-only: this tool never changes system state. --active is the only "
            "privileged mode and it only asks the kernel to scan.\n\n"
            "A WiFi scan sees only WiFi. Bluetooth, USB 3 noise, microwaves and "
            "Zigbee are invisible to it, and Logitech receivers hop across the "
            "whole band rather than sitting on a channel, so any channel advice "
            "here is for the access point alone."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface", metavar="NAME", help="force a wireless interface")
    parser.add_argument(
        "--active",
        action="store_true",
        help="trigger a real scan instead of reading the cache. Requires root. "
        "DISRUPTS the connection: it briefly stalls or disassociates the link, "
        "and on some drivers drops it entirely.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable colour output")
    parser.add_argument(
        "--band",
        choices=["2.4", "5", "both"],
        default="2.4",
        help="which band to report in detail (default: 2.4)",
    )
    args = parser.parse_args()

    result = build_result(args)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        render(Out(color=not args.no_color), result)

    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
