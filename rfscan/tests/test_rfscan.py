#!/usr/bin/env python3
"""
Tests for rfscan.

Run from anywhere:

    python3 -m unittest discover -s rfscan/tests -v
    ./rfscan/tests/test_rfscan.py

Standard library only, same rule as the tools themselves.

The bulk of these test the `iw` parser against captured fixtures, including a
deliberately hostile one. `iw` output is not a stable API: it varies by version
and by driver, so the parser's contract is "skip what you do not recognise,
never lose a network you do, and never let one bad block abort the scan". That
contract is what is being asserted here.
"""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))

import rfscan  # noqa: E402


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def by_bssid(networks):
    return {bss["bssid"]: bss for bss in networks}


class TestBandArithmetic(unittest.TestCase):
    def test_known_channel_centres(self):
        self.assertEqual(rfscan.channel_to_freq(1), 2412)
        self.assertEqual(rfscan.channel_to_freq(6), 2437)
        self.assertEqual(rfscan.channel_to_freq(11), 2462)
        self.assertEqual(rfscan.channel_to_freq(13), 2472)
        self.assertEqual(rfscan.channel_to_freq(14), 2484)

    def test_round_trip(self):
        for channel in rfscan.CHANNELS_2GHZ:
            freq = rfscan.channel_to_freq(channel)
            self.assertEqual(rfscan.freq_to_channel(freq), channel)

    def test_five_ghz(self):
        self.assertEqual(rfscan.freq_to_channel(5180), 36)
        self.assertEqual(rfscan.freq_to_channel(5745), 149)
        self.assertEqual(rfscan.band_of(5180), "5")

    def test_unrecognised_frequency(self):
        self.assertIsNone(rfscan.freq_to_channel(9999))
        self.assertIsNone(rfscan.band_of(9999))
        self.assertIsNone(rfscan.freq_to_channel(None))

    def test_six_ghz_is_not_mistaken_for_five(self):
        self.assertEqual(rfscan.band_of(6115), "6")


class TestCleanScan(unittest.TestCase):
    def setUp(self):
        self.networks, self.skipped = rfscan.parse_iw_scan(fixture("iw-scan-clean.txt"))

    def test_all_parsed(self):
        self.assertEqual(len(self.networks), 3)
        self.assertEqual(self.skipped, 0)

    def test_association_marker(self):
        found = by_bssid(self.networks)
        self.assertTrue(found["00:11:22:33:44:55"]["associated"])
        self.assertFalse(found["00:11:22:33:44:66"]["associated"])

    def test_signal_and_channel(self):
        found = by_bssid(self.networks)["00:11:22:33:44:55"]
        self.assertEqual(found["signal_dbm"], -42.0)
        self.assertEqual(found["channel"], 6)
        self.assertEqual(found["ssid"], "HomeNet")
        self.assertFalse(found["hidden"])

    def test_no_secondary_is_a_reading_not_an_assumption(self):
        # HT operation said "no secondary". 20 MHz is then measured, and must
        # not be flagged as an assumption in the output.
        found = by_bssid(self.networks)["00:11:22:33:44:55"]
        self.assertEqual(found["width_mhz"], 20)
        self.assertIsNone(found["secondary_channel"])
        self.assertFalse(found["width_assumed"])

    def test_missing_ht_operation_is_an_assumption(self):
        found = by_bssid(self.networks)["00:11:22:33:44:77"]
        self.assertEqual(found["width_mhz"], 20)
        self.assertTrue(found["width_assumed"])


class TestMessyScan(unittest.TestCase):
    def setUp(self):
        self.networks, self.skipped = rfscan.parse_iw_scan(fixture("iw-scan-messy.txt"))
        self.found = by_bssid(self.networks)

    def test_counts(self):
        # Ten BSS blocks; two carry no frequency and cannot be placed on a
        # channel, so they are skipped rather than guessed at.
        self.assertEqual(len(self.networks), 8)
        self.assertEqual(self.skipped, 2)

    def test_hidden_ssid_empty(self):
        bss = self.found["00:11:22:33:44:02"]
        self.assertIsNone(bss["ssid"])
        self.assertTrue(bss["hidden"])
        # The real regression risk: a bare "SSID:" line looks exactly like a
        # sub-block heading, and mistaking it drops the network entirely.
        self.assertEqual(bss["channel"], 1)

    def test_hidden_ssid_nulled(self):
        bss = self.found["00:11:22:33:44:05"]
        self.assertIsNone(bss["ssid"])
        self.assertTrue(bss["hidden"])

    def test_non_ascii_ssids_survive(self):
        self.assertEqual(self.found["00:11:22:33:44:03"]["ssid"], "Café_Wireless")
        self.assertEqual(self.found["00:11:22:33:44:08"]["ssid"], "日本語ネット")

    def test_missing_signal_field(self):
        bss = self.found["00:11:22:33:44:04"]
        self.assertIsNone(bss["signal_dbm"])
        # Still counted, still placed on a channel. Only the weighting is lost.
        self.assertEqual(bss["channel"], 1)

    def test_forty_mhz_secondary_above(self):
        bss = self.found["00:11:22:33:44:01"]
        self.assertEqual(bss["channel"], 6)
        self.assertEqual(bss["secondary_channel"], 10)
        self.assertEqual(bss["width_mhz"], 40)

    def test_forty_mhz_secondary_below(self):
        bss = self.found["00:11:22:33:44:08"]
        self.assertEqual(bss["channel"], 13)
        self.assertEqual(bss["secondary_channel"], 9)
        self.assertEqual(bss["width_mhz"], 40)

    def test_off_grid_40mhz_secondary_is_flagged_as_assumed(self):
        # HT operation declares a 40 MHz pairing whose secondary would be
        # channel 17, which does not exist. The AP is not 20 MHz; we simply
        # cannot place the other half, so recording a measured 20 MHz would
        # assert something that was never read.
        text = (
            "BSS 00:11:22:33:44:ff(on wlan0)\n"
            "\tfreq: 2462\n"
            "\tsignal: -50.00 dBm\n"
            "\tSSID: EdgeWide\n"
            "\tHT operation:\n"
            "\t\t * primary channel: 13\n"
            "\t\t * secondary channel offset: above\n"
        )
        networks, _ = rfscan.parse_iw_scan(text)
        bss = networks[0]
        self.assertIsNone(bss["secondary_channel"])
        self.assertEqual(bss["width_mhz"], 20)
        self.assertTrue(bss["width_assumed"])

    def test_five_ghz_width_is_not_asserted(self):
        bss = self.found["00:11:22:33:44:07"]
        self.assertEqual(bss["band"], "5")
        self.assertEqual(bss["channel"], 36)
        # An 80 MHz VHT AP. The 2.4 GHz width model does not describe it, so
        # the tool records nothing rather than claiming 20 MHz.
        self.assertIsNone(bss["width_mhz"])

    def test_unknown_lines_do_not_lose_the_network(self):
        bss = self.found["00:11:22:33:44:09"]
        self.assertEqual(bss["ssid"], "OffGrid")
        self.assertEqual(bss["channel"], 2)

    def test_last_seen_captured(self):
        self.assertEqual(self.found["00:11:22:33:44:01"]["last_seen_ms"], 340.0)


class TestParserRobustness(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(rfscan.parse_iw_scan(""), ([], 0))

    def test_pure_garbage(self):
        networks, skipped = rfscan.parse_iw_scan("not iw output\nat all\n\n\t\t\n")
        self.assertEqual(networks, [])
        self.assertEqual(skipped, 0)

    def test_unparseable_frequency_is_skipped_not_fatal(self):
        text = (
            "BSS 00:11:22:33:44:aa(on wlan0)\n"
            "\tfreq: not-a-number\n"
            "\tsignal: -50.00 dBm\n"
            "\tSSID: Broken\n"
            "BSS 00:11:22:33:44:bb(on wlan0)\n"
            "\tfreq: 2437\n"
            "\tsignal: -50.00 dBm\n"
            "\tSSID: Fine\n"
        )
        networks, skipped = rfscan.parse_iw_scan(text)
        self.assertEqual(skipped, 1)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "Fine")

    def test_signal_without_dbm_unit_is_not_trusted(self):
        # Some drivers report unitless or percentage signal here. Reading it as
        # dBm would poison every score downstream.
        text = (
            "BSS 00:11:22:33:44:cc(on wlan0)\n"
            "\tfreq: 2437\n"
            "\tsignal: 70/100\n"
            "\tSSID: Unitless\n"
        )
        networks, _ = rfscan.parse_iw_scan(text)
        self.assertEqual(len(networks), 1)
        self.assertIsNone(networks[0]["signal_dbm"])

    def test_truncated_final_block(self):
        text = "BSS 00:11:22:33:44:dd(on wlan0)\n\tlast seen: 100 ms ago"
        networks, skipped = rfscan.parse_iw_scan(text)
        self.assertEqual(networks, [])
        self.assertEqual(skipped, 1)

    def test_channel_derived_from_freq_when_ds_absent(self):
        text = "BSS 00:11:22:33:44:ee(on wlan0)\n\tfreq: 2462\n\tsignal: -50.00 dBm\n"
        networks, _ = rfscan.parse_iw_scan(text)
        self.assertEqual(networks[0]["channel"], 11)


class TestWeighting(unittest.TestCase):
    def test_dbm_is_a_log_scale(self):
        # The single most common bug in tools like this is averaging or summing
        # dBm directly. 30 dB is a factor of a thousand in power, and that
        # ratio is the entire reason for weighting.
        ratio = rfscan.dbm_to_mw(-30) / rfscan.dbm_to_mw(-60)
        self.assertAlmostEqual(ratio, 1000.0, places=6)

    def test_one_six_eleven_do_not_overlap(self):
        self.assertEqual(rfscan.overlap_weight(2412, 2437), 0.0)
        self.assertEqual(rfscan.overlap_weight(2437, 2462), 0.0)
        self.assertEqual(rfscan.overlap_weight(2412, 2462), 0.0)

    def test_adjacent_channels_do_overlap(self):
        self.assertGreater(rfscan.overlap_weight(2412, 2417), 0.0)
        self.assertAlmostEqual(rfscan.overlap_weight(2412, 2417), 0.8, places=6)

    def test_channel_14_uses_frequency_not_channel_number(self):
        # 14 sits 12 MHz above 13, not 5. Subtracting channel numbers would
        # give 0.8 here, which would be wrong by more than a third.
        weight = rfscan.overlap_weight(2484, 2472)
        self.assertAlmostEqual(weight, (25.0 - 12.0) / 25.0, places=6)
        self.assertNotAlmostEqual(weight, 0.8, places=2)

    def test_loud_neighbour_outweighs_many_quiet_ones(self):
        loud = [
            {
                "band": "2.4", "channel": 1, "signal_dbm": -30.0,
                "secondary_channel": None,
            }
        ]
        quiet = [
            {
                "band": "2.4", "channel": 6, "signal_dbm": -60.0,
                "secondary_channel": None,
            }
            for _ in range(6)
        ]
        scores, counts, unweighted = rfscan.occupancy_2ghz(loud + quiet)
        self.assertEqual(counts[1], 1)
        self.assertEqual(counts[6], 6)
        self.assertEqual(unweighted, 0)
        # Six quiet APs still lose to one loud one by a wide margin. If this
        # ever inverts, the weighting has regressed to counting.
        self.assertGreater(scores[1], scores[6] * 100)

    def test_unweighted_networks_are_counted_but_not_scored(self):
        networks = [
            {"band": "2.4", "channel": 6, "signal_dbm": None, "secondary_channel": None}
        ]
        scores, counts, unweighted = rfscan.occupancy_2ghz(networks)
        self.assertEqual(counts[6], 1)
        self.assertEqual(unweighted, 1)
        self.assertEqual(scores[6], 0.0)

    def total_energy(self, networks):
        scores, _, _ = rfscan.occupancy_2ghz(networks)
        return sum(scores.values())

    def ap(self, channel, secondary=None, dbm=-40.0):
        return {
            "band": "2.4",
            "channel": channel,
            "signal_dbm": dbm,
            "secondary_channel": secondary,
        }

    def test_forty_mhz_does_not_double_count_energy(self):
        # The failure this guards against: crediting a 40 MHz AP with the full
        # power on BOTH carriers instead of half on each. That would total ~2x
        # the 20 MHz case and would inflate every mid-band channel, which is
        # exactly what a spurious plateau in the histogram would look like.
        narrow = self.total_energy([self.ap(6)])
        wide = self.total_energy([self.ap(6, 10)])
        ratio = wide / narrow
        self.assertLess(ratio, 1.05)
        self.assertGreater(ratio, 0.95)
        # Stated explicitly so the intent survives a future refactor.
        self.assertNotAlmostEqual(ratio, 2.0, places=1)

    def test_grid_edge_truncation_is_a_known_artifact(self):
        # Energy that spills below channel 1 or above 14 leaves the grid, so the
        # GRID TOTAL depends on where a carrier sits: a mid-band AP accounts for
        # 5.0x its power and one on channel 1 only 3.0x. This is a property of
        # summing a finite grid, not of the weighting, and it is pinned here so
        # that a future conservation check is not read as a regression.
        power = rfscan.dbm_to_mw(-40.0)
        self.assertAlmostEqual(self.total_energy([self.ap(6)]) / power, 5.0, places=6)
        self.assertAlmostEqual(self.total_energy([self.ap(1)]) / power, 3.0, places=6)

    def test_per_channel_scores_are_not_truncated_at_the_band_edge(self):
        # The reassurance that makes the artifact above harmless: a channel's
        # own score sums contributions TO it from every AP within range, so it
        # is complete even at channel 1. Only the diagnostic total is truncated,
        # and nothing in the recommendation path uses that total.
        power = rfscan.dbm_to_mw(-40.0)
        scores, _, _ = rfscan.occupancy_2ghz([self.ap(1), self.ap(2), self.ap(3)])
        self.assertAlmostEqual(scores[1], power * (1.0 + 0.8 + 0.6), places=12)

    def test_forty_mhz_spreads_across_both_carriers(self):
        wide = [
            {"band": "2.4", "channel": 6, "signal_dbm": -40.0, "secondary_channel": 10}
        ]
        narrow = [
            {"band": "2.4", "channel": 6, "signal_dbm": -40.0, "secondary_channel": None}
        ]
        wide_scores, _, _ = rfscan.occupancy_2ghz(wide)
        narrow_scores, _, _ = rfscan.occupancy_2ghz(narrow)
        # The 40 MHz AP pushes more energy up the band toward 11 than the
        # 20 MHz one on the same primary channel.
        self.assertGreater(wide_scores[11], narrow_scores[11])
        self.assertLess(wide_scores[6], narrow_scores[6])

    def test_own_bss_is_excluded_from_scoring(self):
        # Your own AP is usually the loudest thing in the scan and it sits on
        # the channel you are being asked whether to leave. Counting it would
        # inflate the current channel against every alternative and bias the
        # tool toward always recommending a move.
        networks = [
            dict(self.ap(6, dbm=-30.0), bssid="aa:bb:cc:dd:ee:ff"),
            dict(self.ap(1, dbm=-70.0), bssid="11:22:33:44:55:66"),
        ]
        with_own, counts_with, _ = rfscan.occupancy_2ghz(networks)
        without, counts_without, _ = rfscan.occupancy_2ghz(
            networks, exclude_bssid="aa:bb:cc:dd:ee:ff"
        )
        self.assertGreater(with_own[6], without[6])
        self.assertEqual(without[6], 0.0)
        # Counts move with the score so the two columns cannot disagree.
        self.assertEqual(counts_with[6], 1)
        self.assertEqual(counts_without[6], 0)
        # Everyone else is untouched.
        self.assertAlmostEqual(with_own[1], without[1], places=12)

    def test_five_ghz_is_excluded_from_the_24_model(self):
        networks = [
            {"band": "5", "channel": 36, "signal_dbm": -30.0, "secondary_channel": None}
        ]
        scores, counts, _ = rfscan.occupancy_2ghz(networks)
        self.assertEqual(sum(scores.values()), 0.0)
        self.assertEqual(sum(counts.values()), 0)


class TestRegulatory(unittest.TestCase):
    def legal_for(self, name):
        country, ranges = rfscan.parse_reg(fixture(name))
        return country, rfscan.legal_channels(country, ranges)

    def test_us_is_one_to_eleven(self):
        country, (channels, _, fell_back) = self.legal_for("iw-reg-us.txt")
        self.assertEqual(country, "US")
        self.assertEqual(channels, list(range(1, 12)))
        self.assertFalse(fell_back)

    def test_eu_is_one_to_thirteen(self):
        country, (channels, _, fell_back) = self.legal_for("iw-reg-de.txt")
        self.assertEqual(country, "DE")
        self.assertEqual(channels, list(range(1, 14)))
        self.assertFalse(fell_back)

    def test_japan_adds_fourteen(self):
        country, (channels, _, fell_back) = self.legal_for("iw-reg-jp.txt")
        self.assertEqual(country, "JP")
        self.assertIn(14, channels)
        self.assertEqual(channels, list(range(1, 15)))
        self.assertFalse(fell_back)

    def test_world_domain_falls_back_and_says_so(self):
        country, (channels, reason, fell_back) = self.legal_for("iw-reg-world.txt")
        self.assertEqual(country, "00")
        self.assertEqual(channels, [1, 6, 11])
        self.assertTrue(fell_back)
        self.assertIn("world", reason)

    def test_unknown_domain_falls_back(self):
        channels, reason, fell_back = rfscan.legal_channels(None, [])
        self.assertEqual(channels, [1, 6, 11])
        self.assertTrue(fell_back)
        self.assertIn("unknown", reason)

    def test_only_the_first_country_block_is_used(self):
        text = fixture("iw-reg-us.txt") + "phy#0\ncountry DE: DFS-ETSI\n\t(2400 - 2483.5 @ 40)\n"
        country, ranges = rfscan.parse_reg(text)
        self.assertEqual(country, "US")
        channels, _, _ = rfscan.legal_channels(country, ranges)
        self.assertNotIn(13, channels)

    def test_candidates_include_13_only_where_legal(self):
        self.assertEqual(rfscan.pick_candidates(list(range(1, 12))), [1, 6, 11])
        self.assertEqual(rfscan.pick_candidates(list(range(1, 14))), [1, 6, 11, 13])

    def test_channel_14_is_never_a_candidate_even_in_japan(self):
        # 14 is DSSS-only: an OFDM access point cannot use it at all, so
        # recommending it is actively harmful rather than merely suboptimal.
        # Legality is necessary but not sufficient.
        country, ranges = rfscan.parse_reg(fixture("iw-reg-jp.txt"))
        permitted, _, _ = rfscan.legal_channels(country, ranges)
        self.assertIn(14, permitted)
        self.assertNotIn(14, rfscan.pick_candidates(permitted))

    def test_channel_14_is_excluded_even_as_the_last_resort(self):
        # The fallback branch must not reach for it either.
        self.assertNotIn(14, rfscan.pick_candidates([14]))
        self.assertEqual(rfscan.pick_candidates([12, 14]), [12])

    def test_channel_12_is_never_a_candidate_in_any_real_domain(self):
        # 12 raises the same client-compatibility question as 13, but it never
        # reaches the hysteresis because it is not in any standard
        # non-overlapping set and so is never offered in the first place.
        for name in ("iw-reg-us.txt", "iw-reg-de.txt", "iw-reg-jp.txt"):
            country, ranges = rfscan.parse_reg(fixture(name))
            permitted, _, _ = rfscan.legal_channels(country, ranges)
            self.assertNotIn(12, rfscan.pick_candidates(permitted), name)


class TestRecommendation(unittest.TestCase):
    def test_marginal_gain_is_not_worth_changing(self):
        # A tool that always recommends a change is a tool people learn to
        # ignore, so sub-3 dB gains must come back as "stay put".
        scores = {1: 1.0, 6: 1.2, 11: 1.0}
        scores.update({c: 0.0 for c in rfscan.CHANNELS_2GHZ if c not in scores})
        result = rfscan.recommend(scores, [1, 6, 11], 6, True)
        self.assertFalse(result["worth_changing"])
        self.assertLess(result["improvement_db"], rfscan.WORTH_CHANGING_DB)

    def test_large_gain_is_worth_changing(self):
        scores = {1: 0.01, 6: 10.0, 11: 5.0}
        scores.update({c: 0.0 for c in rfscan.CHANNELS_2GHZ if c not in scores})
        result = rfscan.recommend(scores, [1, 6, 11], 6, True)
        self.assertTrue(result["worth_changing"])
        self.assertEqual(result["best_channel"], 1)
        self.assertAlmostEqual(result["improvement_db"], 30.0, places=1)

    def test_off_grid_current_channel_always_warrants_a_move(self):
        # Sitting on channel 2 harms both 1 and 6 even when the score barely
        # moves, so the score threshold must not veto the recommendation.
        scores = {c: 1.0 for c in rfscan.CHANNELS_2GHZ}
        result = rfscan.recommend(scores, [1, 6, 11], 2, True)
        self.assertTrue(result["worth_changing"])
        self.assertFalse(result["current_is_non_overlapping"])
        self.assertIn("overlaps", result["reason"])

    def test_already_on_the_best_channel(self):
        scores = {1: 5.0, 6: 1.0, 11: 9.0}
        scores.update({c: 0.0 for c in rfscan.CHANNELS_2GHZ if c not in scores})
        result = rfscan.recommend(scores, [1, 6, 11], 6, True)
        self.assertFalse(result["worth_changing"])
        self.assertEqual(result["improvement_db"], 0.0)

    def test_channel_13_not_taken_for_a_rounding_error(self):
        # 13 wins on score, but only just. Between two effectively empty
        # channels that difference is noise, and 13 is not universally
        # supported by clients, so the standard set should win.
        scores = {c: 0.0 for c in rfscan.CHANNELS_2GHZ}
        # A 1.25x power ratio is under 1 dB. Note that a 2x ratio would be
        # 3.01 dB and would legitimately win, so the margin here is chosen to
        # sit clearly inside the threshold rather than on top of it.
        scores.update({1: 5.0, 6: 9.0, 11: 1.0e-9, 13: 8.0e-10})
        result = rfscan.recommend(scores, [1, 6, 11, 13], 6, True)
        self.assertEqual(result["best_channel"], 11)
        self.assertTrue(result["prefers_standard_set"])

    def test_channel_13_taken_when_clearly_quieter(self):
        scores = {c: 0.0 for c in rfscan.CHANNELS_2GHZ}
        scores.update({1: 5.0, 6: 9.0, 11: 4.0, 13: 0.004})
        result = rfscan.recommend(scores, [1, 6, 11, 13], 6, True)
        self.assertEqual(result["best_channel"], 13)
        self.assertFalse(result["prefers_standard_set"])

    def test_db_ratio_is_undefined_against_silence(self):
        self.assertIsNone(rfscan.db_ratio(1.0, 0.0))
        self.assertEqual(rfscan.db_ratio(0.0, 0.0), 0.0)
        self.assertAlmostEqual(rfscan.db_ratio(1000.0, 1.0), 30.0, places=6)

    def test_no_weighting_means_no_recommendation(self):
        scores = {c: 0.0 for c in rfscan.CHANNELS_2GHZ}
        result = rfscan.recommend(scores, [1, 6, 11], 6, False)
        self.assertIsNone(result["best_channel"])
        self.assertFalse(result["worth_changing"])
        self.assertIn("signal strength", result["reason"])

    def test_completely_clear_target_reports_no_fabricated_db(self):
        scores = {c: 0.0 for c in rfscan.CHANNELS_2GHZ}
        scores[6] = 4.0
        result = rfscan.recommend(scores, [1, 6, 11], 6, True)
        self.assertTrue(result["worth_changing"])
        # No finite dB figure exists against a zero denominator. None is the
        # honest answer; a made-up large number is not.
        self.assertIsNone(result["improvement_db"])

    def test_not_associated_yields_a_suggestion_but_no_comparison(self):
        scores = {1: 1.0, 6: 5.0, 11: 9.0}
        scores.update({c: 0.0 for c in rfscan.CHANNELS_2GHZ if c not in scores})
        result = rfscan.recommend(scores, [1, 6, 11], None, True)
        self.assertEqual(result["best_channel"], 1)
        self.assertFalse(result["worth_changing"])
        self.assertIn("not associated", result["reason"])


class TestExitCodes(unittest.TestCase):
    """Exit 1 means, and only means, "a change is worth making".

    A cold scan cache must NOT exit the same as a genuinely congested band.
    That conflation is the thing these pin against, and it is why no-data
    cases resolve to 2 (could not determine) rather than 1."""

    def setUp(self):
        self.saved = (rfscan.run, rfscan.wireless_interfaces, rfscan.sys.platform)
        rfscan.sys.platform = "linux"
        rfscan.wireless_interfaces = lambda: [
            {"name": "wlan0", "detected_via": "phy80211", "operstate": "up", "up": True}
        ]
        if not hasattr(rfscan.os, "geteuid"):
            rfscan.os.geteuid = lambda: 1000

    def tearDown(self):
        rfscan.run, rfscan.wireless_interfaces, rfscan.sys.platform = self.saved

    def build(self, table, **overrides):
        def fake(cmd, timeout=20):
            joined = " ".join(cmd)
            for prefix, (rc, out) in table.items():
                if joined.startswith(prefix):
                    return rc, out, None
            return None, "", "unavailable"

        rfscan.run = fake
        args = _Args(**overrides)
        return rfscan.build_result(args)

    def test_empty_cache_is_could_not_determine_not_congestion(self):
        result = self.build(
            {"iw reg get": (0, fixture("iw-reg-us.txt")), "iw dev wlan0 scan dump": (0, "")}
        )
        self.assertEqual(result["error"], "empty-scan-cache")
        self.assertEqual(result["exit_code"], rfscan.COULD_NOT_DETERMINE)
        self.assertNotEqual(result["exit_code"], rfscan.ACTION_WORTHWHILE)

    def test_no_data_source_is_could_not_determine(self):
        result = self.build({"iw reg get": (0, fixture("iw-reg-us.txt"))})
        self.assertEqual(result["error"], "no-data")
        self.assertEqual(result["exit_code"], rfscan.COULD_NOT_DETERMINE)

    def test_no_wireless_interface_is_could_not_determine(self):
        rfscan.wireless_interfaces = lambda: []
        result = self.build({"iw reg get": (0, fixture("iw-reg-us.txt"))})
        self.assertEqual(result["exit_code"], rfscan.COULD_NOT_DETERMINE)

    def test_congestion_is_the_only_thing_that_exits_one(self):
        result = self.build(
            {
                "iw reg get": (0, fixture("iw-reg-us.txt")),
                "iw dev wlan0 scan dump": (0, fixture("iw-scan-messy.txt")),
                "iw dev wlan0 link": (0, fixture("iw-link-connected.txt")),
            }
        )
        self.assertIsNone(result["error"])
        self.assertTrue(result["recommendation"]["worth_changing"])
        self.assertEqual(result["exit_code"], rfscan.ACTION_WORTHWHILE)

    def test_unrankable_data_is_could_not_determine_not_a_clean_bill(self):
        # nmcli reports a quality percentage, so no ranking is possible. Exiting
        # 0 would assert "no move is worth making", which was never determined.
        result = self.build(
            {
                "iw reg get": (0, fixture("iw-reg-de.txt")),
                "nmcli": (0, fixture("nmcli-list.txt")),
            }
        )
        self.assertFalse(result["weighting_available"])
        self.assertIsNone(result["recommendation"]["best_channel"])
        self.assertEqual(result["exit_code"], rfscan.COULD_NOT_DETERMINE)

    def test_not_associated_is_could_not_determine(self):
        scan = (
            "BSS 00:11:22:33:44:aa(on wlan0)\n"
            "\tfreq: 2437\n"
            "\tsignal: -50.00 dBm\n"
            "\tSSID: Someone\n"
        )
        result = self.build(
            {
                "iw reg get": (0, fixture("iw-reg-us.txt")),
                "iw dev wlan0 scan dump": (0, scan),
                "iw dev wlan0 link": (0, "Not connected.\n"),
            }
        )
        self.assertIsNone(result["recommendation"]["current_channel"])
        self.assertEqual(result["exit_code"], rfscan.COULD_NOT_DETERMINE)

    def test_clean_band_exits_zero(self):
        # Associated on channel 1 with nothing else on the band: no move to make.
        scan = (
            "BSS 00:11:22:33:44:01(on wlan0) -- associated\n"
            "\tfreq: 2412\n"
            "\tsignal: -40.00 dBm\n"
            "\tSSID: Only\n"
        )
        link = "Connected to 00:11:22:33:44:01 (on wlan0)\n\tSSID: Only\n\tfreq: 2412\n"
        result = self.build(
            {
                "iw reg get": (0, fixture("iw-reg-us.txt")),
                "iw dev wlan0 scan dump": (0, scan),
                "iw dev wlan0 link": (0, link),
            }
        )
        self.assertFalse(result["recommendation"]["worth_changing"])
        self.assertEqual(result["exit_code"], rfscan.NO_ACTION_NEEDED)


class _Args:
    def __init__(self, iface=None, active=False, json=False, no_color=True, band="2.4"):
        self.iface = iface
        self.active = active
        self.json = json
        self.no_color = no_color
        self.band = band


class TestNmcli(unittest.TestCase):
    def setUp(self):
        self.networks, self.skipped = rfscan.parse_nmcli(fixture("nmcli-list.txt"))
        self.found = by_bssid(self.networks)

    def test_counts(self):
        self.assertEqual(len(self.networks), 5)
        self.assertEqual(self.skipped, 1)

    def test_escaped_colons_in_bssid(self):
        self.assertIn("00:11:22:33:44:01", self.found)

    def test_escaped_colons_in_ssid(self):
        bss = self.found["00:11:22:33:44:04"]
        self.assertEqual(bss["ssid"], "Net:With:Colons")

    def test_quality_is_never_presented_as_dbm(self):
        # nmcli's SIGNAL is a 0-100 quality percentage. Storing it as dBm would
        # silently fabricate power figures for the whole weighting model.
        for bss in self.networks:
            self.assertIsNone(bss["signal_dbm"])
        self.assertEqual(self.found["00:11:22:33:44:01"]["signal_quality"], 88)

    def test_hidden_network(self):
        bss = self.found["00:11:22:33:44:02"]
        self.assertTrue(bss["hidden"])
        self.assertEqual(bss["channel"], 1)

    def test_band_detection(self):
        self.assertEqual(self.found["00:11:22:33:44:07"]["band"], "5")


class TestLink(unittest.TestCase):
    def test_connected(self):
        link = rfscan.parse_iw_link(fixture("iw-link-connected.txt"))
        self.assertEqual(link["bssid"], "00:11:22:33:44:01")
        self.assertEqual(link["ssid"], "HomeNet")
        self.assertEqual(link["channel"], 6)

    def test_not_connected(self):
        self.assertIsNone(rfscan.parse_iw_link("Not connected.\n"))
        self.assertIsNone(rfscan.parse_iw_link(""))


class _FakeStdout:
    """Stands in for a console with a specific encoding. Writes are delegated
    to the real stream so a failure inside the patch window still reports."""

    def __init__(self, encoding, real):
        self.encoding = encoding
        self._real = real

    def write(self, text):
        return self._real.write(text)

    def flush(self):
        return self._real.flush()

    def isatty(self):
        return False


class TestEncodingSafety(unittest.TestCase):
    """An SSID is arbitrary bytes chosen by a stranger and the console may be
    POSIX/ASCII. Dying on a neighbour's network name is not acceptable."""

    def setUp(self):
        self.real = sys.stdout

    def tearDown(self):
        sys.stdout = self.real

    def test_ascii_console_escapes_rather_than_crashing(self):
        sys.stdout = _FakeStdout("ascii", self.real)
        self.assertEqual(rfscan.safe_text("日本語"), "\\u65e5\\u672c\\u8a9e")
        self.assertEqual(rfscan.rule_char(), "-")

    def test_utf8_console_is_left_alone(self):
        sys.stdout = _FakeStdout("utf-8", self.real)
        self.assertEqual(rfscan.safe_text("日本語"), "日本語")
        self.assertEqual(rfscan.rule_char(), "─")

    def test_unknown_encoding_does_not_raise(self):
        sys.stdout = _FakeStdout("not-a-real-codec", self.real)
        self.assertIsInstance(rfscan.safe_text("日本語"), str)
        self.assertEqual(rfscan.rule_char(), "-")


class TestFiveGhz(unittest.TestCase):
    def test_summary_counts_and_loudest(self):
        networks = [
            {"band": "5", "channel": 36, "signal_dbm": -50.0},
            {"band": "5", "channel": 36, "signal_dbm": -70.0},
            {"band": "5", "channel": 149, "signal_dbm": None},
            {"band": "2.4", "channel": 6, "signal_dbm": -40.0},
        ]
        rows = rfscan.occupancy_5ghz(networks)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["channel"], 36)
        self.assertEqual(rows[0]["ap_count"], 2)
        self.assertEqual(rows[0]["loudest_dbm"], -50.0)
        self.assertIsNone(rows[1]["loudest_dbm"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
