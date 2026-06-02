"""Unit tests for the pure routing / Sechord logic.

These run without any sockets and pin down the security-critical behaviour,
including the exact numbers from the report's Figure 12.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chordp2p import routing  # noqa: E402


class TestInterval(unittest.TestCase):
    def test_simple(self):
        self.assertTrue(routing.in_interval(5, 1, 10))
        self.assertFalse(routing.in_interval(10, 1, 10))
        self.assertTrue(routing.in_interval(10, 1, 10, inclusive_end=True))

    def test_wraparound(self):
        # arc from 200 clockwise to 10 (mod 256) contains 250 and 5, not 100
        self.assertTrue(routing.in_interval(250, 200, 10))
        self.assertTrue(routing.in_interval(5, 200, 10))
        self.assertFalse(routing.in_interval(100, 200, 10))

    def test_full_circle(self):
        self.assertTrue(routing.in_interval(123, 50, 50))


class TestSechord(unittest.TestCase):
    def test_threshold_matches_report(self):
        # Report Figure 12: mean 32.0, threshold ~94.547
        self.assertAlmostEqual(routing.hop_threshold(97), 94.54748196370498, places=6)

    def test_trap_is_implausible(self):
        # Misrouting node 97 -> trap id 64 must be flagged.
        self.assertFalse(routing.is_plausible_hop(97, 64))

    def test_legit_finger_is_plausible(self):
        self.assertTrue(routing.is_plausible_hop(97, 58))

    def test_valid_hop_requires_progress_and_plausibility(self):
        # 64 makes ring "progress" toward 90 (wraps) but is implausible -> invalid
        self.assertFalse(routing.is_valid_hop(97, 64, 90))
        # 58 both progresses and is plausible -> valid
        self.assertTrue(routing.is_valid_hop(97, 58, 90))

    def test_hash_within_id_space(self):
        for s in ("10.16.9.1:5000", "file.bin", "x"):
            self.assertTrue(0 <= routing.hash_key(s) < 256)

    def test_closest_preceding(self):
        fingers = [148, 148, 148, 148, 148, 148, 58, 58]
        self.assertEqual(routing.closest_preceding(97, 90, fingers), 58)


if __name__ == "__main__":
    unittest.main(verbosity=2)
