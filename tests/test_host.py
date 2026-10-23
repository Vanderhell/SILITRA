import unittest

from host.fp1 import make_frame, parse_frame


class FP1Tests(unittest.TestCase):
    def test_frame_round_trip(self):
        encoded = make_frame("req-1", "swid_profile", "payload|with|separators")
        decoded = parse_frame(encoded.decode("ascii"))
        self.assertEqual(decoded, {"request_id": "req-1", "kind": "swid_profile",
                                   "payload": "payload|with|separators"})

    def test_invalid_crc_and_length_are_rejected(self):
        valid = make_frame("req-2", "ping", "").decode("ascii")
        self.assertIsNone(parse_frame(valid[:-3] + "00\n"))
        self.assertIsNone(parse_frame("FP1|req-2|ping|2|x|00000000\n"))

    def test_non_fp1_input_is_ignored(self):
        self.assertIsNone(parse_frame("ordinary boot log\n"))


if __name__ == "__main__":
    unittest.main()
