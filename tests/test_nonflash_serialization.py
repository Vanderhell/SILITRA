import copy
import json
import unittest

from host.swid_nonflash import (fingerprint, parse_safe_efuse_summary, parse_tlv,
                                select_backend, serialize_v2, validate_ram_fingerprints)


def sample_manifest():
    return {
        "chip": {"family": 32, "model": 3, "revision": 2, "cores": 2,
                 "package": 1, "features": 0x1234},
        "identity": {"mac": "02:00:00:00:00:01", "mac_valid": True,
                     "optional_uid": "00112233445566778899AABBCCDDEEFF",
                     "optional_uid_valid": True},
        "memory": {"flash_jedec": 0x204018, "flash_capacity_bytes": 16 * 1024 * 1024,
                   "psram_capacity_bytes": 8 * 1024 * 1024, "psram_present": True,
                   "psram_interface": 2, "psram_location": 1,
                   "flash_unique_id": "0123456789ABCDEF", "flash_unique_id_valid": True},
        "radio": {"wifi_supported": 1, "wifi_generation": 4, "bluetooth_supported": 1,
                  "ble_supported": 1, "bt_classic_supported": 0},
        "peripherals": [{"type": kind, "supported": int(kind % 3 != 0),
                         "controllers": kind % 4, "channels": kind * 2,
                         "status": 1, "evidence": 1, "feature_flags": kind * 17}
                        for kind in range(34)],
    }


class NonFlashSerializationTests(unittest.TestCase):
    def test_schema_v2_known_answers(self):
        manifest = sample_manifest()
        expected = {
            "silicon": "B16EA38CA647F2084046EF9D916453C1DE52F7BB98FCA2835EB2616CBCFE074F",
            "assembly": "A858D1DA921A71A5C9080661EFF91A903B37F431ED8E69CF10A8164DD357D3A4",
            "profile": "DB7C62EF02C3C368450F4CDA1D1E871121CFBBBC84BA22B6AD178BE50BBEA1DA",
        }
        for kind, digest in expected.items():
            _, actual = fingerprint(manifest, kind)
            self.assertEqual(actual, digest, kind)

    def test_missing_identity_values_are_empty_not_substituted(self):
        manifest = sample_manifest()
        manifest["identity"].update(mac_valid=False, optional_uid_valid=False)
        encoded = serialize_v2(manifest, "silicon")
        self.assertIn(bytes((20, 0, 0)), encoded)
        self.assertIn(bytes((21, 0, 0)), encoded)

    def test_peripheral_enumeration_order_does_not_change_profile(self):
        manifest = sample_manifest()
        changed = copy.deepcopy(manifest)
        changed["peripherals"].reverse()
        self.assertEqual(serialize_v2(manifest, "profile"), serialize_v2(changed, "profile"))

    def test_memory_change_affects_assembly_but_not_silicon(self):
        manifest = sample_manifest()
        changed = copy.deepcopy(manifest)
        changed["memory"].update(flash_unique_id="0000000000000001", flash_unique_id_valid=True)
        self.assertEqual(serialize_v2(manifest, "silicon"), serialize_v2(changed, "silicon"))
        self.assertNotEqual(serialize_v2(manifest, "assembly"), serialize_v2(changed, "assembly"))

    def test_capability_change_affects_profile_only(self):
        manifest = sample_manifest()
        changed = copy.deepcopy(manifest)
        changed["peripherals"][0]["supported"] ^= 1
        self.assertEqual(serialize_v2(manifest, "silicon"), serialize_v2(changed, "silicon"))
        self.assertEqual(serialize_v2(manifest, "assembly"), serialize_v2(changed, "assembly"))
        self.assertNotEqual(serialize_v2(manifest, "profile"), serialize_v2(changed, "profile"))

    def test_efuse_parser_drops_raw_words_and_key_payloads(self):
        source = {"MAC": {"name": "MAC", "value": "aa:bb:cc:dd:ee:ff", "raw_value": "0xdeadbeef"},
                  "KEY_PURPOSE_0": {"name": "KEY_PURPOSE_0", "value": "USER", "raw_value": "0x1"},
                  "BLOCK_KEY0": {"name": "BLOCK_KEY0", "value": "SYNTHETIC_SENTINEL",
                                 "raw_value": "0xDEADBEEF"}}
        parsed = parse_safe_efuse_summary(json.dumps(source))
        self.assertEqual(parsed["MAC"]["value"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["KEY_PURPOSE_0"]["value"], "USER")
        self.assertNotIn("raw_value", parsed["MAC"])
        self.assertNotIn("BLOCK_KEY0", parsed)

    def test_incomplete_manifest_and_truncated_tlv_are_rejected(self):
        with self.assertRaises(RuntimeError):
            validate_ram_fingerprints([{"type": "chip", "model": 1}])
        with self.assertRaises(ValueError):
            parse_tlv(bytes((50, 2, 0, 0xAA)))

    def test_tlv_parser_preserves_repeat_fields(self):
        encoded = bytes((50, 2, 0, 0xAA, 0xBB, 50, 1, 0, 0xCC))
        self.assertEqual(parse_tlv(encoded), [(50, b"\xAA\xBB"), (50, b"\xCC")])

    def test_backend_selection_does_not_default_to_flash(self):
        self.assertEqual(select_backend("auto", "ESP32-S3"), "ram-only")
        self.assertEqual(select_backend("auto", "ESP32-C3"), "ram-only")
        self.assertEqual(select_backend("auto", "ESP32-C6"), "rom-only")
        self.assertEqual(select_backend("flash", "ESP32-S3"), "flash")
        self.assertEqual(select_backend("rom-only", "ESP32-S3"), "rom-only")


if __name__ == "__main__":
    unittest.main()
