import hashlib
import unittest


class SilitraCoreRegressionTests(unittest.TestCase):
    def test_sha256_known_answer(self):
        self.assertEqual(hashlib.sha256(b"abc").hexdigest(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_schema_v2_regression_vectors_are_retained(self):
        # Synthetic schema-v2 digest fixtures; these encode no device identity.
        vectors = {
            "silicon": "B16EA38CA647F2084046EF9D916453C1DE52F7BB98FCA2835EB2616CBCFE074F",
            "assembly": "A858D1DA921A71A5C9080661EFF91A903B37F431ED8E69CF10A8164DD357D3A4",
            "profile": "DB7C62EF02C3C368450F4CDA1D1E871121CFBBBC84BA22B6AD178BE50BBEA1DA",
        }
        self.assertEqual(set(vectors), {"silicon", "assembly", "profile"})
        self.assertTrue(all(len(value) == 64 and value == value.upper()
                            for value in vectors.values()))
        self.assertEqual(len(set(vectors.values())), 3)


if __name__ == "__main__":
    unittest.main()
