import json
import os
import tempfile
import unittest

from aurvet import state as S


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_missing(self):
        s = S.load(self.path)
        self.assertEqual(s["packages"], {})
        self.assertEqual(s["version"], S.SCHEMA_VERSION)

    def test_roundtrip_clear_and_compare(self):
        s = S.load(self.path)
        files = {"PKGBUILD": b"pkgname=x\n", "x.install": b"post_install() {}\n"}
        S.mark_cleared(s, "x", "abc123", files, "clean", extra={"committers": ["a"]})
        S.save(self.path, s)

        with open(self.path) as f:
            self.assertIsInstance(json.load(f), dict)
        loaded = S.load(self.path)
        entry = S.get_cleared(loaded, "x")
        self.assertEqual(entry["git_sha"], "abc123")
        self.assertEqual(set(entry["files"]), {"PKGBUILD", "x.install"})
        self.assertIn("committers", entry)

        # unchanged -> no diff
        self.assertEqual(S.changed_files(entry, files), [])
        # changed file -> flagged
        changed = dict(files)
        changed["PKGBUILD"] = b"pkgname=x\nbuild() { evil; }\n"
        self.assertEqual(S.changed_files(entry, changed), ["PKGBUILD"])
        # added + removed files -> flagged
        added = dict(changed)
        added["new"] = b"hi"
        del added["x.install"]
        self.assertEqual(S.changed_files(entry, added), ["PKGBUILD", "new", "x.install"])

    def test_save_is_atomic(self):
        s = S.load(self.path)
        S.mark_cleared(s, "a", "1", {"PKGBUILD": b"x"}, "clean")
        S.save(self.path, s)
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_state_file_is_owner_only(self):
        s = S.load(self.path)
        S.mark_cleared(s, "a", "1", {"PKGBUILD": b"x"}, "clean")
        S.save(self.path, s)
        # and re-saving over a permissively-modeled pre-existing file
        os.chmod(self.path, 0o644)
        S.save(self.path, s)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
