import unittest

from aurvet.pkgbuild import as_list, as_str, parse_pkgbuild


class ParseTests(unittest.TestCase):
    def test_scalars_and_arrays(self):
        text = """
# a comment
pkgname=foo
pkgver="1.0"
pkgrel=1
arch=(x86_64 armv7h)
license=(MIT "GPL-3.0-or-later")
url="https://example.com"
depends=('curl' 'python>=3.12')
install="foo.install"
"""
        p = parse_pkgbuild(text)
        self.assertEqual(as_str(p, "pkgname"), "foo")
        self.assertEqual(as_str(p, "pkgver"), "1.0")
        self.assertEqual(as_list(p, "arch"), ["x86_64", "armv7h"])
        self.assertEqual(as_list(p, "license"), ["MIT", "GPL-3.0-or-later"])
        self.assertEqual(as_list(p, "depends"), ["curl", "python>=3.12"])
        self.assertEqual(as_str(p, "install"), "foo.install")
        self.assertIn("url", p)

    def test_multiline_array_with_comments(self):
        text = """
source=(
  "foo-1.tar.gz::https://example.com/foo-1.tar.gz"
  "patch::https://example.com/f.patch"  # trailing comment
)
sha256sums=(
  'aaaa'
  'bbbb'   # comment
)
"""
        p = parse_pkgbuild(text)
        self.assertEqual(as_list(p, "source"),
                         ["foo-1.tar.gz::https://example.com/foo-1.tar.gz",
                          "patch::https://example.com/f.patch"])
        self.assertEqual(as_list(p, "sha256sums"), ["aaaa", "bbbb"])

    def test_url_with_fragment(self):
        text = 'url="https://example.com/a#frag"\n'
        p = parse_pkgbuild(text)
        self.assertEqual(as_str(p, "url"), "https://example.com/a#frag")

    def test_function_body_tolerated(self):
        text = """
pkgver() {
  local v
  v=9.9
  echo $v
}
pkgname=bar
depends=('git')
"""
        p = parse_pkgbuild(text)
        self.assertEqual(as_str(p, "pkgname"), "bar")
        self.assertEqual(as_list(p, "depends"), ["git"])

    def test_hash_inside_array_string(self):
        text = "source=('https://example.com/a.tar#sha256=abcdef')\n"
        p = parse_pkgbuild(text)
        self.assertEqual(as_list(p, "source"), ["https://example.com/a.tar#sha256=abcdef"])


if __name__ == "__main__":
    unittest.main()
