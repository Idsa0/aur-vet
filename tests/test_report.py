import unittest

from aurvet.report import PkgReport, Verdict, render_text, scrub
from aurvet.rules import Finding, Severity


class ScrubTests(unittest.TestCase):
    def test_csi_stripped(self):
        self.assertEqual(scrub("a\x1b[2Jb"), "ab")
        self.assertEqual(scrub("\x1b[31mred\x1b[0m"), "red")

    def test_osc_stripped(self):
        self.assertEqual(scrub("a\x1b]0;title\x07b"), "ab")
        self.assertEqual(scrub("a\x1b]8;;https://x\x1b\\b"), "ab")

    def test_other_escapes_and_ctrl_stripped(self):
        self.assertEqual(scrub("a\x1b(Bb"), "ab")
        self.assertEqual(scrub("a\x00b\x07c\x1bd"), "abc")

    def test_plain_text_kept(self):
        s = "hello - world\nnew line\ttab"
        self.assertEqual(scrub(s), s)

    def test_rendered_report_has_no_escaping(self):
        # payloads go into every field the renderer actually prints
        r = PkgReport(name="x\x1b[2Jpkg", verdict=Verdict.REVIEW,
                      info={"Maintainer": "g", "Version": "1-1", "NumVotes": 3})
        r.findings.append(Finding(
            "root-acts", Severity.WARN,
            "write to /etc/: 'echo x > /etc\x1b[K/y\x1b]0;fake\x07'"))
        out = render_text([r], ["note: \x1b[2Jclear"], color=False)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x00", out)
        self.assertIn("xpkg", out)
        self.assertIn("/etc/y'", out)
        self.assertIn("clear", out)


if __name__ == "__main__":
    unittest.main()
