import unittest
from unittest import mock

from aurvet import deps


def _graph(*args, **kw):
    nodes, all_info, truncated = deps.build_graph(*args, **kw)
    return nodes, all_info, truncated


class BareNameTests(unittest.TestCase):
    def test_version_specs(self):
        self.assertEqual(deps.bare_name("python>=3.12"), "python")
        self.assertEqual(deps.bare_name("glib<2"), "glib")
        self.assertEqual(deps.bare_name("a!b"), "a")
        # bare '=' is not a version operator
        self.assertEqual(deps.bare_name("a=b"), "a=b")
        self.assertEqual(deps.bare_name("nodejs-lts"), "nodejs-lts")
        self.assertEqual(deps.bare_name("  foo  "), "foo")


class GraphTests(unittest.TestCase):
    def make_infos(self):
        return {
            "top": {
                "Name": "top",
                "Depends": ["python>=3.12", "evilpkg", "git"],
                "MakeDepends": ["golang"],
            },
            "evilpkg": {
                "Name": "evilpkg",
                "Depends": ["otherdep", "python"],
                "MakeDepends": [],
            },
        }

    def test_graph_classifies_and_recurses(self):
        infos = self.make_infos()

        def fake_info(names):
            return {n: infos[n] for n in names if n in infos}

        official = {"python", "git", "golang"}
        with mock.patch.object(deps.AUR, "info", side_effect=fake_info):
            nodes, all_info, truncated = _graph("top", infos["top"], official)
        self.assertFalse(truncated)

        names = {n.name for n in nodes}
        self.assertEqual(names, {"evilpkg", "otherdep"})
        # evilpkg resolved via AUR; otherdep unknown (not in AUR, not official)
        by_name = {n.name: n for n in nodes}
        self.assertEqual(by_name["evilpkg"].kind, "aur")
        self.assertEqual(by_name["otherdep"].kind, "unknown")
        self.assertTrue(
            any(f["rule"] == "dep-unresolvable" for f in by_name["otherdep"].findings)
        )
        # official deps are excluded
        self.assertNotIn("python", names)
        # recursion pulled in 'otherdep' via evilpkg
        self.assertIn("otherdep", all_info or names)

    def test_cycle_safe(self):
        infos = {
            "a": {"Name": "a", "Depends": ["b", "python"]},
            "b": {"Name": "b", "Depends": ["a", "python"]},
        }

        def fake_info(names):
            return {n: infos[n] for n in names if n in infos}

        with mock.patch.object(deps.AUR, "info", side_effect=fake_info):
            nodes, _, _ = _graph("a", infos["a"], {"python"})
        self.assertEqual({n.name for n in nodes}, {"b"})

    def test_graph_truncates_at_cap(self):
        n = deps.MAX_DEPS + 50
        infos = {"top": {"Name": "top", "Depends": [f"dep{i}" for i in range(n)]}}

        def fake_info(names):
            return {}  # none resolve -> all remain graph nodes

        with mock.patch.object(deps.AUR, "info", side_effect=fake_info):
            nodes, _, truncated = _graph("top", infos["top"], set())
        self.assertTrue(truncated)
        self.assertEqual(len(nodes), deps.MAX_DEPS)


if __name__ == "__main__":
    unittest.main()
