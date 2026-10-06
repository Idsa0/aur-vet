import json
import unittest
from unittest import mock

from aurvet import lists as L
from aurvet.http import HttpError

CAMPAIGNS = {
    "campaigns": [
        {
            "id": "camp1",
            "display": "Campaign 1 (test)",
            "lists": ["data/c/camp1/packages.txt"],
            "npm_lists": ["data/c/camp1/npm.txt"],
            "refresh_url": "https://md.example/live",
        },
        {
            "id": "camp2",
            "display": "Campaign 2",
            "lists": ["data/c/camp2/packages.txt"],
        },
    ]
}

FILES = {
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
    "/data/campaigns.json": json.dumps(CAMPAIGNS).encode(),
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
    "/data/c/camp1/packages.txt": b"# comment\npkgA\n\npkgB\n",
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
    "/data/c/camp1/npm.txt": b"evil-npm\n",
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
    "/data/c/camp2/packages.txt": b"pkgD\n",
    "https://md.example/live": b"pkgC\npkgE\n",
}


class FetchStub:
    def __init__(self, files):
        self.files = files
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        if url in self.files:
            return self.files[url]
        raise HttpError(f"404 for {url}")


class ListsTests(unittest.TestCase):
    def test_load_full(self):
        stub = FetchStub(FILES)
        with mock.patch.object(L, "fetch", stub):
            bad = L.load(refresh=True)
        self.assertFalse(bad.degraded)
        self.assertEqual(len(bad.campaigns), 2)
        c1 = bad.campaigns[0]
        self.assertEqual(c1.id, "camp1")
        # repo list + live refresh list unioned
        self.assertTrue({"pkgA", "pkgB", "pkgC", "pkgE"} <= c1.packages)
        self.assertIn("evil-npm", c1.npm_packages)
        self.assertEqual(bad.find("pkgA"), ["Campaign 1 (test)"])
        self.assertEqual(bad.find("pkgC"), ["Campaign 1 (test)"])
        self.assertEqual(bad.find("pkgD"), ["Campaign 2"])
        self.assertEqual(bad.find("pkgX"), [])
        self.assertEqual(bad.find("PKGa"), ["Campaign 1 (test)"])  # case-insensitive
        self.assertEqual(bad.find_npm("evil-npm"), ["Campaign 1 (test)"])
        self.assertEqual(bad.find_npm("other-npm"), [])
        self.assertIn("evil-npm", bad.all_npm_names())

    def test_partial_failure_degrades(self):
        stub = FetchStub({k: v for k, v in FILES.items()
                          if "campaigns.json" in k or "camp2/packages" in k})
        with mock.patch.object(L, "fetch", stub):
            bad = L.load(refresh=True)
        self.assertTrue(bad.degraded)
        # camp2 list loaded, camp1 did not
        self.assertEqual(bad.find("pkgD"), ["Campaign 2"])
        self.assertEqual(bad.find("pkgA"), [])

    def test_total_failure_empty(self):
        stub = FetchStub({})
        with mock.patch.object(L, "fetch", stub):
            bad = L.load(refresh=True)
        self.assertTrue(bad.degraded)
        self.assertEqual(bad.campaigns, [])
        self.assertEqual(bad.find("anything"), [])


class MalformedUpstreamTests(unittest.TestCase):
    """A compromised or broken upstream index must degrade, never crash."""

    def _load_with(self, payload):
        if isinstance(payload, str):
            stub = FetchStub({L.CAMPAIGNS_URL: payload.encode()})
        else:
            stub = FetchStub({L.CAMPAIGNS_URL: json.dumps(payload).encode()})
        with mock.patch.object(L, "fetch", stub):
            return L.load(refresh=True)

    def test_invalid_json(self):
        bad = self._load_with("{not json")
        self.assertTrue(bad.degraded)
        self.assertEqual(bad.campaigns, [])

    def test_campaigns_not_a_list(self):
        bad = self._load_with({"campaigns": {"id": "x"}})
        self.assertTrue(bad.degraded)
        self.assertEqual(bad.campaigns, [])

    def test_top_level_not_a_dict(self):
        bad = self._load_with([1, 2, 3])
        self.assertTrue(bad.degraded)

    def test_entry_not_a_dict(self):
        bad = self._load_with({"campaigns": ["just-a-string", 42,
                                             {"id": "ok", "display": "ok"}]})
        ids = [c.id for c in bad.campaigns]
        self.assertEqual(ids, ["ok"])

    def test_list_field_wrong_types(self):
        payload = {"campaigns": [{
            "id": "c", "display": "C",
            "lists": "data/x/packages.txt",   # string, not list
            "npm_lists": 42,                  # number, not list
            "refresh_url": 7,                 # number, not string
        }]}
        stub = FetchStub({L.CAMPAIGNS_URL: json.dumps(payload).encode()})
        with mock.patch.object(L, "fetch", stub):
            bad = L.load(refresh=True)
        # nothing loadable, but no crash
        self.assertEqual(len(bad.campaigns), 1)
        self.assertEqual(bad.campaigns[0].packages, set())
        self.assertIsNone(bad.campaigns[0].refresh_url)


if __name__ == "__main__":
    unittest.main()
