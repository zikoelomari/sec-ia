import unittest

from backend import main


class ScannerSelectionTests(unittest.TestCase):
    def test_normalize_valid_scanners(self):
        res = main._normalize_and_validate_scanners(["bandit", "semgrep"], None)
        self.assertEqual(res, ["bandit", "semgrep"])

    def test_normalize_invalid_scanners(self):
        with self.assertRaises(main.HTTPException):
            main._normalize_and_validate_scanners(["oops"], None)

    def test_normalize_empty(self):
        res = main._normalize_and_validate_scanners(None, None)
        self.assertEqual(res, [])


class GithubUrlTests(unittest.TestCase):
    def test_parse_github_url_with_branch(self):
        owner, repo, branch = main.parse_github_url("https://github.com/foo/bar/tree/dev")
        self.assertEqual(owner, "foo")
        self.assertEqual(repo, "bar")
        self.assertEqual(branch, "dev")

    def test_parse_github_url_without_branch(self):
        owner, repo, branch = main.parse_github_url("https://github.com/foo/bar")
        self.assertEqual((owner, repo), ("foo", "bar"))
        self.assertIsNone(branch)

    def test_parse_github_url_invalid(self):
        with self.assertRaises(main.HTTPException):
            main.parse_github_url("https://github.com/foo")


if __name__ == "__main__":
    unittest.main()
