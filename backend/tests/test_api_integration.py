import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from backend import main


class APITests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)

    def test_analyze_snippet_ok(self):
        with patch("backend.main.run_all_scans_on_path", return_value={"bandit": {"success": True}}), patch(
            "backend.main.detect_code_string", return_value={"matches": []}
        ):
            resp = self.client.post("/analyze", json={"language": "python", "code": "print('hi')"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("scanners", body)
        self.assertIn("bandit", body["scanners"])

    def test_analyze_fast_ok(self):
        with patch(
            "backend.main.analyze_python_code_with_bandit", return_value={"success": True, "issues": []}
        ), patch("backend.main.detect_code_string", return_value={"matches": []}):
            resp = self.client.post("/analyze-fast", json={"language": "python", "code": "a=1"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("bandit", resp.json()["scanners"])

    def test_analyze_github_ok(self):
        tmpdir = tempfile.mkdtemp(prefix="repo_fake_")
        fake_repo = Path(tmpdir)
        with patch("backend.main.download_repo_zip", return_value=fake_repo), patch(
            "backend.main.run_all_scans_on_path", return_value={"semgrep": {"success": True}}
        ), patch("backend.main.requests.get") as mock_get:
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"default_branch": "dev"}
            mock_get.return_value = m
            resp = self.client.post("/analyze-github", json={"url": "https://github.com/org/repo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("repo", body)
        self.assertIn("scanners", body)
        self.assertIn("semgrep", body["scanners"])


if __name__ == "__main__":
    unittest.main()
