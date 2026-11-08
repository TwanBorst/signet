import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from release import main, semver, validate


class ReleaseTests(unittest.TestCase):
    def test_stable_semver(self):
        self.assertEqual(semver("v0.1.0"), (0, 1, 0))
        for tag in ("1.2.3", "v01.2.3", "v1.02.3", "v1.2.03",
                    "v1.2", "v1.2.3-rc.1", "v1.2.3+build", "v1.2.3\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                semver(tag)

    def test_first_release_and_retry(self):
        self.assertEqual(validate("v0.1.0", [], True, True), "0.1.0")
        self.assertEqual(validate("v0.1.0", ["v0.1.0"], True, True), "0.1.0")

    def test_forward_only(self):
        tags = ["v0.1.9", "v0.2.0", "v0.2.1", "v0.2.10", "unrelated"]
        for tag in ("v0.1.10", "v0.2.2", "v0.2.9"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate(tag, tags, True, True)
        for tag in ("v0.2.11", "v0.3.0", "v1.0.0"):
            with self.subTest(tag=tag):
                self.assertEqual(validate(tag, tags, True, True), tag[1:])

    def test_requires_verified_main(self):
        for on_main, verified in ((False, True), (True, False), (False, False)):
            with self.subTest(on_main=on_main, verified=verified), self.assertRaises(ValueError):
                validate("v0.1.0", [], on_main, verified)

    def test_release_outputs_and_existing_release_gate(self):
        sha = "a" * 40
        runs = {"workflow_runs": [{
            "head_sha": sha, "head_branch": "main",
            "event": "push", "conclusion": "success",
        }]}
        for published in (False, True):
            with self.subTest(published=published), tempfile.TemporaryDirectory() as directory:
                output = os.path.join(directory, "outputs")
                env = {
                    "GITHUB_REF_NAME": "v0.2.0",
                    "GITHUB_REPOSITORY": "TwanBorst/signet",
                    "GITHUB_OUTPUT": output,
                }
                releases = [[{"tag_name": "v0.2.0"}]] if published else [[]]
                responses = [sha, json.dumps(runs), "v0.1.0\nv0.2.0", json.dumps(releases)]
                with patch.dict(os.environ, env), patch("release.command", side_effect=responses), \
                        patch("release.subprocess.run", return_value=SimpleNamespace(returncode=0)):
                    if published:
                        with self.assertRaises(ValueError):
                            main()
                        self.assertFalse(os.path.exists(output))
                    else:
                        main()
                        with open(output, encoding="utf-8") as result:
                            self.assertEqual(result.read(),
                                             f"version=0.2.0\nsha={sha}\nimage=ghcr.io/twanborst/signet\n")


if __name__ == "__main__":
    unittest.main()
