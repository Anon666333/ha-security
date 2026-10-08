"""Protect immutable release tags and version consistency without network writes."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ha_security_release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = "a" * 40


class ReleaseTests(unittest.TestCase):
    def api(self, values):
        return Mock(side_effect=lambda path, payload=None: values.get(path) if payload is None else {"ok": True})

    def test_first_release_tags_tested_commit_and_uses_notes(self):
        api = self.api({})
        release.publish("0.1.10", "Update notes", "owner/repo", SHA, api)
        writes = [(call.args[0], call.args[1]) for call in api.call_args_list if len(call.args) == 2]
        self.assertEqual(writes[0], ("git/refs", {"ref": "refs/tags/v0.1.10", "sha": SHA}))
        self.assertEqual(writes[1][1]["tag_name"], "v0.1.10")
        self.assertEqual(writes[1][1]["body"], "Update notes")
        self.assertFalse(writes[1][1]["draft"])

    def test_existing_release_is_not_rewritten(self):
        api = self.api({"releases/tags/v0.1.10": {"draft": False, "prerelease": False}})
        release.publish("0.1.10", "New notes", "owner/repo", SHA, api)
        self.assertEqual(len(api.call_args_list), 1)

    def test_downgrades_and_existing_drafts_require_review(self):
        for values in ({"releases/latest": {"tag_name": "v0.2.0"}},
                       {"releases/tags/v0.1.10": {"draft": True}}):
            api = self.api(values)
            with self.assertRaises(ValueError):
                release.publish("0.1.10", "notes", "owner/repo", SHA, api)
            self.assertTrue(all(len(call.args) == 1 for call in api.call_args_list))

    def test_retry_existing_tag_and_refuse_moving_it(self):
        for tagged_sha in (SHA, "b" * 40):
            api = self.api({"git/ref/tags/v0.1.10": {"object": {"type": "commit", "sha": tagged_sha}}})
            if tagged_sha == SHA:
                release.publish("0.1.10", "notes", "owner/repo", SHA, api)
                self.assertEqual(api.call_args_list[-1].args[0], "releases")
            else:
                with self.assertRaisesRegex(ValueError, "never moved"):
                    release.publish("0.1.10", "notes", "owner/repo", SHA, api)
                self.assertTrue(all(len(call.args) == 1 for call in api.call_args_list))
            self.assertFalse(any(call.args[0] == "git/refs" for call in api.call_args_list))

    def test_annotated_tag_is_resolved_before_publication(self):
        api = self.api({"git/ref/tags/v0.1.10": {"object": {"type": "tag", "sha": "tag-object"}},
                        "git/tags/tag-object": {"object": {"type": "commit", "sha": SHA}}})
        release.publish("0.1.10", "notes", "owner/repo", SHA, api)
        self.assertTrue(any(call.args[0] == "git/tags/tag-object" for call in api.call_args_list))

    def test_publish_cli_rejects_feature_branch_without_api_call(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/feature/example"}), patch("sys.argv", ["release.py", "--publish"]), patch.object(release, "github_api") as api:
            with self.assertRaisesRegex(ValueError, "main-branch"):
                release.main()
            api.assert_not_called()

    def test_release_metadata_and_dashboard_version_drift(self):
        version, notes = release.validate()
        self.assertEqual(release.version_tuple(version), tuple(map(int, version.split("."))))
        self.assertTrue(notes.strip())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copytree(ROOT / "custom_components", root / "custom_components", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "dashboards", root / "dashboards")
            for name in ("README.md", "CHANGELOG.md", "hacs.json"):
                shutil.copyfile(ROOT / name, root / name)
            (root / "dashboards/security.yaml").write_text("old resource version", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "resource version"):
                release.validate(root)

    def test_stable_versions_order_numerically(self):
        self.assertGreater(release.version_tuple("0.1.10"), release.version_tuple("0.1.9"))
        for invalid in ("v0.1.10", "0.01.10", "0.1", "0.1.10-beta.1", "0.1.10\n"):
            with self.assertRaises(ValueError):
                release.version_tuple(invalid)
