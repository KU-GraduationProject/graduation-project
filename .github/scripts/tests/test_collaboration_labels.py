import copy
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collaboration_labels as labels


def issue():
    return {"number": 25, "title": "[ci] 협업 설정", "state": "open", "type": None,
            "labels": [], "assignees": []}


def pr():
    return {"state": "open", "draft": False, "merged": False, "changed_files": 2,
            "user": {"type": "User", "login": "author"}}


class FakeAPI:
    def __init__(self):
        self.item = issue()
        self.pr = pr()
        self.files = [{"filename": ".github/workflows/test.yml"}, {"filename": "docs/dev-rules.md"}]
        self.permission = "write"
        self.calls = []

    def __call__(self, path, method="GET", data=None):
        self.calls.append((path, method, data))
        if method == "POST" and path.endswith("/labels"):
            current = {x["name"] for x in self.item["labels"]}
            self.item["labels"].extend({"name": name} for name in data["labels"] if name not in current)
        elif method == "DELETE":
            removed = urllib.parse.unquote(path.rsplit("/", 1)[1])
            self.item["labels"] = [x for x in self.item["labels"] if x["name"] != removed]
        elif method == "POST" and path.endswith("/assignees"):
            self.item["assignees"] = [{"login": name} for name in data["assignees"]]
        elif method == "PATCH":
            self.item["type"] = {"name": data["type"]}
        elif path.endswith("/issues/25"):
            return copy.deepcopy(self.item)
        elif path.endswith("/pulls/25"):
            return copy.deepcopy(self.pr)
        elif "/files?" in path:
            return self.files
        elif path.endswith("/issue-types"):
            return [{"name": kind} for kind in ("Task", "Bug", "Feature")]
        elif path.endswith("/permission"):
            if self.permission == "missing":
                raise urllib.error.HTTPError(path, 404, "Not found", {}, None)
            return {"permission": self.permission}
        return {}

    def writes(self):
        return [call for call in self.calls if call[1] != "GET"]


class LabelTests(unittest.TestCase):
    def test_catalog_is_unique_and_covers_all_types_and_areas(self):
        names = [x["name"] for x in labels.CATALOG]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(set(labels.AREA_PATHS).issubset(names))
        for kind in ("feat", "fix", "docs", "test", "refactor", "chore", "ci"):
            self.assertIn("type:" + kind, names)
        for label in labels.CATALOG:
            self.assertRegex(label["color"], r"^[0-9A-Fa-f]{6}$")
            self.assertTrue(label["description"])

    def test_all_title_types(self):
        for kind in ("feat", "fix", "docs", "test", "refactor", "chore", "ci"):
            item = {**issue(), "title": f"[{kind}] 실제 작업"}
            desired, managed, selected = labels.desired_labels(item)
            self.assertIn("type:" + kind, desired)
            self.assertEqual(selected, kind)
            if kind == "docs":
                self.assertIn("area:docs", desired)

    def test_pr_paths_drive_multiple_areas(self):
        desired, _, _ = labels.desired_labels(issue(), pr(), [".github/workflows/ci.yml", "docs/dev-rules.md",
            "aiops/pipeline/main.py", "aiops/remediation/main.py", "docker-compose.yml"])
        self.assertTrue({"area:github", "area:docs", "area:pipeline", "area:remediation", "area:infra"}.issubset(desired))

    def test_issue_manual_areas_and_unknown_title_type_are_preserved(self):
        _, managed, _ = labels.desired_labels(issue())
        self.assertNotIn("area:infra", managed)
        _, managed, selected = labels.desired_labels({**issue(), "title": "legacy title"})
        self.assertIsNone(selected)
        self.assertNotIn("type:feat", managed)

    def test_lifecycle_status_is_not_a_human_approval(self):
        cases = [(issue(), None, "status:open"), (issue(), {**pr(), "draft": True}, "status:draft"),
                 (issue(), pr(), "status:in-review"),
                 ({**issue(), "state": "closed", "state_reason": "completed"}, None, "status:done"),
                 ({**issue(), "state": "closed", "state_reason": "not_planned"}, None, "status:closed"),
                 ({**issue(), "state": "closed"}, {**pr(), "merged": True}, "status:done"),
                 ({**issue(), "state": "closed"}, {**pr(), "state": "closed"}, "status:closed")]
        for item, pull, status in cases:
            with self.subTest(status=status):
                desired, _, _ = labels.desired_labels(item, pull)
                self.assertEqual({x for x in desired if x.startswith("status:")}, {status})

    def test_sync_preserves_custom_labels_and_removes_only_stale_managed_labels(self):
        fake = FakeAPI()
        fake.item["labels"] = [{"name": name} for name in ("documentation", "priority:high", "type:docs", "status:open", "area:infra")]
        with patch.object(labels.policy, "api", side_effect=fake):
            labels.sync("owner/repo", 25, True)
        names = {x["name"] for x in fake.item["labels"]}
        self.assertTrue({"documentation", "priority:high", "type:ci", "status:in-review", "area:github", "area:docs"}.issubset(names))
        self.assertFalse({"type:docs", "status:open", "area:infra"} & names)
        self.assertFalse(any(method == "PUT" for _, method, _ in fake.calls))

    def test_native_issue_type_mapping_and_no_automatic_issue_owner(self):
        for kind, native in (("feat", "Feature"), ("fix", "Bug"), ("docs", "Task"), ("ci", "Task")):
            fake = FakeAPI()
            fake.item["title"] = f"[{kind}] 실제 작업"
            with self.subTest(kind=kind), patch.object(labels.policy, "api", side_effect=fake):
                labels.sync("owner/repo", 25, False)
            self.assertEqual(fake.item["type"]["name"], native)
            self.assertEqual(fake.item["assignees"], [])

    def test_existing_assignee_is_not_replaced(self):
        fake = FakeAPI()
        fake.item["assignees"] = [{"login": "maintainer"}]
        with patch.object(labels.policy, "api", side_effect=fake):
            labels.sync("owner/repo", 25, True)
        self.assertEqual(fake.item["assignees"], [{"login": "maintainer"}])
        self.assertFalse(any(path.endswith("/permission") for path, _, _ in fake.calls))

    def test_external_contributors_and_bots_are_not_auto_assigned(self):
        for permission, user_type in (("read", "User"), ("missing", "User"), ("write", "Bot")):
            fake = FakeAPI()
            fake.permission = permission
            fake.pr["user"]["type"] = user_type
            with self.subTest(permission=permission, user_type=user_type), patch.object(labels.policy, "api", side_effect=fake):
                labels.sync("owner/repo", 25, True)
            self.assertEqual(fake.item["assignees"], [])

    def test_missing_pr_files_fail_before_writing(self):
        fake = FakeAPI()
        fake.pr["changed_files"] = 3
        with patch.object(labels.policy, "api", side_effect=fake), self.assertRaises(ValueError):
            labels.sync("owner/repo", 25, True)
        self.assertEqual(fake.writes(), [])

    def test_repeated_sync_is_idempotent(self):
        fake = FakeAPI()
        with patch.object(labels.policy, "api", side_effect=fake):
            labels.sync("owner/repo", 25, True)
            count = len(fake.writes())
            labels.sync("owner/repo", 25, True)
        self.assertEqual(len(fake.writes()), count)

    def test_catalog_setup_does_not_modify_existing_labels(self):
        with patch.object(labels.policy, "paginated", return_value=labels.CATALOG), patch.object(labels.policy, "api") as api:
            labels.ensure_catalog("owner/repo")
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
