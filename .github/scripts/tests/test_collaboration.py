import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

SCRIPT = Path(__file__).resolve().parents[1] / "collaboration.py"
ROOT = SCRIPT.parents[2]
spec = importlib.util.spec_from_file_location("collaboration", SCRIPT)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def valid_pr():
    return {"title": "[ci] 협업 검사 추가 (#12)", "head": {"ref": "ci/12-collaboration", "sha": "a" * 40},
            "base": {"ref": "main"}, "number": 30, "commits": 1,
            "body": "\n\n".join(("## 개요\n협업 규칙을 검사합니다.", "## 관련 이슈\nCloses #12",
                       "## 변경 사항\n검증 스크립트 추가", "## 테스트\npython -m unittest 실행: 10개 PASS",
                       "## 리뷰 포인트\n실패 시 병합 차단 설정 확인", "## 체크리스트\n" +
                       "\n".join("- [ ] " + item for item in policy.CHECKLIST)))}


class PolicyTests(unittest.TestCase):
    def test_valid_types_and_crlf(self):
        for kind in ("feat", "fix", "docs", "test", "refactor", "chore", "ci"):
            with self.subTest(kind=kind):
                policy.validate_message(f"[{kind}] 작업 설명 (#12)\r\n\r\n본문", issue=12)

    def test_invalid_commit_titles(self):
        for title in ("[feature] 작업 (#12)", "[feat] 작업", "[feat]  (#12)", "[feat] 작업 (#0)",
                      "feat: 작업 (#12)", "[feat] 작업 (#12) extra", "[feat] 작업 (#12)\nother",
                      "[feat]  작업 (#12)", "[feat] 작업  (#12)"):
            with self.subTest(title=title), self.assertRaises(ValueError):
                policy.title_issue(title)

    def test_wrong_issue_commit(self):
        with self.assertRaises(ValueError):
            policy.validate_message("[fix] 작업 (#13)", issue=12)

    def test_merge_requires_graph_context(self):
        policy.validate_message("Merge branch 'main' into ci/12-collaboration", merge=True)
        for message in ("Merge fabricated", 'Revert "anything"', "fixup! [ci] 작업 (#12)"):
            with self.subTest(message=message), self.assertRaises(ValueError):
                policy.validate_message(message)
        policy.validate_message("[fix] 잘못된 변경 되돌리기 (#12)")

    def test_complete_pr(self):
        self.assertEqual(policy.validate_pr(valid_pr(), "main"), 12)

    def test_all_required_sections(self):
        for heading in policy.PR_SECTIONS:
            pr = valid_pr()
            pr["body"] = pr["body"].replace("## " + heading, "## 제거된 섹션")
            with self.subTest(heading=heading), self.assertRaises(ValueError):
                policy.validate_pr(pr, "main")

    def test_comment_placeholder_and_fenced_headings(self):
        for body in ("<!-- " + valid_pr()["body"] + " -->", "```md\n" + valid_pr()["body"] + "\n```",
                     valid_pr()["body"].replace("협업 규칙을 검사합니다.", "<!-- 실제 내용 -->"),
                     valid_pr()["body"].replace("협업 규칙을 검사합니다.", "TODO")):
            with self.subTest(body=body[:30]), self.assertRaises(ValueError):
                policy.validate_pr({**valid_pr(), "body": body}, "main")

    def test_invalid_closes(self):
        for related in ("Closes #", "Closes #13", "Closes #0", "Closes #12abc", "`Closes #12`",
                        "<!-- Closes #12 -->", "```\nCloses #12\n```", "Closes #12\nCloses #13"):
            pr = valid_pr()
            pr["body"] = pr["body"].replace("Closes #12", related)
            with self.subTest(related=related), self.assertRaises(ValueError):
                policy.validate_pr(pr, "main")

    def test_extra_issue_closing_rejected(self):
        for suffix in ("\nFixes #13", "\nCloses https://github.com/other/repo/issues/13"):
            with self.assertRaises(ValueError):
                policy.validate_pr({**valid_pr(), "body": valid_pr()["body"] + suffix}, "main")

    def test_fence_closers_are_consistent_for_sections_and_links(self):
        for opener, inner, closer in (("```md", "```python", "````"),
                                      ("~~~~", "~~~", "~~~~~"),
                                      ("```", "~~~", "```"),
                                      ("```", "``` trailing text", "```")):
            with self.subTest(opener=opener, inner=inner):
                # Fake headings and closing references remain code even after an
                # info-string marker, short marker or different marker character.
                code = f"\n{opener}\n{inner}\n## 개요\nCloses #13\n{closer}\n"
                policy.validate_pr({**valid_pr(), "body": valid_pr()["body"] + code}, "main")

    def test_bad_branch_title_or_base(self):
        for branch in ("ci/13-collaboration", "ci/collaboration", "main", "feature/12-policy", "ci/12-TASK"):
            pr = valid_pr()
            pr["head"]["ref"] = branch
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                policy.validate_pr(pr, "main")
        with self.assertRaises(ValueError):
            policy.validate_pr({**valid_pr(), "title": "bad title"}, "main")
        with self.assertRaises(ValueError):
            policy.validate_pr({**valid_pr(), "base": {"ref": "develop"}}, "main")

    def test_unrun_tests_require_explanation(self):
        body = valid_pr()["body"].replace("python -m unittest 실행: 10개 PASS", "미실행. 사유: 문서만 변경했고 코드 실행 경로에 영향이 없습니다. CI에서 회귀 검증 예정.")
        policy.validate_pr({**valid_pr(), "body": body}, "main")

    def test_incomplete_test_reports_rejected(self):
        for report in ("미실행", "미실행. 사유:", "TODO", "PASS", "테스트 예정"):
            body = valid_pr()["body"].replace("python -m unittest 실행: 10개 PASS", report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                policy.validate_pr({**valid_pr(), "body": body}, "main")

    def test_shell_text_remains_data(self):
        pr = valid_pr()
        pr["title"] = "[ci] $(touch /tmp/should-never-exist) `whoami` (#12)"
        policy.validate_pr(pr, "main")

    def test_issue_forms(self):
        for kind in ("feat", "fix", "docs", "test", "refactor", "chore", "ci"):
            headings = policy.ISSUE_SECTIONS.get(kind, policy.TASK_SECTIONS)
            issue = {"title": f"[{kind}] 작업 정의", "body": "\n\n".join(f"### {h}\n실제 요구사항과 검증 조건" for h in headings)}
            policy.validate_issue(issue)
            with self.assertRaises(ValueError):
                policy.validate_issue({**issue, "body": "<!-- " + issue["body"] + " -->"})

    def test_duplicate_headings(self):
        with self.assertRaises(ValueError):
            policy.validate_pr({**valid_pr(), "body": valid_pr()["body"] + "\n## 개요\n두 번째 내용"}, "main")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.pr = valid_pr()
        self.event = {"pull_request": copy.deepcopy(self.pr)}
        self.commit = {"sha": "b" * 40, "parents": [{"sha": "c" * 40}],
                       "commit": {"message": "[ci] 협업 검사 추가 (#12)"}}

    def response(self, path):
        if path.endswith("/pulls/30"):
            return self.pr
        if path.endswith("/issues/12"):
            return {"number": 12, "state": "open"}
        if "/commits?" in path:
            return [self.commit]
        return {"default_branch": "main"}

    def test_api_backed_pr_and_commits(self):
        with patch.object(policy, "api", side_effect=self.response):
            policy.check_pr("pr", self.event, "owner/repo")
            policy.check_pr("commits", self.event, "owner/repo")

    def test_closed_issue_and_pr_number_rejected(self):
        for linked in ({"state": "closed"}, {"state": "open", "pull_request": {}}):
            def response(path):
                return linked if path.endswith("/issues/12") else self.response(path)
            with self.subTest(linked=linked), patch.object(policy, "api", side_effect=response), self.assertRaises(ValueError):
                policy.check_pr("pr", self.event, "owner/repo")

    def test_stale_event_rejected(self):
        self.pr["head"]["sha"] = "d" * 40
        with patch.object(policy, "api", side_effect=self.response), self.assertRaises(ValueError):
            policy.check_pr("commits", self.event, "owner/repo")

    def test_missing_commits_fail_closed(self):
        self.pr["commits"] = 251
        with patch.object(policy, "api", side_effect=self.response), self.assertRaises(ValueError):
            policy.check_pr("commits", self.event, "owner/repo")

    def test_pagination_checks_later_pages(self):
        with patch.object(policy, "api", side_effect=[[self.commit] * 100, [self.commit]]) as mock:
            self.assertEqual(len(policy.paginated("/repos/owner/repo/pulls/30/commits")), 101)
            self.assertIn("page=2", mock.call_args.args[0])

    def test_api_failure_fails_check(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps(self.event), encoding="utf-8")
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_REPOSITORY="owner/repo"), \
                 patch.object(sys, "argv", [str(SCRIPT), "pr"]), \
                 patch.object(policy, "api", side_effect=urllib.error.HTTPError("https://api.github.com", 403, "Forbidden", {}, None)):
                self.assertEqual(policy.main(), 1)

    def test_issue_label_added_and_removed(self):
        issue = {"number": 12, "title": "bad title", "body": "", "labels": []}
        calls = []
        def response(path, method="GET", data=None):
            calls.append((path, method, data))
            return issue if path.endswith("/issues/12") else {}
        with patch.object(policy, "api", side_effect=response), self.assertRaises(ValueError):
            policy.check_issue({"issue": {"number": 12}}, "owner/repo")
        self.assertEqual(calls[-1][2], {"labels": ["needs-issue-update"]})
        issue.update(title="[docs] 작업 문서", body="\n".join("### " + h + "\n구체적인 작업 내용" for h in policy.TASK_SECTIONS),
                     labels=[{"name": "needs-issue-update"}])
        with patch.object(policy, "api", side_effect=response):
            policy.check_issue({"issue": {"number": 12}}, "owner/repo")
        self.assertEqual(calls[-1][1], "DELETE")


class HookTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git") and shutil.which("sh"), "Git Bash/POSIX sh required")
    def test_real_hook_in_temporary_git_repo(self):
        # No real repository configuration, commits or existing hooks are touched.
        with tempfile.TemporaryDirectory(prefix="leafy-hook-") as directory:
            tmp = Path(directory)
            subprocess.run(["git", "init", "-q", str(tmp)], check=True, capture_output=True)
            target = tmp / ".github/scripts/collaboration.py"
            target.parent.mkdir(parents=True)
            shutil.copyfile(SCRIPT, target)
            message = tmp / "message.txt"
            env = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"], "PYTHONUTF8": "1"}
            for subject, expected in (("[feat] 정상 커밋 (#12)\r\n", 0), ("[feature] 잘못된 type (#12)", 1),
                                      ("[fix] 이슈 없음", 1), ("Merge fabricated", 1)):
                message.write_bytes(subject.encode("utf-8"))
                result = subprocess.run(["sh", str(ROOT / ".githooks/commit-msg"), str(message)], cwd=tmp,
                                        env=env, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr.decode(errors="replace"))
            # Git MERGE_HEAD distinguishes an actual in-progress merge from a fake subject.
            (tmp / ".git/MERGE_HEAD").write_text("a" * 40 + "\n", encoding="ascii")
            message.write_text("Merge branch 'main'", encoding="utf-8")
            result = subprocess.run(["sh", str(ROOT / ".githooks/commit-msg"), str(message)], cwd=tmp,
                                    env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
