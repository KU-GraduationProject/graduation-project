"""Dependency-free Git/PR/Issue validation. Treat all event/API text as data."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

TYPES = r"feat|fix|docs|test|refactor|chore|ci"
TITLE = re.compile(rf"\[({TYPES})\] ([^\r\n]+) \(#([1-9][0-9]*)\)")
BRANCH = re.compile(rf"({TYPES})/([1-9][0-9]*)-[a-z0-9]+(?:-[a-z0-9]+)*")
PR_SECTIONS = ("개요", "관련 이슈", "변경 사항", "테스트", "리뷰 포인트", "체크리스트")
ISSUE_SECTIONS = {
    "feat": ("작업 목적", "배경 및 필요성", "요구사항", "구현 범위", "완료 조건", "테스트 방법"),
    "fix": ("문제 설명", "재현 방법", "기대 동작", "실제 동작", "수정 완료 조건"),
}
TASK_SECTIONS = ("작업 목적", "작업 항목", "산출물", "완료 조건")
EXAMPLE = "[feat] 사용자 인증 API 구현 (#12)"
CHECKLIST = ("관련 Issue 연결", "로컬 테스트 완료", "기존 기능 영향 확인", "필요한 문서 수정",
             "리뷰어 지정", "민감정보 포함 여부 확인")


def title_issue(title):
    match = TITLE.fullmatch(title)
    if not match or not match[2].strip() or match[2] != match[2].strip():
        raise ValueError(f"제목 형식: [type] 요약 (#이슈번호). 예: {EXAMPLE}")
    return int(match[3])


def validate_message(message, issue=None, merge=False):
    subject = message.splitlines()[0] if message.splitlines() else ""
    # Only actual merge commits may use Git's generated Merge subject.
    if merge and subject.startswith("Merge "):
        return
    number = title_issue(subject)
    if issue is not None and number != issue:
        raise ValueError("커밋의 Issue 번호가 작업 브랜치/PR과 다릅니다.")


def without_comments(body):
    return re.sub(r"<!--[\s\S]*?(?:-->|$)", "", body or "")


def markdown_lines(body):
    """Yield content and prose flags using the same fence rules everywhere."""
    fence = None
    for line in without_comments(body).splitlines():
        if fence is None:
            opening = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
            if opening and (opening[1][0] != "`" or "`" not in opening[2]):
                fence = opening[1]
                continue
        else:
            closing = re.fullmatch(r" {0,3}(`{3,}|~{3,})[ \t]*", line)
            if closing and closing[1][0] == fence[0] and len(closing[1]) >= len(fence):
                fence = None
                continue
        yield line, fence is None


def sections(body):
    """Ignore commented/fenced headings; keep code blocks as section content."""
    result = {}
    current = None
    for line, prose in markdown_lines(body):
        heading = re.fullmatch(r"#{2,3}\s+(.+?)\s*#*\s*", line) if prose else None
        if heading:
            current = heading[1]
            if current in result:
                raise ValueError("같은 섹션 제목을 중복 작성하지 마세요.")
            result[current] = []
        elif current:
            result[current].append(line)
    return {key: "\n".join(value).strip() for key, value in result.items()}


def substantive(value):
    value = re.sub(r"(?m)^\s*[-*]\s+\[[ xX]\]\s*", "", value)
    value = re.sub(r"[\s`*_>#\-\[\]().]", "", value)
    return value.lower() not in {"", "todo", "tbd", "작성필요", "입력필요", "해당없음", "n/a", "na"}


def require_sections(body, required):
    parts = sections(body)
    for heading in required:
        if not substantive(parts.get(heading, "")):
            raise ValueError(f"필수 섹션에 실제 내용을 작성하세요: {heading}")
    return parts


def validate_test_report(report):
    if re.search(r"미실행|실행하지 않|not (?:run|executed)", report, re.I):
        if not re.search(r"(?:사유|이유|reason)\s*[:：]\s*\S.+", report, re.I):
            raise ValueError("미실행 테스트에는 사유: 구체적인 이유와 후속 검증을 작성하세요.")
    elif not re.search(r"\b(?:pass(?:ed)?|fail(?:ed)?|ok|skip(?:ped)?)\b|통과|실패|성공|정상|확인 완료", report, re.I):
        raise ValueError("테스트에는 수행한 검사와 결과(PASS/FAIL/통과 등), 또는 미실행 사유를 작성하세요.")
    if report.strip().lower() in {"pass", "fail", "ok", "통과", "실패", "성공", "정상"}:
        raise ValueError("결과만 적지 말고 수행한 테스트/검사도 작성하세요.")


def validate_pr(pr, default_branch):
    issue = title_issue(pr["title"])
    branch = BRANCH.fullmatch(pr["head"]["ref"])
    if not branch or int(branch[2]) != issue:
        raise ValueError("브랜치 형식: <type>/<issue-number>-<description>; PR과 같은 Issue를 사용하세요.")
    if pr["base"]["ref"] != default_branch:
        raise ValueError("Closes 자동 연결을 위해 이 정책의 PR은 기본 브랜치를 대상으로 합니다.")
    parts = require_sections(pr.get("body"), PR_SECTIONS)
    validate_test_report(parts["테스트"])
    related = parts["관련 이슈"]
    if not re.fullmatch(rf"Closes #{issue}\.?", related, re.IGNORECASE):
        raise ValueError("관련 이슈에는 PR 제목과 같은 번호의 Closes #숫자 한 줄을 작성하세요.")
    # Closing keywords in examples/code/comments do not create an Issue link.
    prose = "\n".join(line for line, is_prose in markdown_lines(pr.get("body")) if is_prose)
    links = re.findall(r"\b(?:close[sd]?|fix(?:es|ed)?|resolve[sd]?)\s+(?:#[1-9][0-9]*|https?://\S+)", prose, re.I)
    if len(links) != 1 or re.fullmatch(rf"Closes #{issue}", links[0], re.I) is None:
        raise ValueError("1 Issue = 1 PR: 실제 Closes #숫자 연결을 정확히 하나 작성하세요.")
    for item in CHECKLIST:
        if not re.search(rf"(?m)^\s*- \[[ xX]\] {re.escape(item)}\s*$", parts["체크리스트"]):
            raise ValueError(f"체크리스트 항목이 필요합니다: {item}")
    return issue


def validate_issue(issue):
    match = re.fullmatch(rf"\[({TYPES})\] \S[^\r\n]*", issue["title"])
    if not match:
        raise ValueError("Issue 제목 형식: [type] 작업 제목")
    require_sections(issue.get("body"), ISSUE_SECTIONS.get(match[1], TASK_SECTIONS))


def api(path, method="GET", data=None):
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = urllib.request.Request(
        base + path, method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                 "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def paginated(path):
    result = []
    for page in range(1, 1001):
        batch = api(f"{path}?per_page=100&page={page}")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("API 페이지 제한 초과; PR을 작은 작업으로 분리하세요.")


def check_pr(mode, event, repo):
    number = int(event["pull_request"]["number"])
    pr = api(f"/repos/{repo}/pulls/{number}")
    if pr["head"]["sha"] != event["pull_request"]["head"]["sha"]:
        raise ValueError("더 최신 커밋이 있습니다. 최신 이벤트의 검사 결과를 확인하세요.")
    default = api(f"/repos/{repo}")["default_branch"]
    issue = validate_pr(pr, default) if mode == "pr" else title_issue(pr["title"])
    if mode == "pr":
        linked = api(f"/repos/{repo}/issues/{issue}")
        if "pull_request" in linked or linked["state"] != "open":
            raise ValueError("Closes 대상은 이 저장소의 실제 열린 Issue여야 합니다(PR 번호 불가).")
        print("PASS: PR 양식, 브랜치, 기본 브랜치, 실제 열린 Issue/Closes 연결")
        # CODEOWNERS can request review on ready PRs. Approval is enforced by Rulesets.
        if not pr.get("requested_reviewers") and not pr.get("requested_teams"):
            print("NOTICE: 리뷰 요청 목록을 확인하세요. 사람 승인 1명은 Ruleset에서 설정합니다.")
    else:
        commits = paginated(f"/repos/{repo}/pulls/{number}/commits")
        if not commits or len(commits) != pr["commits"]:
            raise ValueError("전체 PR 커밋을 조회하지 못했습니다(REST 최대 250개). PR을 분리하세요.")
        for commit in commits:
            try:
                validate_message(commit["commit"]["message"], issue, len(commit["parents"]) > 1)
            except ValueError as error:
                raise ValueError(f"커밋 {commit['sha'][:12]}: {error}") from error
        print(f"PASS: PR 제목 및 전체 작업 커밋 {len(commits)}개")


def check_issue(event, repo):
    number = int(event["issue"]["number"])
    issue = api(f"/repos/{repo}/issues/{number}")
    if "pull_request" in issue:
        return
    label = "needs-issue-update"
    try:
        validate_issue(issue)
    except ValueError as error:
        try:
            api(f"/repos/{repo}/labels/{label}")
        except urllib.error.HTTPError as missing:
            if missing.code != 404:
                raise
            try:
                api(f"/repos/{repo}/labels", "POST", {"name": label, "color": "D93F0B",
                    "description": "Issue 제목/필수 본문을 협업 규칙에 맞게 보완하세요."})
            except urllib.error.HTTPError as raced:
                if raced.code != 422:
                    raise
        api(f"/repos/{repo}/issues/{number}/labels", "POST", {"labels": [label]})
        raise ValueError(f"{error} (needs-issue-update 라벨 지정)") from error
    if label in {item["name"] for item in issue.get("labels", [])}:
        api(f"/repos/{repo}/issues/{number}/labels/{label}", "DELETE")
    print("PASS: Issue 제목/본문 (Issue 생성 자체를 차단하지 않음)")


def main():
    mode = sys.argv[1]
    try:
        if mode == "message":
            raw = Path(sys.argv[2]).read_text(encoding="utf-8-sig")
            merge = subprocess.run(["git", "rev-parse", "-q", "--verify", "MERGE_HEAD"],
                                   capture_output=True).returncode == 0
            validate_message(raw, merge=merge)
            print("PASS: commit message")
        else:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
            repo = os.environ["GITHUB_REPOSITORY"]
            if mode == "issue":
                check_issue(event, repo)
            elif mode in {"pr", "commits"}:
                check_pr(mode, event, repo)
            else:
                raise ValueError("알 수 없는 검사 모드")
        return 0
    except (ValueError, KeyError, OSError, urllib.error.URLError) as error:
        # Never log API response bodies, credentials, or user-supplied shell text.
        if isinstance(error, urllib.error.HTTPError):
            print(f"FAIL: GitHub API HTTP {error.code}; 권한/Issue/설정을 확인하세요.", file=sys.stderr)
        elif isinstance(error, urllib.error.URLError):
            print("FAIL: GitHub API 연결 실패; 다시 실행하세요.", file=sys.stderr)
        else:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
