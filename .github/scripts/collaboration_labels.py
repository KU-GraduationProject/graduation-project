"""Sync only this repository's managed collaboration labels and metadata."""
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse

import collaboration as policy

CATALOG = json.loads((Path(__file__).resolve().parents[1] / "labels.json").read_text(encoding="utf-8"))
AREA_PATHS = {
    "area:github": (".github/*", ".githooks/*", ".coderabbit.yaml", "AGENTS.md", "claude.md", ".gitattributes"),
    "area:docs": ("docs/*", "*.md"),
    "area:pipeline": ("aiops/pipeline/*",),
    "area:remediation": ("aiops/remediation/*", "aiops/policy/*"),
    "area:observability": ("monitoring/*", "aiops/network-observer/*", "leafy/fluentd/*"),
    "area:infra": ("deploy/*", "docker-compose*.yml", "leafy/db/*", "leafy/frontend/*"),
    "area:scenarios": ("scenarios/*", "aiops/eval/*"),
    "area:tooling": ("tools/*", "testing/*"),
}


def ensure_catalog(repo):
    """Create missing names; preserve existing colors, descriptions and legacy labels."""
    existing = {item["name"] for item in policy.paginated(f"/repos/{repo}/labels")}
    for label in CATALOG:
        if label["name"] in existing:
            continue
        try:
            policy.api(f"/repos/{repo}/labels", "POST", label)
        except urllib.error.HTTPError as error:
            if error.code != 422:
                raise
            # Another run may have created it. Fail if it is still unavailable.
            policy.api(f"/repos/{repo}/labels/" + urllib.parse.quote(label["name"], safe=""))


def desired_labels(item, pr=None, filenames=()):
    """Return desired managed labels and the subset this event may replace."""
    match = re.match(rf"^\[({policy.TYPES})\]\s+\S", item["title"])
    kind = match[1] if match else None
    desired = {f"type:{kind}"} if kind else set()
    if item["state"] == "closed":
        complete = bool(pr.get("merged")) if pr is not None else item.get("state_reason") == "completed"
        desired.add("status:done" if complete else "status:closed")
    else:
        desired.add("status:open" if pr is None else "status:draft" if pr["draft"] else "status:in-review")
    managed = {label["name"] for label in CATALOG if label["name"].startswith("status:")
               or kind and label["name"].startswith("type:")}
    if pr is not None:
        managed.update(AREA_PATHS)
        desired.update(area for area, patterns in AREA_PATHS.items()
                       if any(fnmatch.fnmatchcase(name, pattern) for name in filenames for pattern in patterns))
    # Issues have no changed-file list; their areas remain manually selected.
    if kind == "docs":
        desired.add("area:docs")
    return desired, managed, kind


def sync(repo, number, is_pr):
    """Refresh live metadata before writing; never replace the full label/assignee set."""
    number = int(number)
    item = policy.api(f"/repos/{repo}/issues/{number}")
    pr = policy.api(f"/repos/{repo}/pulls/{number}") if is_pr else None
    files = policy.paginated(f"/repos/{repo}/pulls/{number}/files") if is_pr else []
    if pr is not None and len(files) != pr["changed_files"]:
        raise ValueError("전체 PR 파일을 조회하지 못했습니다. 영역 라벨을 수동 검토하세요.")
    desired, managed, kind = desired_labels(item, pr, [entry["filename"] for entry in files])
    current = {label["name"] for label in item["labels"]}
    additions = sorted(desired - current)
    if additions:
        policy.api(f"/repos/{repo}/issues/{number}/labels", "POST", {"labels": additions})
    for label in sorted((current & managed) - desired):
        policy.api(f"/repos/{repo}/issues/{number}/labels/" + urllib.parse.quote(label, safe=""), "DELETE")
    if pr is None and kind:
        native = "Feature" if kind == "feat" else "Bug" if kind == "fix" else "Task"
        supported = policy.api(f"/repos/{repo}/issue-types")
        if native in {entry["name"] for entry in supported} and (item.get("type") or {}).get("name") != native:
            policy.api(f"/repos/{repo}/issues/{number}", "PATCH", {"type": native})
    if pr is not None and pr["state"] == "open" and not item["assignees"] and pr["user"]["type"] == "User":
        author = pr["user"]["login"]
        try:
            permission = policy.api(f"/repos/{repo}/collaborators/{author}/permission")["permission"]
        except urllib.error.HTTPError as error:
            if error.code not in (403, 404):
                raise
            permission = None
        if permission in {"admin", "maintain", "write"}:
            policy.api(f"/repos/{repo}/issues/{number}/assignees", "POST", {"assignees": [author]})
    print(f"PASS: collaboration metadata synced for #{number}")


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    is_pr = "pull_request" in event
    number = event["pull_request" if is_pr else "issue"]["number"]
    ensure_catalog(repo)
    sync(repo, number, is_pr)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, urllib.error.URLError) as error:
        # No API bodies, token values, titles or user text in failure logs.
        print(f"FAIL: metadata sync ({type(error).__name__}); check permissions and API availability.", file=sys.stderr)
        sys.exit(1)
