#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["questionary>=2.1", "rich>=13.7"]
# ///
"""gha_audit: interactive GitHub Actions usage auditor.

Scans a GitHub account (user or org) for repositories that have Actions
workflows and run history, shows which branches/events are consuming runs,
and lets you selectively disable workflows or whole-repo Actions.

Nothing is ever committed. Disabling uses the Actions REST API
(PUT .../workflows/{id}/disable or PUT .../actions/permissions), which
flips GitHub-side state only. Every change requires explicit confirmation.

Usage:
    uv run gha_audit.py                    # interactive, authed account
    uv run gha_audit.py --owner ORG        # audit an org
    uv run gha_audit.py --forks-only       # only scan forks
    uv run gha_audit.py --scan-only        # read-only report, no prompts

Requirements: gh CLI authenticated (gh auth login), uv.
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import date, timedelta
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import questionary
from questionary import Choice
from rich.console import Console
from rich.table import Table

console = Console(width=max(140, shutil.get_terminal_size().columns))
ALL_ACTIONS = "__disable_entire_repo__"


def gh_json(args: list[str]):
    """Run `gh api <args>`; return parsed JSON or None on failure."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def gh_write(args: list[str]) -> str | None:
    """Run a mutating gh api call; return error text or None on success."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    return None if proc.returncode == 0 else proc.stderr.strip()


def authed_login() -> str | None:
    proc = subprocess.run(
        ["gh", "api", "user", "--jq", ".login"], capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


def list_repos(owner: str) -> list[dict]:
    proc = subprocess.run(
        [
            "gh", "repo", "list", owner, "--limit", "1000",
            "--json", "nameWithOwner,name,isFork,isPrivate",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        console.print(f"[red]gh repo list failed:[/] {proc.stderr.strip()}")
        sys.exit(1)
    return json.loads(proc.stdout)


def scan_repo(full_name: str) -> dict:
    """Fetch workflows + recent runs for one repo."""
    info: dict = {
        "full_name": full_name,
        "workflows": [],
        "runs_total": 0,
        "runs_30d": 0,
        "runs": [],
        "error": None,
    }
    wf = gh_json([f"repos/{full_name}/actions/workflows"])
    if wf is None:
        info["error"] = "unavailable"
        return info
    info["workflows"] = wf.get("workflows", [])
    recent = gh_json([f"repos/{full_name}/actions/runs?per_page=50"])
    if recent:
        info["runs_total"] = recent.get("total_count", info["runs_total"])
        info["runs"] = recent.get("workflow_runs", [])
    start = (date.today() - timedelta(days=30)).isoformat()
    end = date.today().isoformat()
    win = gh_json(
        [f"repos/{full_name}/actions/runs?per_page=1&created={start}..{end}"]
    )
    if win:
        info["runs_30d"] = win.get("total_count", 0)
    return info


def wf_activity(info: dict, wf_id: int) -> dict:
    """Aggregate branches/events seen for a workflow from recent runs."""
    branches, events = set(), set()
    last = ""
    for r in info["runs"]:
        if r.get("workflow_id") == wf_id:
            if r.get("head_branch"):
                branches.add(r["head_branch"])
            if r.get("event"):
                events.add(r["event"])
            ts = r.get("created_at", "")
            if ts > last:
                last = ts
    return {"branches": sorted(branches), "events": sorted(events),
            "last": last[:10]}


def billable_minutes(full_name: str, wf_id: int) -> float | None:
    t = gh_json([f"repos/{full_name}/actions/workflows/{wf_id}/timing"])
    if not t:
        return None
    ms = sum(v.get("total_ms", 0) for v in t.get("billable", {}).values())
    return ms / 60000.0


def repo_actions_enabled(full_name: str) -> bool | None:
    p = gh_json([f"repos/{full_name}/actions/permissions"])
    return p.get("enabled") if p else None


def print_scan_table(rows: list[dict], meta: dict[str, dict]) -> None:
    table = Table(
        title="GitHub Actions usage by repository",
        caption=(
            "All time = total workflow runs ever. Last 30d = runs in the "
            "last 30 days. Branches/Events sampled from the 50 most "
            "recent runs."
        ),
        show_lines=True,
    )
    table.add_column("Repo", style="cyan", no_wrap=True)
    table.add_column("Kind")
    table.add_column("All time", justify="right")
    table.add_column("Last 30d", justify="right")
    table.add_column("Active workflows")
    table.add_column("Branches seen")
    table.add_column("Events")
    for info in rows:
        m = meta[info["full_name"]]
        wfs = info["workflows"]
        active_names = [w["name"] for w in wfs
                        if w.get("state") == "active"]
        wf_cell = ", ".join(active_names)
        if len(active_names) < len(wfs):
            wf_cell += f"  ({len(active_names)}/{len(wfs)} active)"
        branches = sorted({r.get("head_branch") for r in info["runs"]
                           if r.get("head_branch")})
        events = sorted({r.get("event") for r in info["runs"]
                         if r.get("event")})
        kind = "fork" if m["isFork"] else "own"
        if m["isPrivate"]:
            kind += "/priv"
        table.add_row(
            info["full_name"].split("/", 1)[-1], kind,
            str(info["runs_total"]),
            str(info["runs_30d"]),
            wf_cell or f"- ({len(wfs)} disabled)",
            ", ".join(branches[:6]) + (" ..." if len(branches) > 6 else ""),
            ", ".join(events),
        )
    console.print(table)


def print_repo_detail(info: dict) -> None:
    enabled = repo_actions_enabled(info["full_name"])
    console.rule(f"[bold]{info['full_name']}")
    console.print(
        f"Repo-wide Actions: [bold]{'enabled' if enabled else 'disabled' if enabled is False else 'unknown'}[/]"
    )
    table = Table(show_lines=True)
    table.add_column("Workflow", style="cyan")
    table.add_column("State")
    table.add_column("File")
    table.add_column("Events")
    table.add_column("Branches")
    table.add_column("Last run")
    table.add_column("Billable min", justify="right")
    for w in info["workflows"]:
        act = wf_activity(info, w["id"])
        mins = billable_minutes(info["full_name"], w["id"])
        state = w.get("state", "?")
        colored = {
            "active": f"[green]{state}[/]",
            "disabled_manually": f"[yellow]{state}[/]",
            "disabled_inactivity": f"[red]{state}[/]",
        }.get(state, state)
        table.add_row(
            w["name"], colored, w["path"].split("/")[-1],
            ", ".join(act["events"]) or "-",
            ", ".join(act["branches"]) or "-",
            act["last"] or "-",
            f"{mins:.1f}" if mins is not None else "-",
        )
    console.print(table)


def confirm_and_execute(plan: list[tuple[str, str, int | None]]) -> None:
    """plan entries: (repo_full_name, label, workflow_id|ALL_ACTIONS)."""
    console.rule("[bold red]Confirmation required")
    console.print("The following changes will be applied via the GitHub API.")
    console.print("They do NOT create commits on any repository.\n")
    for i, (repo, label, _) in enumerate(plan, 1):
        console.print(f"  {i}. [cyan]{repo}[/] -> {label}")
    if not questionary.confirm(
        f"\nApply {len(plan)} change(s)?", default=False
    ).ask():
        console.print("Aborted. Nothing was changed.")
        return
    results = Table(title="Results")
    results.add_column("Repo")
    results.add_column("Action")
    results.add_column("Status")
    for repo, label, wf_id in plan:
        if wf_id == ALL_ACTIONS:
            err = gh_write([
                "-X", "PUT", f"repos/{repo}/actions/permissions",
                "-F", "enabled=false",
            ])
        else:
            err = gh_write([
                "-X", "PUT",
                f"repos/{repo}/actions/workflows/{wf_id}/disable",
            ])
        results.add_row(
            repo, label,
            "[green]done[/]" if err is None else f"[red]failed: {err}[/]",
        )
    console.print(results)


def main() -> None:
    ap = argparse.ArgumentParser(description="Interactive GitHub Actions auditor")
    ap.add_argument("--owner", help="GitHub user or org to audit "
                                    "(default: authenticated account)")
    ap.add_argument("--forks-only", action="store_true",
                    help="only scan forked repositories")
    ap.add_argument("--scan-only", action="store_true",
                    help="print the audit table and exit (read-only)")
    args = ap.parse_args()

    owner = args.owner or authed_login()
    if not owner:
        owner = questionary.text(
            "GitHub owner (user or org) to audit:").ask()
        if not owner:
            sys.exit("No owner given.")

    console.print(f"Scanning [bold]{owner}[/] ...")
    repos = list_repos(owner)
    meta = {r["nameWithOwner"]: r for r in repos}
    names = [r["nameWithOwner"] for r in repos
             if not args.forks_only or r["isFork"]]

    scanned: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for info in ex.map(scan_repo, names):
            scanned[info["full_name"]] = info

    rows = sorted(
        (i for i in scanned.values()
         if i["runs_total"] or i["workflows"]),
        key=lambda i: (-i["runs_30d"], -i["runs_total"]),
    )
    if not rows:
        console.print("No repositories with Actions activity found.")
        return
    print_scan_table(rows, meta)

    if args.scan_only:
        return

    choices = [
        Choice(
            title=(
                f"{i['full_name']}  "
                f"[{'fork' if meta[i['full_name']]['isFork'] else 'own'}] "
                f"30d={i['runs_30d']} all={i['runs_total']} "
                f"active={sum(1 for w in i['workflows'] if w['state'] == 'active')}/{len(i['workflows'])}"
            ),
            value=i["full_name"],
        )
        for i in rows
    ]
    selected = questionary.checkbox(
        "Select repositories to inspect/manage (space to check):",
        choices=choices,
    ).ask()
    if not selected:
        console.print("No repositories selected. Done.")
        return

    plan: list[tuple[str, str, int | None]] = []
    for full_name in selected:
        info = scanned[full_name]
        print_repo_detail(info)
        wf_choices = [
            Choice(
                title=(
                    f"{w['name']}  [{w['state']}]  "
                    f"{w['path'].split('/')[-1]}  "
                    f"events={','.join(wf_activity(info, w['id'])['events']) or '-'}  "
                    f"branches={','.join(wf_activity(info, w['id'])['branches']) or '-'}"
                ),
                value=w["id"],
            )
            for w in info["workflows"]
            if w.get("state") == "active"
        ]
        wf_choices.append(
            Choice(
                title="!! Disable ALL GitHub Actions on this repo",
                value=ALL_ACTIONS,
            )
        )
        picked = questionary.checkbox(
            f"{full_name}: select workflows to DISABLE (space to check, "
            f"empty = no change):",
            choices=wf_choices,
        ).ask()
        if picked is None:
            console.print("Cancelled.")
            return
        for pid in picked:
            label = ("disable entire repo Actions"
                     if pid == ALL_ACTIONS
                     else "disable workflow "
                          + next(w["name"] for w in info["workflows"]
                                 if w["id"] == pid))
            plan.append((full_name, label, pid))

    if not plan:
        console.print("Nothing selected to disable. Done.")
        return
    confirm_and_execute(plan)


if __name__ == "__main__":
    main()
