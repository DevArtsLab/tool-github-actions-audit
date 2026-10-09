#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["questionary>=2.1", "rich>=13.7", "pyyaml>=6.0"]
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
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta

import questionary
import yaml
from questionary import Choice, Style
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
from rich.tree import Tree

console = Console(width=max(140, shutil.get_terminal_size().columns))
ALL_ACTIONS = "__disable_entire_repo__"
CANCEL = "__cancel__"
WINDOW_DAYS = 30

QSTYLE = Style(
    [
        ("qmark", "fg:#5f87ff bold"),
        ("question", "bold"),
        ("pointer", "fg:#ff5f5f bold"),
        ("highlighted", "fg:#5f87ff bold"),
        ("selected", "fg:#87af5f"),
        ("instruction", "fg:#808080"),
        ("answer", "fg:#87af5f bold"),
    ]
)


def heat(n: int) -> str:
    """Color tier for a run count."""
    if n >= 50:
        return "bold red"
    if n >= 10:
        return "yellow"
    if n > 0:
        return "white"
    return "dim"


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


def scan_repo(full_name: str, start: str, end: str) -> dict:
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
    for w in info["workflows"]:
        raw = fetch_workflow_yaml(full_name, w.get("path", ""))
        if raw:
            w.update(analyze_workflow(full_name, raw))
        else:
            w.update({"trigger": "trigger unknown (file unreadable)",
                      "tags": [], "effects": [], "secrets": []})
    recent = gh_json([f"repos/{full_name}/actions/runs?per_page=50"])
    if recent:
        info["runs_total"] = recent.get("total_count", info["runs_total"])
        info["runs"] = recent.get("workflow_runs", [])
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


def gh_text(args: list[str]) -> str | None:
    """Run `gh api <args>`; return raw stdout or None on failure."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else None


def disable_cmd(full_name: str, wf_id) -> str:
    """The literal gh command used for a given disable action."""
    if wf_id == ALL_ACTIONS:
        return (f"gh api -X PUT repos/{full_name}/actions/permissions "
                f"-F enabled=false")
    return (f"gh api -X PUT "
            f"repos/{full_name}/actions/workflows/{wf_id}/disable")


# (needle-in-yaml, short tag for tables, human phrase for prompts)
EFFECT_RULES = [
    ("airtable", "airtable", "writes to Airtable"),
    ("azure", "azure", "writes to Azure storage"),
    ("wayback", "wayback", "submits pages to the Wayback Machine"),
    ("deploy-pages", "pages", "deploys a GitHub Pages site"),
    ("repository_dispatch", "repo-dispatch",
     "triggers workflows in other repositories"),
    ("twine", "pypi", "publishes to PyPI"),
    ("npm publish", "npm", "publishes to npm"),
    ("docker push", "containers", "pushes container images"),
    ("ghcr.io", "containers", "pushes container images"),
    ("slack", "slack", "sends Slack messages"),
    ("sentry", "sentry", "reports errors to Sentry"),
    ("gh-workflow-keepalive", "keepalive",
     "auto re-enables its own schedule via the API"),
    ("scrapy crawl", "web-scrape", "crawls external websites"),
    (".deploy.sh", "web-scrape", "crawls external websites"),
    ("git push", "repo-push", "pushes commits to this repo"),
    ("git commit", "repo-commit", "creates commits in this repo"),
    ("curl ", "http", "makes outbound HTTP calls"),
    ("wget ", "http", "makes outbound HTTP calls"),
]


def fetch_workflow_yaml(full_name: str, wf_path: str) -> str | None:
    return gh_text([
        "-H", "Accept: application/vnd.github.raw",
        f"repos/{full_name}/contents/{wf_path}",
    ])


def analyze_workflow(full_name: str, raw: str) -> dict:
    """Describe a workflow's `on:` triggers and external effects."""
    info = {"trigger": "trigger unknown", "tags": [], "effects": [],
            "secrets": []}
    try:
        doc = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        doc = {}
        info["trigger"] = "trigger unknown (unparseable yaml)"
    # YAML 1.1 parses the bare key `on:` as boolean True.
    on = doc.get("on", doc.get(True)) if doc else None
    if on is None and doc:
        info["trigger"] = "trigger not declared"
    if on is not None:
        if isinstance(on, str):
            on = [on]
        if isinstance(on, list):
            on = {k: None for k in on}
        parts = []
        if "push" in on:
            cfg = on.get("push") or {}
            br = cfg.get("branches") if isinstance(cfg, dict) else None
            parts.append(
                "when code is pushed"
                + (f" to {', '.join(map(str, br))}" if br else "")
            )
        if "pull_request" in on:
            parts.append("when a pull request is opened/updated")
        if "schedule" in on:
            crons = [
                c.get("cron") for c in (on.get("schedule") or [])
                if isinstance(c, dict)
            ]
            parts.append(
                "on a schedule (cron)"
                + (f": {'; '.join(map(str, crons))}" if crons else "")
            )
        if "workflow_dispatch" in on:
            parts.append("when run manually")
        if "workflow_run" in on:
            parts.append("after another workflow finishes")
        if "release" in on:
            parts.append("when a release is published")
        known = {"push", "pull_request", "schedule", "workflow_dispatch",
                 "workflow_run", "release"}
        parts += [f"on {k}" for k in on
                  if isinstance(k, str) and k not in known]
        info["trigger"] = ", ".join(parts) or "trigger unknown"

    lowered = raw.lower()
    secrets = sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", raw)))
    info["secrets"] = secrets
    if secrets:
        info["tags"].append("secrets")
        info["effects"].append("uses secrets: " + ", ".join(secrets))
    for needle, tag, phrase in EFFECT_RULES:
        if needle in lowered and tag not in info["tags"]:
            info["tags"].append(tag)
            info["effects"].append(phrase)
    owner = full_name.split("/", 1)[0].lower()
    for m in re.finditer(r"uses:\s*([\w.\-]+)/([\w.\-]+)/", raw):
        if m.group(1).lower() not in (owner, "actions"):
            tag = "ext-call"
            if tag not in info["tags"]:
                info["tags"].append(tag)
            info["effects"].append(
                f"calls workflow in {m.group(1)}/{m.group(2)}")
    return info


def print_scan_table(rows: list[dict], meta: dict[str, dict],
                     start: str, end: str) -> None:
    table = Table(
        title="GitHub Actions usage by repository",
        caption=(
            f"All time = total workflow runs ever. Last {WINDOW_DAYS}d = "
            f"runs {start} .. {end}. Branches/Events sampled from the 50 "
            f"most recent runs."
        ),
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        row_styles=["", "on #16161e"],
    )
    table.add_column("Repo", style="cyan", no_wrap=True)
    table.add_column("Kind", justify="center")
    table.add_column("All time", justify="right")
    table.add_column(f"Last {WINDOW_DAYS}d", justify="right")
    table.add_column("Active workflows")
    table.add_column("External effects")
    table.add_column("Branches seen")
    table.add_column("Events")
    for info in rows:
        m = meta[info["full_name"]]
        wfs = info["workflows"]
        active_names = [w["name"] for w in wfs
                        if w.get("state") == "active"]
        wf_cell = ", ".join(active_names)
        if len(active_names) < len(wfs):
            wf_cell += f"  [dim]({len(active_names)}/{len(wfs)} active)[/]"
        tags = sorted({t for w in wfs for t in w.get("tags", [])})
        branches = sorted({r.get("head_branch") for r in info["runs"]
                           if r.get("head_branch")})
        events = sorted({r.get("event") for r in info["runs"]
                         if r.get("event")})
        if m["isFork"]:
            kind = "[magenta]fork[/]"
        else:
            kind = "[green]own[/]"
        if m["isPrivate"]:
            kind += "[dim]/priv[/]"
        n30 = info["runs_30d"]
        table.add_row(
            info["full_name"].split("/", 1)[-1], kind,
            str(info["runs_total"]),
            f"[{heat(n30)}]{n30}[/]",
            wf_cell or f"[dim]- ({len(wfs)} disabled)[/]",
            "[yellow]" + ", ".join(tags) + "[/]" if tags
            else "[dim]none[/]",
            ", ".join(branches[:6]) + (" ..." if len(branches) > 6 else ""),
            ", ".join(events),
            style="" if n30 else "dim",
        )
    console.print(table)


def print_repo_detail(info: dict) -> None:
    enabled = repo_actions_enabled(info["full_name"])
    status = (
        "[green]enabled[/]" if enabled
        else "[red]disabled[/]" if enabled is False
        else "[dim]unknown[/]"
    )
    table = Table(
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        row_styles=["", "on #16161e"],
    )
    table.add_column("Workflow", style="cyan")
    table.add_column("State", justify="center")
    table.add_column("File")
    table.add_column("External effects")
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
        mins_cell = (
            f"[{heat(int(mins))}]{mins:.1f}[/]" if mins is not None else "-"
        )
        effects = "; ".join(w.get("effects", [])) or "[dim]none detected[/]"
        table.add_row(
            w["name"], colored, w["path"].split("/")[-1],
            effects,
            ", ".join(act["events"]) or "[dim]none seen[/]",
            ", ".join(act["branches"]) or "[dim]none seen[/]",
            act["last"] or "[dim]none seen[/]",
            mins_cell,
        )
    console.print(
        Panel(
            table,
            title=f"[bold]{info['full_name']}[/]",
            subtitle=f"repo-wide Actions: {status}",
            border_style="blue",
        )
    )


def confirm_and_execute(plan: list[tuple[str, str, int | None]]) -> None:
    """plan entries: (repo_full_name, label, workflow_id|ALL_ACTIONS)."""
    by_repo: dict[str, list[tuple[str, object]]] = {}
    for repo, label, wf_id in plan:
        by_repo.setdefault(repo, []).append((label, wf_id))

    tree = Tree(f"[bold red]{len(plan)} pending change(s)[/]")
    for repo, items in by_repo.items():
        node = tree.add(f"[cyan]{repo}[/]")
        for label, wf_id in items:
            node.add(f"{label}\n[dim]$ {disable_cmd(repo, wf_id)}[/]")
    console.print(
        Panel(
            tree,
            title="[bold red]Confirmation required[/]",
            subtitle=(
                "stops workflows via the API only | never runs them | "
                "no commits on any repo"
            ),
            border_style="red",
        )
    )
    if not questionary.confirm(
        f"Apply {len(plan)} change(s)?",
        default=False,
        style=QSTYLE,
        instruction="No or ctrl+c = exit with no changes",
    ).ask():
        console.print("[dim]Aborted. Nothing was changed.[/]")
        return

    results = Table(
        title="Results",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
    )
    results.add_column("Repo")
    results.add_column("Action")
    results.add_column("Status", justify="center")
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
            "[bold green]done[/]" if err is None
            else f"[bold red]failed: {err}[/]",
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
            "GitHub owner (user or org) to audit:", style=QSTYLE).ask()
        if not owner:
            sys.exit("No owner given.")

    start = (date.today() - timedelta(days=WINDOW_DAYS)).isoformat()
    end = date.today().isoformat()
    mode = "read-only scan" if args.scan_only else "interactive"
    scope = "forks only" if args.forks_only else "all repos"
    console.print(
        Panel.fit(
            f"[bold cyan]gha_audit[/]  |  owner: [bold]{owner}[/]  |  "
            f"window: {start} .. {end}  |  mode: {mode}, {scope}",
            border_style="cyan",
        )
    )

    repos = list_repos(owner)
    meta = {r["nameWithOwner"]: r for r in repos}
    names = [r["nameWithOwner"] for r in repos
             if not args.forks_only or r["isFork"]]

    scanned: dict[str, dict] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning repos", total=len(names))
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(scan_repo, n, start, end): n
                       for n in names}
            for fut in as_completed(futures):
                info = fut.result()
                scanned[info["full_name"]] = info
                progress.update(
                    task, advance=1,
                    description=f"Scanned {info['full_name'].split('/')[-1]}",
                )

    rows = sorted(
        (i for i in scanned.values()
         if i["runs_total"] or i["workflows"]),
        key=lambda i: (-i["runs_30d"], -i["runs_total"]),
    )
    if not rows:
        console.print("No repositories with Actions activity found.")
        return

    forks = sum(1 for i in rows if meta[i["full_name"]]["isFork"])
    console.print(
        Panel.fit(
            f"scanned: [bold]{len(names)}[/]  |  with Actions activity: "
            f"[bold]{len(rows)}[/]  |  forks: [bold]{forks}[/]  |  "
            f"runs last {WINDOW_DAYS}d: "
            f"[bold]{sum(i['runs_30d'] for i in rows)}[/]",
            border_style="blue",
        )
    )
    print_scan_table(rows, meta, start, end)

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
        "Select repositories to inspect/manage:",
        choices=choices,
        style=QSTYLE,
        instruction="space = check, enter = continue, "
                    "enter on empty = exit, ctrl+c = cancel",
    ).ask()
    if selected is None:
        console.print("[dim]Cancelled. No changes were made.[/]")
        return
    if not selected:
        console.print("[dim]No repositories selected. Done, "
                      "nothing changed.[/]")
        return

    plan: list[tuple[str, str, int | None]] = []
    for full_name in selected:
        info = scanned[full_name]
        print_repo_detail(info)
        active_wfs = [w for w in info["workflows"]
                      if w.get("state") == "active"]
        # "Disable all" first, CI-style workflow last, then Cancel.
        active_wfs.sort(key=lambda w: w["name"] == "CI")
        wf_choices = [
            Choice(
                title="STOP everything - disable ALL GitHub Actions "
                      "on this repo",
                description=(
                    f"runs: {disable_cmd(full_name, ALL_ACTIONS)} | turns "
                    f"off the Actions feature repo-wide (the Actions tab "
                    f"shows 'disabled'); per-workflow states are kept and "
                    f"return if re-enabled"
                ),
                value=ALL_ACTIONS,
            )
        ]
        for w in active_wfs:
            act = wf_activity(info, w["id"])
            trig = w.get("trigger", "trigger unknown")
            side_effects = (
                "; ".join(w.get("effects", []))
                or "no external effects detected"
            )
            observed = (
                f"runs: {disable_cmd(full_name, w['id'])} | "
                f"stops only this workflow (shows disabled in the "
                f"Actions tab) | effects: {side_effects} | last ran "
                f"{act['last'] or 'never in recent sample'} | "
                f"branches seen: {', '.join(act['branches']) or 'none'}"
            )
            wf_choices.append(
                Choice(
                    title=f"DISABLE '{w['name']}'  |  currently runs {trig}",
                    description=observed,
                    value=w["id"],
                )
            )
        wf_choices.append(
            Choice(
                title="Cancel - quit without changes",
                description="exit now; nothing is modified",
                value=CANCEL,
            )
        )
        picked = questionary.checkbox(
            f"{full_name}: select workflows to STOP "
            f"(nothing here runs workflows, it only disables them):",
            choices=wf_choices,
            style=QSTYLE,
            instruction="space = check, enter = next repo, "
                        "enter on empty = skip this repo, "
                        "ctrl+c = cancel all",
        ).ask()
        if picked is None or CANCEL in picked:
            console.print("[dim]Cancelled. No changes were made.[/]")
            return
        if not picked:
            console.print(f"[dim]Skipped {full_name}, no changes.[/]")
            continue
        for pid in picked:
            label = ("disable entire repo Actions"
                     if pid == ALL_ACTIONS
                     else "disable workflow "
                          + next(w["name"] for w in info["workflows"]
                                 if w["id"] == pid))
            plan.append((full_name, label, pid))

    if not plan:
        console.print("[dim]Nothing selected to disable. Done, "
                      "nothing changed.[/]")
        return
    confirm_and_execute(plan)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled. No changes were made.[/]")
