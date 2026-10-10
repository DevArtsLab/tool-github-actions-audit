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
from rich.markup import escape
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
EXIT = "__exit__"
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


_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(s: object) -> str:
    """Strip terminal control chars from untrusted text."""
    return _CTRL_RE.sub("", str(s))


def disp(s: object) -> str:
    """sanitize() plus Rich-markup escaping; safe for any Rich render."""
    return escape(sanitize(s))


_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")


def valid_owner(owner: str) -> bool:
    """GitHub login rules: alphanumerics/hyphens, max 39 chars, no leading '-'."""
    return bool(_OWNER_RE.match(owner))


def gh_json(args: list[str]) -> tuple[object, str | None]:
    """Run `gh api <args>`; return (parsed JSON, error_text)."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr.strip() or f"gh api exited {proc.returncode}"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as e:
        return None, f"invalid JSON response: {e}"


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
            "gh",
            "repo",
            "list",
            owner,
            "--limit",
            "1000",
            "--json",
            "nameWithOwner,name,isFork,isPrivate",
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
        "errors": [],
        "actions_enabled": None,
    }
    perms, err = gh_json([f"repos/{full_name}/actions/permissions"])
    if err:
        info["errors"].append(f"actions permissions failed: {err}")
    else:
        info["actions_enabled"] = perms.get("enabled")
    wf, err = gh_json([f"repos/{full_name}/actions/workflows?per_page=100"])
    if err:
        info["error"] = f"workflows list failed: {err}"
        return info
    info["workflows"] = wf.get("workflows", [])
    total_wf = wf.get("total_count", len(info["workflows"]))
    if total_wf > len(info["workflows"]):
        info["errors"].append(
            f"workflow list truncated: "
            f"{len(info['workflows'])} of {total_wf} fetched"
        )
    for w in info["workflows"]:
        raw = fetch_workflow_yaml(full_name, w.get("path", ""))
        try:
            parsed = (
                analyze_workflow(full_name, raw)
                if raw
                else {
                    "trigger": "trigger unknown (file unreadable)",
                    "tags": [],
                    "effects": [],
                    "secrets": [],
                }
            )
        except Exception as e:
            parsed = {
                "trigger": f"trigger unknown (unparseable: {type(e).__name__})",
                "tags": [],
                "effects": [],
                "secrets": [],
            }
        w.update(parsed)
    recent, err = gh_json([f"repos/{full_name}/actions/runs?per_page=50"])
    if err:
        info["errors"].append(f"recent runs failed: {err}")
    else:
        info["runs_total"] = recent.get("total_count", info["runs_total"])
        info["runs"] = recent.get("workflow_runs", [])
    win, err = gh_json(
        [f"repos/{full_name}/actions/runs?per_page=1&created={start}..{end}"]
    )
    if err:
        info["errors"].append(f"30d window failed: {err}")
    else:
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
    return {"branches": sorted(branches), "events": sorted(events), "last": last[:10]}


def billable_minutes(full_name: str, wf_id: int) -> float | None:
    t, _err = gh_json([f"repos/{full_name}/actions/workflows/{wf_id}/timing"])
    if not t:
        return None
    ms = sum(v.get("total_ms", 0) for v in t.get("billable", {}).values())
    return ms / 60000.0


def repo_actions_enabled(full_name: str) -> bool | None:
    p, _err = gh_json([f"repos/{full_name}/actions/permissions"])
    return p.get("enabled") if p else None


def gh_text(args: list[str]) -> str | None:
    """Run `gh api <args>`; return raw stdout or None on failure."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else None


def disable_cmd(full_name: str, wf_id) -> str:
    """The literal gh command used for a given disable action."""
    if wf_id == ALL_ACTIONS:
        return (
            f"gh api -X PUT repos/{full_name}/actions/permissions " f"-F enabled=false"
        )
    return f"gh api -X PUT " f"repos/{full_name}/actions/workflows/{wf_id}/disable"


# (needle-in-yaml, short tag for tables, human phrase for prompts)
EFFECT_RULES = [
    ("airtable", "airtable", "writes to Airtable"),
    ("azure", "azure", "writes to Azure storage"),
    ("wayback", "wayback", "submits pages to the Wayback Machine"),
    ("deploy-pages", "pages", "deploys a GitHub Pages site"),
    (
        "repository_dispatch",
        "repo-dispatch",
        "triggers workflows in other repositories",
    ),
    ("twine", "pypi", "publishes to PyPI"),
    ("npm publish", "npm", "publishes to npm"),
    ("docker push", "containers", "pushes container images"),
    ("ghcr.io", "containers", "pushes container images"),
    ("slack", "slack", "sends Slack messages"),
    ("sentry", "sentry", "reports errors to Sentry"),
    (
        "gh-workflow-keepalive",
        "keepalive",
        "auto re-enables its own schedule via the API",
    ),
    ("scrapy crawl", "web-scrape", "crawls external websites"),
    (".deploy.sh", "web-scrape", "crawls external websites"),
    ("git push", "repo-push", "pushes commits to this repo"),
    ("git commit", "repo-commit", "creates commits in this repo"),
    ("curl ", "http", "makes outbound HTTP calls"),
    ("wget ", "http", "makes outbound HTTP calls"),
]


def fetch_workflow_yaml(full_name: str, wf_path: str) -> str | None:
    return gh_text(
        [
            "-H",
            "Accept: application/vnd.github.raw",
            f"repos/{full_name}/contents/{wf_path}",
        ]
    )


def analyze_workflow(full_name: str, raw: str) -> dict:
    """Describe a workflow's `on:` triggers and external effects."""
    info = {"trigger": "trigger unknown", "tags": [], "effects": [], "secrets": []}
    try:
        doc = yaml.safe_load(raw)
    except Exception:
        # YAMLError, RecursionError on hostile nesting, etc.
        doc = None
        info["trigger"] = "trigger unknown (unparseable yaml)"
    if not isinstance(doc, dict):
        doc = {}
    # YAML 1.1 parses the bare key `on:` as boolean True.
    on = doc.get("on", doc.get(True))
    if on is None and doc:
        info["trigger"] = "trigger not declared"
    if on is not None:
        if isinstance(on, str):
            on = [on]
        if isinstance(on, list):
            on = {k: None for k in on if isinstance(k, str)}
        if not isinstance(on, dict):
            on = {}
        parts = []
        if "push" in on:
            cfg = on.get("push")
            br = cfg.get("branches") if isinstance(cfg, dict) else None
            if isinstance(br, str):
                br = [br]
            if isinstance(br, list):
                br = [b for b in br if isinstance(b, (str, int, float))]
            else:
                br = None
            parts.append(
                "when code is pushed" + (f" to {', '.join(map(str, br))}" if br else "")
            )
        if "pull_request" in on:
            parts.append("when a pull request is opened/updated")
        if "schedule" in on:
            sched = on.get("schedule")
            crons = (
                [
                    str(c.get("cron"))
                    for c in sched
                    if isinstance(c, dict) and c.get("cron") is not None
                ]
                if isinstance(sched, list)
                else []
            )
            parts.append(
                "on a schedule (cron)" + (f": {'; '.join(crons)}" if crons else "")
            )
        if "workflow_dispatch" in on:
            parts.append("when run manually")
        if "workflow_run" in on:
            parts.append("after another workflow finishes")
        if "release" in on:
            parts.append("when a release is published")
        known = {
            "push",
            "pull_request",
            "schedule",
            "workflow_dispatch",
            "workflow_run",
            "release",
        }
        parts += [f"on {k}" for k in on if isinstance(k, str) and k not in known]
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
            info["effects"].append(f"calls workflow in {m.group(1)}/{m.group(2)}")
    return info


def print_scan_table(
    rows: list[dict], meta: dict[str, dict], start: str, end: str
) -> None:
    table = Table(
        title="GitHub Actions usage by repository",
        caption=(
            f"All time = total workflow runs ever. Last {WINDOW_DAYS}d = "
            f"runs {start} .. {end}. Branches/Events sampled from the 50 "
            f"most recent runs. Actions = the repo-wide gate: OFF blocks "
            f"every run type (schedule, push, manual) and any workflow "
            f"synced in later. External effects are best-effort keyword "
            f"heuristics, not an authoritative audit."
        ),
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        row_styles=["", "on #16161e"],
    )
    table.add_column("Repo", style="cyan", no_wrap=True)
    table.add_column("Kind", justify="center")
    table.add_column("Actions", justify="center")
    table.add_column("All time", justify="right")
    table.add_column(f"Last {WINDOW_DAYS}d", justify="right")
    table.add_column("Active workflows")
    table.add_column("External effects")
    table.add_column("Branches seen")
    table.add_column("Events")
    for info in rows:
        m = meta[info["full_name"]]
        wfs = info["workflows"]
        active_names = [w["name"] for w in wfs if w.get("state") == "active"]
        wf_cell = ", ".join(disp(n) for n in active_names)
        if len(active_names) < len(wfs):
            wf_cell += f"  [dim]({len(active_names)}/{len(wfs)} active)[/]"
        tags = sorted({t for w in wfs for t in w.get("tags", [])})
        branches = sorted(
            {r.get("head_branch") for r in info["runs"] if r.get("head_branch")}
        )
        events = sorted({r.get("event") for r in info["runs"] if r.get("event")})
        if m["isFork"]:
            kind = "[magenta]fork[/]"
        else:
            kind = "[green]own[/]"
        if m["isPrivate"]:
            kind += "[dim]/priv[/]"
        n30 = info["runs_30d"]
        gate = info.get("actions_enabled")
        gate_cell = (
            "[red]OFF[/]" if gate is False else "[green]on[/]" if gate else "[dim]?[/]"
        )
        table.add_row(
            disp(info["full_name"].split("/", 1)[-1]),
            kind,
            gate_cell,
            str(info["runs_total"]),
            f"[{heat(n30)}]{n30}[/]",
            wf_cell or f"[dim]- ({len(wfs)} disabled)[/]",
            "[yellow]" + ", ".join(tags) + "[/]" if tags else "[dim]none[/]",
            ", ".join(disp(b) for b in branches[:6])
            + (" ..." if len(branches) > 6 else ""),
            ", ".join(disp(e) for e in events),
            style="" if (n30 and gate is not False) else "dim",
        )
    console.print(table)


def print_repo_detail(info: dict) -> None:
    enabled = info.get("actions_enabled")
    if enabled is None:
        enabled = repo_actions_enabled(info["full_name"])
    status = (
        "[green]enabled[/]"
        if enabled
        else (
            (
                "[red]DISABLED - hard gate:[/] no run can start "
                "[dim](schedule, push, manual, or newly synced "
                "workflows)[/]"
            )
            if enabled is False
            else "[dim]unknown[/]"
        )
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
        }.get(state, disp(state))
        mins_cell = (
            f"[{heat(int(mins))}]{mins:.1f}[/]" if mins is not None else "[dim]n/a[/]"
        )
        effects = (
            "; ".join(disp(e) for e in w.get("effects", [])) or "[dim]none detected[/]"
        )
        table.add_row(
            disp(w["name"]),
            colored,
            disp(w["path"].split("/")[-1]),
            effects,
            ", ".join(disp(e) for e in act["events"]) or "[dim]none seen[/]",
            ", ".join(disp(b) for b in act["branches"]) or "[dim]none seen[/]",
            act["last"] or "[dim]none seen[/]",
            mins_cell,
        )
    console.print(
        Panel(
            table,
            title=f"[bold]{disp(info['full_name'])}[/]",
            subtitle=f"repo-wide Actions: {status}",
            border_style="blue",
        )
    )


def confirm_and_execute(
    plan: list[tuple[str, str, int | str]],
) -> set[str]:
    """plan entries: (repo_full_name, label, workflow_id|ALL_ACTIONS).
    Returns the set of repos actually modified (empty if aborted)."""
    by_repo: dict[str, list[tuple[str, object]]] = {}
    for repo, label, wf_id in plan:
        by_repo.setdefault(repo, []).append((label, wf_id))

    tree = Tree(f"[bold red]{len(plan)} pending change(s)[/]")
    for repo, items in by_repo.items():
        node = tree.add(f"[cyan]{disp(repo)}[/]")
        for label, wf_id in items:
            node.add(f"{disp(label)}\n[dim]$ {disp(disable_cmd(repo, wf_id))}[/]")
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
        instruction="[y + Enter = apply] | [n + Enter = abort]",
    ).ask():
        console.print("[dim]Aborted. Nothing was changed.[/]")
        return set()

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
            err = gh_write(
                [
                    "-X",
                    "PUT",
                    f"repos/{repo}/actions/permissions",
                    "-F",
                    "enabled=false",
                ]
            )
        else:
            err = gh_write(
                [
                    "-X",
                    "PUT",
                    f"repos/{repo}/actions/workflows/{wf_id}/disable",
                ]
            )
        results.add_row(
            disp(repo),
            disp(label),
            (
                "[bold green]done[/]"
                if err is None
                else f"[bold red]failed: {disp(err)}[/]"
            ),
        )
    console.print(results)
    return set(by_repo)


def main() -> None:
    ap = argparse.ArgumentParser(description="Interactive GitHub Actions auditor")
    ap.add_argument(
        "--owner",
        help="GitHub user or org to audit " "(default: authenticated account)",
    )
    ap.add_argument(
        "--forks-only", action="store_true", help="only scan forked repositories"
    )
    ap.add_argument(
        "--scan-only",
        action="store_true",
        help="print the audit table and exit (read-only)",
    )
    args = ap.parse_args()

    owner = args.owner or authed_login()
    if owner and not valid_owner(owner):
        sys.exit(
            f"Invalid owner {owner!r}: expected a GitHub user/org login "
            "(alphanumerics and hyphens, max 39 chars)."
        )
    while not owner:
        owner = questionary.text(
            "GitHub owner (user or org) to audit:", style=QSTYLE
        ).ask()
        if not owner:
            sys.exit("No owner given.")
        if not valid_owner(owner):
            console.print(
                "[red]Not a valid GitHub login (alphanumerics and "
                "hyphens, max 39 chars).[/]"
            )
            owner = None

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
    if len(repos) >= 1000:
        console.print(
            "[yellow]warning: repo listing hit the 1000 limit - "
            "some repos may be missing from this audit[/]"
        )
    meta = {r["nameWithOwner"]: r for r in repos}
    names = [r["nameWithOwner"] for r in repos if not args.forks_only or r["isFork"]]

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
            futures = {ex.submit(scan_repo, n, start, end): n for n in names}
            for fut in as_completed(futures):
                try:
                    info = fut.result()
                except Exception as e:
                    info = {
                        "full_name": futures[fut],
                        "workflows": [],
                        "runs_total": 0,
                        "runs_30d": 0,
                        "runs": [],
                        "error": f"scan crashed: {type(e).__name__}: {e}",
                        "errors": [],
                        "actions_enabled": None,
                    }
                scanned[info["full_name"]] = info
                progress.update(
                    task,
                    advance=1,
                    description=f"Scanned {info['full_name'].split('/')[-1]}",
                )

    rows = sorted(
        (i for i in scanned.values() if i["runs_total"] or i["workflows"]),
        key=lambda i: (-i["runs_30d"], -i["runs_total"]),
    )
    if not rows:
        console.print("No repositories with Actions activity found.")
        return

    forks = sum(1 for i in rows if meta[i["full_name"]]["isFork"])
    gates_off = sum(1 for i in scanned.values() if i.get("actions_enabled") is False)
    console.print(
        Panel.fit(
            f"scanned: [bold]{len(names)}[/]  |  with Actions activity: "
            f"[bold]{len(rows)}[/]  |  forks: [bold]{forks}[/]  |  "
            f"runs last {WINDOW_DAYS}d: "
            f"[bold]{sum(i['runs_30d'] for i in rows)}[/]  |  "
            f"repo Actions OFF: [bold red]{gates_off}[/]",
            border_style="blue",
        )
    )
    failed = [i for i in scanned.values() if i.get("error")]
    partial = [i for i in scanned.values() if i.get("errors")]
    if failed or partial:
        warn = Tree("[bold]audit may be incomplete[/]")
        for i in failed:
            warn.add(f"[red]{disp(i['full_name'])}[/]: {disp(i['error'])}")
        for i in partial:
            for e in i["errors"]:
                warn.add(f"[yellow]{disp(i['full_name'])}[/]: {disp(e)}")
        console.print(
            Panel(
                warn,
                title=f"[bold yellow]{len(failed) + len(partial)} "
                "repo(s) failed or partially scanned[/]",
                border_style="yellow",
            )
        )
    print_scan_table(rows, meta, start, end)

    if args.scan_only:
        return

    def gate_word(i: dict) -> str:
        g = i.get("actions_enabled")
        return "OFF" if g is False else "on" if g else "?"

    choices = [
        Choice(
            title=sanitize(
                f"{i['full_name']}  "
                f"[{'fork' if meta[i['full_name']]['isFork'] else 'own'}] "
                f"30d={i['runs_30d']} all={i['runs_total']} "
                f"active="
                f"{sum(1 for w in i['workflows'] if w['state'] == 'active')}"
                f"/{len(i['workflows'])}  "
                f"actions={gate_word(i)}"
            ),
            value=i["full_name"],
        )
        for i in rows
    ] + [
        Choice(
            title="Exit - quit without changes",
            description="leave the tool; nothing is modified",
            value=EXIT,
        )
    ]
    dirty: set[str] = set()
    while True:
        selected = questionary.select(
            "Select a repository to inspect/manage:",
            choices=choices,
            style=QSTYLE,
            instruction="enter = select, ctrl+c = exit",
        ).ask()
        if not selected or selected == EXIT:
            console.print("[dim]Done. Nothing else selected.[/]")
            return

        plan: list[tuple[str, str, int | str]] = []
        cancelled = False
        for full_name in [selected]:
            if full_name in dirty:
                console.print(
                    f"[dim]Refreshing {disp(full_name)} after earlier " f"changes...[/]"
                )
                scanned[full_name] = scan_repo(full_name, start, end)
            info = scanned[full_name]
            print_repo_detail(info)
            active_wfs = [w for w in info["workflows"] if w.get("state") == "active"]
            # "Disable all" first, CI-style workflow last, then Cancel.
            # Gate already off -> the kill switch is meaningless, hide it.
            gate_off = info.get("actions_enabled") is False
            active_wfs.sort(key=lambda w: w["name"] == "CI")
            wf_choices = (
                []
                if gate_off
                else [
                    Choice(
                        title="STOP everything - disable ALL GitHub Actions "
                        "on this repo",
                        description=(
                            f"runs: {disable_cmd(full_name, ALL_ACTIONS)} | "
                            f"repo-wide hard gate: blocks every run type "
                            f"(schedule, push, manual) plus any workflow "
                            f"synced in later; per-workflow states are kept "
                            f"and return if re-enabled"
                        ),
                        value=ALL_ACTIONS,
                    )
                ]
            )
            for w in active_wfs:
                act = wf_activity(info, w["id"])
                trig = w.get("trigger", "trigger unknown")
                side_effects = (
                    "; ".join(w.get("effects", [])) or "no external effects detected"
                )
                observed = sanitize(
                    f"runs: {disable_cmd(full_name, w['id'])} | "
                    f"stops only this workflow (shows disabled in the "
                    f"Actions tab) | effects: {side_effects} | last ran "
                    f"{act['last'] or 'never in recent sample'} | "
                    f"branches seen: {', '.join(act['branches']) or 'none'}"
                )
                wf_choices.append(
                    Choice(
                        title=sanitize(
                            f"DISABLE '{w['name']}'  |  currently runs {trig}"
                        ),
                        description=observed,
                        value=w["id"],
                    )
                )
            wf_choices.append(
                Choice(
                    title="Cancel - quit without changes",
                    description=(
                        "exit the picker; picks already queued from "
                        "earlier repos are still shown for confirmation, "
                        "never applied silently"
                    ),
                    value=CANCEL,
                )
            )
            picked = questionary.checkbox(
                f"{sanitize(full_name)}: select workflows to STOP "
                + (
                    "(repo-wide Actions is OFF - nothing can run here; "
                    "per-workflow disables still apply if re-enabled):"
                    if gate_off
                    else "(nothing here runs workflows, " "it only disables them):"
                ),
                choices=wf_choices,
                style=QSTYLE,
                instruction="space = check, enter = next repo, "
                "enter on empty = skip this repo, "
                "ctrl+c = cancel all",
            ).ask()
            if picked is None or CANCEL in picked:
                cancelled = True
                break
            if not picked:
                console.print(f"[dim]Skipped {disp(full_name)}, no changes.[/]")
                continue
            for pid in picked:
                label = (
                    "disable entire repo Actions"
                    if pid == ALL_ACTIONS
                    else "disable workflow "
                    + sanitize(
                        next(w["name"] for w in info["workflows"] if w["id"] == pid)
                    )
                )
                plan.append((full_name, label, pid))

        if plan:
            dirty |= confirm_and_execute(plan)
        elif cancelled:
            console.print("[dim]Cancelled. No changes were made.[/]")
        else:
            console.print("[dim]Nothing selected to disable.[/]")

        again = questionary.confirm(
            "Manage more repositories?",
            default=False,
            style=QSTYLE,
            instruction="y + Enter = back to repo list, " "n + Enter or ctrl+c = exit",
        ).ask()
        if not again:
            console.print("[dim]Done.[/]")
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled. No changes were made.[/]")
