#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["rich>=13.7"]
# ///
"""token_audit: read-only owner-credential audit (A6 control, DEV-120).

Inventories long-lived credentials and flags ones that should be
short-lived per the lab owner-credential hardening control:

  1. gh CLI token type (OAuth vs classic PAT vs fine-grained PAT).
  2. GitHub Actions secrets per repo: names + last-updated, flags
     PAT-shaped names and secrets not rotated in STALE_DAYS.
  3. Cloudflare user API tokens: name, status, expiry (needs
     CLOUDFLARE_API_TOKEN or CF_API_TOKEN in env; skipped otherwise).
  4. Local workflow files under --scan-root: literal token patterns
     committed to .github/workflows and secrets.* references.
  5. Local agent/tool configs: credential-shaped variable NAMES only
     (values are never read or printed).

Usage:
    uv run token_audit.py                       # full report
    uv run token_audit.py --scan-root ~/repos   # local tree to scan
    uv run token_audit.py --json                # machine-readable

Requirements: gh CLI authenticated, uv.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

console = Console(width=max(140, shutil.get_terminal_size().columns))

STALE_DAYS = 90
DEFAULT_SCAN_ROOT = Path.home() / "projects" / "devartslab"

TOKEN_PREFIXES = {
    "gho_": ("OAuth (gh CLI)", "ok"),
    "ghu_": ("OAuth user-to-server", "ok"),
    "ghp_": ("classic PAT, long-lived", "finding"),
    "github_pat_": ("fine-grained PAT, has expiry", "warn"),
    "ghs_": ("server-to-server", "ok"),
    "ghr_": ("refresh token", "ok"),
}

SECRET_NAME_RE = re.compile(r"(PAT|TOKEN|API_?KEY|SECRET|PASSWORD)", re.I)
TOKEN_LITERAL_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})"
)
SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
LOCAL_KEY_RE = re.compile(
    r"([A-Za-z0-9_]*(?:API_?KEY|TOKEN|SECRET)[A-Za-z0-9_]*)\s*[:=]", re.I
)
LOCAL_CONFIG_GLOBS = [
    ".agents/**/*.json",
    ".agents/**/*.toml",
    ".agents/**/*.yaml",
    ".agents/**/*.yml",
    ".config/devin/**/*.json",
    ".codeium/**/*.json",
    ".cursor/**/*.json",
    ".claude.json",
]


@dataclass
class Report:
    gh_token: dict = field(default_factory=dict)
    gh_secrets: list[dict] = field(default_factory=list)
    cf_tokens: list[dict] = field(default_factory=list)
    workflow_findings: list[dict] = field(default_factory=list)
    local_keys: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def run(cmd: list[str]) -> tuple[str, str, int]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout, proc.stderr, proc.returncode


def gh_json(args: list[str]) -> tuple[object, str | None]:
    out, err, code = run(["gh", "api", *args])
    if code != 0:
        return None, err.strip() or f"gh api exited {code}"
    try:
        return json.loads(out), None
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"


def gh_lines(args: list[str]) -> tuple[list[str], str | None]:
    """gh api call returning newline-separated output (e.g. --jq)."""
    out, err, code = run(["gh", "api", *args])
    if code != 0:
        return [], err.strip() or f"gh api exited {code}"
    return [l for l in out.splitlines() if l], None


def days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        then = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - then).days
    except ValueError:
        return None


def audit_gh_token(rep: Report) -> None:
    out, err, code = run(["gh", "auth", "token"])
    if code != 0 or not out.strip():
        rep.skipped.append("gh auth token: not authenticated")
        return
    token = out.strip()
    label, level = "unknown prefix", "warn"
    for prefix, (lbl, lvl) in TOKEN_PREFIXES.items():
        if token.startswith(prefix):
            label, level = lbl, lvl
            break
    _, _, code = run(["gh", "api", "user", "--jq", ".login"])
    status_out, _, _ = run(["gh", "auth", "status"])
    scopes = ""
    m = re.search(r"Token scopes: (.+)", status_out)
    if m:
        scopes = m.group(1).strip()
    rep.gh_token = {"type": label, "level": level, "scopes": scopes}
    if level == "finding":
        rep.findings.append(
            "gh CLI uses a classic PAT (ghp_): replace with OAuth (`gh auth login`) "
            "or a fine-grained PAT with expiry"
        )
    elif level == "warn":
        rep.findings.append("fine-grained PAT in use: confirm expiry is set and <=90 days")


def audit_gh_secrets(rep: Report, owner: str) -> None:
    repo_names: list[str] = []
    lines, err = gh_lines(
        ["user/repos", "--paginate", "--jq", ".[].full_name"]
    )
    if err:
        rep.skipped.append(f"GitHub user repos listing: {err}")
    repo_names += lines
    orgs, _ = gh_lines(["user/orgs", "--jq", ".[].login"])
    for org in orgs:
        lines, err = gh_lines(
            [f"orgs/{org}/repos", "--paginate", "--jq", ".[].full_name"]
        )
        if err:
            rep.skipped.append(f"GitHub org {org} repos listing: {err}")
        repo_names += lines
    repo_names = sorted(set(repo_names))
    if not repo_names:
        rep.skipped.append("GitHub repos listing: none found")
        return
    for full in repo_names:
        data, err = gh_json([f"repos/{full}/actions/secrets"])
        if err or not isinstance(data, dict):
            continue
        for s in data.get("secrets", []):
            age = days_since(s.get("updated_at"))
            flags = []
            if SECRET_NAME_RE.search(s["name"]):
                flags.append("credential-shaped name")
            if age is not None and age > STALE_DAYS:
                flags.append(f"stale {age}d")
            rep.gh_secrets.append(
                {
                    "repo": full,
                    "name": s["name"],
                    "updated_at": s.get("updated_at", "")[:10],
                    "age_days": age,
                    "flags": flags,
                }
            )
    stale = [s for s in rep.gh_secrets if any("stale" in f for f in s["flags"])]
    if stale:
        rep.findings.append(
            f"{len(stale)} Actions secrets not rotated in {STALE_DAYS}+ days "
            f"(e.g. {stale[0]['repo']}:{stale[0]['name']})"
        )


def audit_cloudflare(rep: Report) -> None:
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    if not token:
        rep.skipped.append(
            "Cloudflare: no CLOUDFLARE_API_TOKEN/CF_API_TOKEN in env; "
            "token listing skipped"
        )
        return
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/user/tokens?per_page=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        rep.skipped.append(f"Cloudflare token listing failed: {e}")
        return
    for t in data.get("result", []):
        exp = t.get("expires_on")
        no_expiry = not exp
        rep.cf_tokens.append(
            {
                "name": t.get("name", "?"),
                "status": t.get("status", "?"),
                "expires_on": (exp or "never")[:10],
                "issued_on": (t.get("issued_on") or "")[:10],
            }
        )
        if no_expiry and t.get("status") == "active":
            rep.findings.append(
                f"Cloudflare token '{t.get('name')}' has no expiry"
            )


def audit_local_workflows(rep: Report, root: Path) -> None:
    for wf in sorted(root.glob("*/.github/workflows/*.y*ml")):
        try:
            text = wf.read_text(errors="replace")
        except OSError:
            continue
        repo = wf.relative_to(root).parts[0]
        for name in SECRET_REF_RE.findall(text):
            if name != "GITHUB_TOKEN" and SECRET_NAME_RE.search(name):
                rep.workflow_findings.append(
                    {"repo": repo, "file": wf.name, "ref": f"secrets.{name}"}
                )
        hits = TOKEN_LITERAL_RE.findall(text)
        if hits:
            rep.workflow_findings.append(
                {"repo": repo, "file": wf.name, "ref": f"LITERAL TOKEN x{len(hits)}"}
            )
            rep.findings.append(
                f"literal token committed in {repo}/.github/workflows/{wf.name}"
            )


def audit_local_configs(rep: Report) -> None:
    home = Path.home()
    seen = set()
    for pattern in LOCAL_CONFIG_GLOBS:
        for f in home.glob(pattern):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for name in LOCAL_KEY_RE.findall(text):
                key = (str(f), name.upper())
                if key in seen:
                    continue
                seen.add(key)
                rep.local_keys.append({"file": str(f).replace(str(home), "~"), "var": name})
    if rep.local_keys:
        rep.findings.append(
            f"{len(rep.local_keys)} credential-shaped variables in local agent/tool "
            "configs: confirm each is scoped and short-lived or OAuth-backed"
        )


def print_report(rep: Report) -> None:
    if rep.gh_token:
        t = rep.gh_token
        console.print(f"\n[bold]gh CLI token[/bold]: {t['type']}  scopes: {t['scopes']}")

    if rep.gh_secrets:
        table = Table(title="GitHub Actions secrets", box=box.SIMPLE)
        table.add_column("Repo")
        table.add_column("Secret")
        table.add_column("Updated")
        table.add_column("Flags")
        for s in rep.gh_secrets:
            style = "yellow" if s["flags"] else "dim"
            table.add_row(s["repo"], s["name"], s["updated_at"], ", ".join(s["flags"]), style=style)
        console.print(table)

    if rep.cf_tokens:
        table = Table(title="Cloudflare API tokens", box=box.SIMPLE)
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Issued")
        table.add_column("Expires")
        for t in rep.cf_tokens:
            style = "yellow" if t["expires_on"] == "never" else "white"
            table.add_row(t["name"], t["status"], t["issued_on"], t["expires_on"], style=style)
        console.print(table)

    if rep.workflow_findings:
        table = Table(title="Workflow secret references", box=box.SIMPLE)
        table.add_column("Repo")
        table.add_column("Workflow")
        table.add_column("Reference")
        for w in rep.workflow_findings:
            table.add_row(w["repo"], w["file"], w["ref"])
        console.print(table)

    if rep.local_keys:
        table = Table(title="Local config credential variables (names only)", box=box.SIMPLE)
        table.add_column("File")
        table.add_column("Variable")
        for k in rep.local_keys:
            table.add_row(k["file"], k["var"])
        console.print(table)

    if rep.skipped:
        console.print("\n[dim]Skipped:[/dim] " + " | ".join(rep.skipped))
    console.print()
    if rep.findings:
        for f in rep.findings:
            console.print(f"[yellow]FINDING[/yellow] {f}")
    else:
        console.print("[green]No findings.[/green]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan-root", type=Path, default=DEFAULT_SCAN_ROOT)
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    rep = Report()
    audit_gh_token(rep)
    out, _, code = run(["gh", "api", "user", "--jq", ".login"])
    owner = out.strip() if code == 0 else ""
    if owner:
        audit_gh_secrets(rep, owner)
    audit_cloudflare(rep)
    if args.scan_root.is_dir():
        audit_local_workflows(rep, args.scan_root)
    audit_local_configs(rep)

    if args.as_json:
        print(json.dumps(rep.__dict__, indent=2, default=str))
    else:
        print_report(rep)
    sys.exit(1 if rep.findings else 0)


if __name__ == "__main__":
    main()
