# Tool: GitHub Actions Audit

## Overview

Interactive auditor for GitHub Actions usage across a user or org account.
Built for finding "minute eaters": forks and stale repos whose inherited or
scheduled workflows keep burning Actions minutes.

## Requirements

- `gh` CLI, authenticated (`gh auth login`)
- `uv` (deps auto-resolve via inline script metadata)
  or Python 3.10+ with `questionary`, `rich`, and `pyyaml`

## Run

```bash
uv run gha_audit.py                 # interactive audit of your account
uv run gha_audit.py --owner ORG     # audit an org instead
uv run gha_audit.py --forks-only    # only scan forks
uv run gha_audit.py --scan-only     # read-only table, no prompts
```

## Flow

1. Scans every repo and prints a table with: the repo-wide **Actions**
   gate (`OFF` = hard gate: no run of any type can start - schedules,
   pushes, manual dispatch, or anything synced in later - and gated rows
   are dimmed), **All time** run count,
   **Last 30d** run count (via the API `created=START..END` filter),
   active workflow **names** (CI, Cron, Staging, ...), an
   **External effects** column summarizing what each repo's workflows can
   touch outside GitHub (Airtable, Azure, Wayback, repo commits, secrets,
   external reusable workflows, outbound HTTP, ...), and the
   branches/events seen in the 50 most recent runs.
2. You pick one repo to inspect (Enter selects; `Exit` is the last
   row). Each repo's line ends with its repo-wide Actions gate state
   (`actions=on|OFF|?`).
3. Per repo: a detail panel shows each workflow's state, declared trigger,
   external effects, observed events/branches, last run, and billable
   minutes (via the workflow `timing` endpoint, real per-OS billable ms).
4. Per repo you pick one action (Enter selects). Rows are:
   `STOP everything - disable ALL GitHub Actions on this repo` (first,
   hidden when the repo-wide gate is already OFF),
   `DISABLE '<name>'` per active workflow (CI last), and
   `Cancel - quit without changes` (last). Every row shows the literal
   `gh api` command it would run plus its external effects, so nothing
   is ambiguous.
5. A confirmation panel lists every pending change grouped by repo with
   the exact API call under each (`y + Enter` applies, anything else
   aborts).
6. After each batch you can answer "Manage more repositories?" to loop
   back to the repo list without re-scanning; repos you changed are
   refreshed on demand if reselected.

## Safety model

- Read-only by default; `--scan-only` never prompts or writes.
- Every disable requires explicit selection plus a final confirm.
- Disabling uses the Actions REST API only:

  ```
  PUT /repos/{o}/{r}/actions/workflows/{id}/disable
  PUT /repos/{o}/{r}/actions/permissions        (enabled=false)
  ```

  These flip GitHub-side state and create **no commits** on the target
  repo or anywhere else. Reversible any time (re-enable via API or UI).

- Per-workflow disable stops one workflow; it shows as `disabled_manually`
  in the still-visible Actions tab. Repo-wide disable turns the Actions
  feature off for the whole repo (Actions tab shows a disabled state) and
  blocks even workflows that arrive later via fork syncs; re-enabling
  restores previous per-workflow states.
- The tool never runs workflows, syncs forks, commits, or pushes; every
  subprocess call is `gh api` (reads plus the two disable PUTs above).
- Untrusted input is hardened: workflow YAML parse failures degrade to
  "unparseable" instead of crashing the audit, all GitHub-sourced strings
  are sanitized/Rich-escaped before display, `--owner` is validated as a
  GitHub login, and failed API calls are reported in a warning panel
  rather than silently treated as "no data".

- Forks are the usual leak: they inherit `.github/workflows` from
  upstream, and `schedule:` cron workflows keep firing on the fork's
  default branch. Any push (e.g. a fork sync) also triggers `push`
  workflows.

## token_audit.py

Read-only owner-credential audit supporting the A6 hardening control
(DEV-120): flags credentials that should be short-lived or rotated.

```bash
uv run token_audit.py            # full report
uv run token_audit.py --json     # machine-readable, exits 1 on findings
```

Checks:

- `gh` CLI token class (OAuth vs classic PAT vs fine-grained PAT).
- GitHub Actions secrets across user + org repos: credential-shaped
  names and secrets not rotated in 90+ days.
- Cloudflare user API tokens: name, status, expiry. Needs
  `CLOUDFLARE_API_TOKEN` or `CF_API_TOKEN` in env; skipped otherwise.
- Local `.github/workflows` under `--scan-root` (default
  `~/projects/devartslab`): literal committed tokens and
  `secrets.*` references.
- Local agent/tool configs (`~/.agents`, `~/.config/devin`,
  `~/.codeium`, `~/.cursor`, `~/.claude.json`): credential-shaped
  variable names only; values are never read or printed.

Read-only, always. Exit code 1 when findings exist so it can run in CI
or the monthly review (DEV-121).

## Tests

```bash
uv run --with pytest --with "questionary>=2.1" --with "rich>=13.7" \
    --with "pyyaml>=6.0" python -m pytest test_gha_audit.py -v
```

Regression tests cover malformed-YAML resilience, Rich markup/escape
injection, API error visibility, owner validation, and pagination.

## Notes

- `schedule:` (cron) workflows run only on the default branch; `push`,
  `pull_request`, and `workflow_dispatch` runs can come from any branch,
  so the tool surfaces branches per workflow.
- Account-level billing totals need the `user` scope:
  `gh auth refresh -h github.com -s user`, then
  `gh api /users/<you>/settings/billing/actions`.
- To cap risk permanently, set an Actions spending limit of $0 in
  GitHub Settings > Billing.
