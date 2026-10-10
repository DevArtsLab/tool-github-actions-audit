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

1. Scans every repo and prints a table with: **All time** run count,
   **Last 30d** run count (via the API `created=START..END` filter),
   active workflow **names** (CI, Cron, Staging, ...), an
   **External effects** column summarizing what each repo's workflows can
   touch outside GitHub (Airtable, Azure, Wayback, repo commits, secrets,
   external reusable workflows, outbound HTTP, ...), and the
   branches/events seen in the 50 most recent runs.
2. You checkbox-select repos to inspect (empty selection exits).
3. Per repo: a detail panel shows each workflow's state, declared trigger,
   external effects, observed events/branches, last run, and billable
   minutes (via the workflow `timing` endpoint, real per-OS billable ms).
4. Per repo you checkbox-select what to STOP. Rows are:
   `STOP everything - disable ALL GitHub Actions on this repo` (first),
   `DISABLE '<name>'` per active workflow (CI last), and
   `Cancel - quit without changes` (last). Every row shows the literal
   `gh api` command it would run plus its external effects, so nothing
   is ambiguous. An empty selection skips the repo.
5. A confirmation panel lists every pending change grouped by repo with
   the exact API call under each (`y + Enter` applies, anything else
   aborts).
6. After each batch you can answer "Manage more repositories?" to loop
   back to the repo list without re-scanning; repos you changed are
   refreshed on demand if reselected.

## Safety model

- Read-only by default; `--scan-only` never prompts or writes.
- Every disable requires explicit checkbox selection plus a final confirm.
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

- Forks are the usual leak: they inherit `.github/workflows` from
  upstream, and `schedule:` cron workflows keep firing on the fork's
  default branch. Any push (e.g. a fork sync) also triggers `push`
  workflows.

## Notes

- `schedule:` (cron) workflows run only on the default branch; `push`,
  `pull_request`, and `workflow_dispatch` runs can come from any branch,
  so the tool surfaces branches per workflow.
- Account-level billing totals need the `user` scope:
  `gh auth refresh -h github.com -s user`, then
  `gh api /users/<you>/settings/billing/actions`.
- To cap risk permanently, set an Actions spending limit of $0 in
  GitHub Settings > Billing.
