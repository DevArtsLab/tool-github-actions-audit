# tool-github-actions-audit

Interactive auditor for GitHub Actions usage across a user or org account.
Built for finding "minute eaters": forks and stale repos whose inherited or
scheduled workflows keep burning Actions minutes.

## Requirements

- `gh` CLI, authenticated (`gh auth login`)
- `uv` (deps auto-resolve via inline script metadata)
  or Python 3.10+ with `questionary` and `rich`

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
   active workflow **names** (CI, Cron, Staging, ...), and the
   branches/events seen in the 50 most recent runs.
2. You checkbox-select repos to inspect.
3. Per repo: a detail table shows each workflow's state, trigger events,
   branches, last run, and billable minutes (via the workflow `timing`
   endpoint, which reports real per-OS billable ms).
4. You checkbox-select which workflows to disable, or choose
   "Disable ALL GitHub Actions on this repo" for a full kill switch.
5. A final confirmation lists every pending change before anything runs.

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
