"""Security regression tests for gha_audit.py (GitHub issue #1).

Covers: YAML parsing DoS, Rich markup injection, silent API failures,
--owner flag injection, heuristic labeling, and pagination.
Run: uv run --with pytest python -m pytest test_gha_audit.py -v
"""

import io
import subprocess

import pytest
from rich.console import Console

import gha_audit as ga

EVIL_NAME = "[/x][link=https://evil.example]click[/]\x1b[2J"


def _completed(rc=0, out="", err=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)


class TestYamlParsingDoS:
    """HIGH: malformed workflow YAML must never crash the audit."""

    @pytest.mark.parametrize(
        "raw",
        [
            "- a\n- b\n",  # top-level list, not dict
            "on: 5\n",  # `on:` key -> True, int value
            "on: true\n",  # `on:` key -> True, bool value
            "on: [[a]]\n",  # unhashable list item
            "on: push\n",
            "on:\n  push:\n    branches: main\n",  # branches as string
            "on:\n  schedule: {cron: '0 0 * * *'}\n",  # schedule not a list
            "on:\n  push: [a, b]\n",  # push config as list
            "!!!not yaml [{\n",
            "",
            "just a string",
            "5",
            "a" * 5000,
        ],
    )
    def test_malformed_yaml_never_crashes(self, raw):
        out = ga.analyze_workflow("o/r", raw)
        assert isinstance(out["trigger"], str)
        assert isinstance(out["tags"], list)
        assert isinstance(out["effects"], list)

    def test_deeply_nested_yaml(self):
        raw = "on: push\na:\n" + "".join(f"{'  ' * i}b:\n" for i in range(1, 400))
        out = ga.analyze_workflow("o/r", raw)
        assert "trigger" in out

    def test_analyzer_exception_caught_in_scan(self, monkeypatch):
        monkeypatch.setattr(
            ga,
            "gh_json",
            lambda a: (
                (
                    {
                        "total_count": 1,
                        "workflows": [
                            {
                                "id": 1,
                                "name": "X",
                                "path": ".github/workflows/x.yml",
                                "state": "active",
                            }
                        ],
                    },
                    None,
                )
                if "workflows" in a[0]
                else ({"total_count": 0, "workflow_runs": []}, None)
            ),
        )
        monkeypatch.setattr(ga, "fetch_workflow_yaml", lambda *a: "x: y")
        monkeypatch.setattr(
            ga,
            "analyze_workflow",
            lambda *a: (_ for _ in ()).throw(RecursionError()),
        )
        info = ga.scan_repo("o/r", "2026-01-01", "2026-02-01")
        assert info["error"] is None
        assert "unparseable" in info["workflows"][0]["trigger"]


class TestMarkupInjection:
    """MEDIUM: untrusted strings must not be parsed as Rich markup."""

    def test_disp_escapes_markup_and_controls(self):
        out = ga.disp(EVIL_NAME)
        assert "\\[" in out  # markup escaped
        assert "\x1b" not in out  # control chars stripped

    def _evil_repo(self, wf_overrides=None):
        wf = {
            "id": 1,
            "name": EVIL_NAME,
            "path": ".github/workflows/x.yml",
            "state": "active",
            "tags": [],
            "effects": ["does [red]evil[/] things"],
        }
        wf.update(wf_overrides or {})
        return {
            "full_name": "o/evil",
            "workflows": [wf],
            "runs_total": 1,
            "runs_30d": 1,
            "runs": [
                {
                    "workflow_id": 1,
                    "head_branch": EVIL_NAME,
                    "event": EVIL_NAME,
                    "created_at": "2026-01-01",
                }
            ],
            "error": None,
            "errors": [],
        }

    def test_scan_table_renders_evil_input(self, monkeypatch):
        monkeypatch.setattr(ga, "console", Console(file=io.StringIO(), width=140))
        meta = {
            "o/evil": {
                "nameWithOwner": "o/evil",
                "isFork": True,
                "isPrivate": False,
            }
        }
        # Would raise rich.errors.MarkupError if unescaped.
        ga.print_scan_table([self._evil_repo()], meta, "s", "e")

    def test_detail_table_renders_evil_input(self, monkeypatch):
        monkeypatch.setattr(ga, "console", Console(file=io.StringIO(), width=140))
        monkeypatch.setattr(ga, "repo_actions_enabled", lambda n: True)
        monkeypatch.setattr(ga, "billable_minutes", lambda n, i: 1.5)
        ga.print_repo_detail(self._evil_repo())


class TestSilentApiFailures:
    """MEDIUM: API errors must surface, not look like 'no data'."""

    def test_gh_json_returns_error_text(self, monkeypatch):
        monkeypatch.setattr(
            ga.subprocess,
            "run",
            lambda *a, **k: _completed(rc=1, err="HTTP 429: rate limited"),
        )
        data, err = ga.gh_json(["x"])
        assert data is None
        assert "429" in err

    def test_gh_json_bad_json(self, monkeypatch):
        monkeypatch.setattr(
            ga.subprocess, "run", lambda *a, **k: _completed(out="<<not json")
        )
        data, err = ga.gh_json(["x"])
        assert data is None
        assert err

    def test_gh_json_ok(self, monkeypatch):
        monkeypatch.setattr(
            ga.subprocess, "run", lambda *a, **k: _completed(out='{"a": 1}')
        )
        data, err = ga.gh_json(["x"])
        assert data == {"a": 1}
        assert err is None

    def test_scan_repo_records_partial_failures(self, monkeypatch):
        def fake_gh(args):
            if "workflows" in args[0]:
                return {
                    "total_count": 1,
                    "workflows": [
                        {
                            "id": 1,
                            "name": "CI",
                            "path": ".github/workflows/ci.yml",
                            "state": "active",
                        }
                    ],
                }, None
            return None, "HTTP 429: rate limited"  # runs + window calls fail

        monkeypatch.setattr(ga, "gh_json", fake_gh)
        monkeypatch.setattr(ga, "fetch_workflow_yaml", lambda *a: "on: push")
        info = ga.scan_repo("o/r", "2026-01-01", "2026-02-01")
        assert info["error"] is None
        assert len(info["errors"]) == 2  # both failed calls recorded

    def test_scan_repo_fatal_failure(self, monkeypatch):
        monkeypatch.setattr(ga, "gh_json", lambda a: (None, "HTTP 500"))
        info = ga.scan_repo("o/r", "s", "e")
        assert info["error"]
        assert "500" in info["error"]


class TestOwnerValidation:
    """LOW: owner must not be able to inject gh flags."""

    @pytest.mark.parametrize(
        "owner", ["foo", "my-org", "a", "0x", "user-name-1", "x" * 39]
    )
    def test_valid(self, owner):
        assert ga.valid_owner(owner)

    @pytest.mark.parametrize(
        "owner",
        ["--help", "-x", "", "a b", "x" * 40, "-lead", "a_b", "a.b", "a/b"],
    )
    def test_invalid(self, owner):
        assert not ga.valid_owner(owner)


class TestPagination:
    """LOW: workflow listing must request full pages."""

    def test_workflows_endpoint_requests_per_page_100(self, monkeypatch):
        seen = []

        def fake_gh(args):
            seen.append(args[0])
            if "workflows" in args[0]:
                return {"total_count": 0, "workflows": []}, None
            return {"total_count": 0, "workflow_runs": []}, None

        monkeypatch.setattr(ga, "gh_json", fake_gh)
        monkeypatch.setattr(ga, "fetch_workflow_yaml", lambda *a: None)
        ga.scan_repo("o/r", "s", "e")
        assert any("per_page=100" in c for c in seen if "workflows" in c)

    def test_workflow_list_truncation_recorded(self, monkeypatch):
        def fake_gh(args):
            if "workflows" in args[0]:
                # API claims 150 workflows but page held only 100.
                return {
                    "total_count": 150,
                    "workflows": [
                        {
                            "id": i,
                            "name": f"w{i}",
                            "path": "x.yml",
                            "state": "active",
                        }
                        for i in range(100)
                    ],
                }, None
            return {"total_count": 0, "workflow_runs": []}, None

        monkeypatch.setattr(ga, "gh_json", fake_gh)
        monkeypatch.setattr(ga, "fetch_workflow_yaml", lambda *a: None)
        info = ga.scan_repo("o/r", "s", "e")
        assert any("truncated" in e for e in info["errors"])
