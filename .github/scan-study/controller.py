#!/usr/bin/env python3
"""Finite coordinator for the Codex Security overnight reliability experiment.

No model credentials are read. GH_TOKEN grants dispatch/read access to the study
repository. Child run-name must contain the exact study_id and trial_id, separated
from other text by spaces, slashes, colons, or hyphens. The worker accepts string
inputs study_id, trial_id, scope, model and fixes effort=low itself.

The worker publishes metrics-${study_id}-${trial_id}, containing metric.json:
  {"study_id": "...", "trial_id": "t001", "scope": "diff",
   "model": "gpt-6-luna", "budget_estimated_usd": 1.23,
   "capture_available": true, ...Action outputs...}
It may nest the Action outputs under "outputs". Empty/missing/non-numeric costs
are unknown, charged at PER_SCAN_RESERVE_USD for the launch decision, never zero.

Required env: STUDY_BRANCH, STUDY_HEAD_SHA. Optional env: STUDY_ID, STUDY_REPO,
STUDY_MODELS_JSON, STUDY_OUTPUT, MAX_TRIALS, MAX_ACTIVE,
LAUNCH_WINDOW_SECONDS, POLL_SECONDS, BUDGET_USD, BUDGET_HEADROOM_USD,
PER_SCAN_RESERVE_USD. Defaults: three models x two scopes, 60 attempts, two
concurrent, five-hour launch window, $500 budget with $50 launch headroom.

Each dispatch is attempted once. Any ambiguous/failed dispatch stops all further
launches; observation continues for identifiable children. Reruns are never used.
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def estimated_cost(metric: Any) -> float | None:
    if not isinstance(metric, dict):
        return None
    if "budget_estimated_usd" in metric:
        # A present but unknown conservative estimate must not silently fall
        # back to a cheaper short-context estimate.
        return finite_number(metric["budget_estimated_usd"])
    for source in (metric, metric.get("outputs", {})):
        if not isinstance(source, dict):
            continue
        for key in ("estimated-cost", "estimated_cost", "estimatedCost"):
            if key in source:
                return finite_number(source[key])
    return None


def metric_from_archive(content: bytes, study_id: str, trial_id: str) -> dict:
    # Read a single known filename; never extract archive-controlled paths.
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        matches = [item for item in archive.infolist() if item.filename == "metric.json"]
        if len(matches) != 1 or matches[0].file_size > 1024 * 1024:
            raise ValueError("metrics archive must contain one bounded metric.json")
        metric = json.loads(archive.read(matches[0]))
    if not isinstance(metric, dict):
        raise ValueError("metric.json must be an object")
    for key, expected in (("study_id", study_id), ("trial_id", trial_id)):
        if metric.get(key) != expected:
            raise ValueError(f"metric identity mismatch: {key}")
    return metric


def name_matches(title: str, study_id: str, trial_id: str) -> bool:
    # Full non-word token boundaries avoid t001 matching t0010.
    return all(re.search(r"(?<![A-Za-z0-9_])" + re.escape(token) +
                         r"(?![A-Za-z0-9_])", title) for token in (study_id, trial_id))


@dataclass
class Config:
    repo: str
    branch: str
    study_id: str
    models: list[str]
    output: str
    head_sha: str = ""
    workflow: str = "codex-upload-sarif.yml"
    max_trials: int = 60
    max_active: int = 2
    launch_seconds: float = 5 * 60 * 60
    poll_seconds: float = 30
    budget_usd: float = 500
    headroom_usd: float = 50
    reserve_usd: float = 30

    @classmethod
    def from_env(cls) -> Config:
        study_id = os.environ.get("STUDY_ID", "scan-study-" +
                                  datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        config = cls(
            repo=os.environ.get("STUDY_REPO", "dans-oai/goof"),
            branch=os.environ["STUDY_BRANCH"], study_id=study_id,
            models=json.loads(os.environ.get("STUDY_MODELS_JSON",
                              '["gpt-6-luna","gpt-6-sol","gpt-6-astra"]')),
            output=os.environ.get("STUDY_OUTPUT", "study-output"),
            head_sha=os.environ["STUDY_HEAD_SHA"],
            max_trials=int(os.environ.get("MAX_TRIALS", "60")),
            max_active=int(os.environ.get("MAX_ACTIVE", "2")),
            launch_seconds=float(os.environ.get("LAUNCH_WINDOW_SECONDS", "18000")),
            poll_seconds=float(os.environ.get("POLL_SECONDS", "30")),
            budget_usd=float(os.environ.get("BUDGET_USD", "500")),
            headroom_usd=float(os.environ.get("BUDGET_HEADROOM_USD", "50")),
            reserve_usd=float(os.environ.get("PER_SCAN_RESERVE_USD", "30")),
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", study_id):
            raise ValueError("invalid study ID")
        if not re.fullmatch(r"[a-f0-9]{40}", config.head_sha):
            raise ValueError("STUDY_HEAD_SHA must be the immutable experiment commit")
        if not isinstance(config.models, list) or not config.models or any(
            not isinstance(model, str) or not model for model in config.models
        ):
            raise ValueError("models must be a nonempty JSON array of names")
        if len(set(config.models)) != len(config.models):
            raise ValueError("duplicate models")
        if not 1 <= config.max_trials <= 60 or not 1 <= config.max_active <= 2:
            raise ValueError("study requires 1-60 trials and 1-2 active children")
        if not 0 < config.launch_seconds <= 18000 or not 1 <= config.poll_seconds <= 60:
            raise ValueError("invalid launch/poll interval")
        if not (0 < config.reserve_usd <= config.budget_usd and
                0 <= config.headroom_usd < config.budget_usd <= 500):
            raise ValueError("invalid budget configuration")
        return config


def accounting(trials: list[dict], reserve: float) -> dict:
    known = sum(t["estimated_cost_usd"] for t in trials
                if t.get("state") == "completed" and t.get("estimated_cost_usd") is not None)
    unknown = sum(t.get("state") == "completed" and t.get("estimated_cost_usd") is None
                  for t in trials)
    pending = sum(t.get("state") != "completed" for t in trials)
    return {"known_estimated_cost_usd": known, "unknown_cost_trials": unknown,
            "charged_usd": known + unknown * reserve,
            "reserved_usd": pending * reserve,
            "active_or_unresolved_trials": pending}


def can_launch(trials: list[dict], config: Config) -> bool:
    budget = accounting(trials, config.reserve_usd)
    return (budget["charged_usd"] + budget["reserved_usd"] + config.reserve_usd
            <= config.budget_usd - config.headroom_usd)


class ApiError(RuntimeError):
    pass


class GitHub:
    def call(self, endpoint: str, *, body: dict | None = None,
             binary: bool = False) -> Any:
        command = ["gh", "api", endpoint]
        content = None
        if body is not None:
            command += ["--method", "POST", "--input", "-"]
            content = json.dumps(body).encode()
        result = subprocess.run(command, input=content, capture_output=True, timeout=90)
        if result.returncode:
            # Do not write captured diagnostics/environment/token values to artifacts.
            raise ApiError(f"GitHub request failed (exit {result.returncode})")
        if binary:
            return result.stdout
        return json.loads(result.stdout) if result.stdout.strip() else None


class Study:
    def __init__(self, config: Config, github: GitHub | None = None) -> None:
        self.config = config
        self.github = github or GitHub()
        self.output = Path(config.output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.output / "ledger.json"
        if self.ledger_path.exists():
            raise ValueError("existing ledger: refusing a duplicate controller run")
        self.started = time.monotonic()
        self.trials: list[dict] = []
        self.stop_reason: str | None = None
        self.discovery_failures = 0
        self.ledger = {"schema_version": 1, "started_at": utc_now(),
                       "config": asdict(config), "trials": self.trials,
                       "budget_note": "Estimates and reservations are not billing caps."}
        self.save()

    def write_json(self, path: Path, value: Any) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n")
        temporary.replace(path)

    def save(self) -> None:
        self.ledger.update(updated_at=utc_now(), stop_reason=self.stop_reason,
                           accounting=accounting(self.trials, self.config.reserve_usd))
        self.write_json(self.ledger_path, self.ledger)

    def event(self, message: str) -> None:
        print(f"{utc_now()} {message}", flush=True)

    def dispatch(self) -> None:
        from urllib.parse import quote
        try:
            branch = self.github.call(f"repos/{self.config.repo}/branches/" +
                                      quote(self.config.branch, safe=""))
            if branch["commit"]["sha"] != self.config.head_sha:
                self.stop_reason = "study_branch_moved"
                self.save()
                return
        except (ApiError, subprocess.TimeoutExpired, KeyError, ValueError):
            self.stop_reason = "study_branch_unverified"
            self.save()
            return
        index = len(self.trials)
        cells = [(model, scope) for model in self.config.models
                 for scope in ("diff", "repository")]
        model, scope = cells[index % len(cells)]
        trial = {"trial_id": f"t{index + 1:03d}", "model": model, "scope": scope,
                 "effort": "low", "state": "dispatching", "dispatched_at": utc_now(),
                 "estimated_cost_usd": None, "reservation_usd": self.config.reserve_usd,
                 "discovery_polls": 0}
        self.trials.append(trial)
        self.save()  # Persist the intention before a possibly ambiguous network request.
        try:
            self.github.call(f"repos/{self.config.repo}/actions/workflows/"
                             f"{self.config.workflow}/dispatches", body={
                "ref": self.config.branch,
                "inputs": {"study_id": self.config.study_id,
                           "trial_id": trial["trial_id"], "scope": scope, "model": model},
            })
            trial["state"] = "dispatched"
        except (ApiError, subprocess.TimeoutExpired):
            trial["state"] = "dispatch_uncertain"
            trial["dispatch_error"] = "dispatch result uncertain; never retried"
            self.stop_reason = "dispatch_uncertain"
        self.save()
        self.event(f"{trial['trial_id']} {scope} {model}: {trial['state']}")

    def collect(self, trial: dict, run: dict) -> None:
        directory = self.output / trial["trial_id"]
        directory.mkdir(exist_ok=True)
        run_id = run["id"]
        trial.update(state="completed", conclusion=run.get("conclusion"),
                     run_id=run_id, run_attempt=run.get("run_attempt"),
                     head_sha=run.get("head_sha"), url=run.get("html_url"),
                     completed_at=run.get("updated_at"), collection_errors=[])
        self.write_json(directory / "run.json", run)
        log_archive = None
        for filename, endpoint, binary in (
            ("jobs.json", f"repos/{self.config.repo}/actions/runs/{run_id}/jobs?per_page=100", False),
            ("logs.zip", f"repos/{self.config.repo}/actions/runs/{run_id}/logs", True),
        ):
            try:
                value = self.github.call(endpoint, binary=binary)
                if binary:
                    (directory / filename).write_bytes(value)
                    log_archive = value
                else:
                    self.write_json(directory / filename, value)
            except (ApiError, subprocess.TimeoutExpired, ValueError):
                trial["collection_errors"].append(filename)
        try:
            response = self.github.call(
                f"repos/{self.config.repo}/actions/runs/{run_id}/artifacts?per_page=100")
            self.write_json(directory / "artifacts.json", response)
            name = f"metrics-{self.config.study_id}-{trial['trial_id']}"
            matches = [a for a in response["artifacts"] if a["name"] == name and not a["expired"]]
            if len(matches) != 1:
                raise ValueError("missing or ambiguous metrics artifact")
            content = self.github.call(
                f"repos/{self.config.repo}/actions/artifacts/{matches[0]['id']}/zip", binary=True)
            metric = metric_from_archive(content, self.config.study_id, trial["trial_id"])
            if metric.get("scope") != trial["scope"] or metric.get("model") != trial["model"]:
                raise ValueError("metric cell identity mismatch")
            (directory / "metrics.zip").write_bytes(content)
            self.write_json(directory / "metric.json", metric)
            trial["estimated_cost_usd"] = estimated_cost(metric)
            trial["metric"] = metric
        except (ApiError, subprocess.TimeoutExpired, ValueError, KeyError, zipfile.BadZipFile):
            trial["collection_errors"].append("metrics")
        if trial["estimated_cost_usd"] is None:
            trial["cost_status"] = "unknown_reserved"
        else:
            trial["cost_status"] = "estimated"
        failure_class = trial.get("metric", {}).get("failure_class")
        trial["systemic_access_failure"] = failure_class in {
            "auth_error", "model_access", "model_unavailable", "quota_exhausted",
            "unsupported_model", "missing_credentials",
        }
        if log_archive and not trial["systemic_access_failure"]:
            try:
                with zipfile.ZipFile(io.BytesIO(log_archive)) as archive:
                    patterns = re.compile(
                        r"invalid_api_key|model_not_found|Incorrect API key provided|"
                        r"does not exist or you do not have access|"
                        r"do not have access to (?:this |the )?model|insufficient_quota|"
                        r"Set CODEX_SECURITY_API_KEY in Actions secrets", re.IGNORECASE)
                    trial["systemic_access_failure"] = any(
                        patterns.search(archive.read(entry).decode("utf-8", errors="replace"))
                        for entry in archive.infolist() if not entry.is_dir())
            except (ValueError, zipfile.BadZipFile):
                pass
        completed = [t for t in self.trials if t["state"] == "completed"]
        metric = trial.get("metric", {})
        capture = metric.get("capture_available")
        if "metrics" in trial["collection_errors"] or not isinstance(capture, bool):
            self.stop_reason = "metrics_observability_unavailable"
        elif not capture:
            outputs = metric.get("outputs", metric)
            exit_code = outputs.get("exit-code") if isinstance(outputs, dict) else None
            if exit_code not in (None, ""):
                self.stop_reason = "scan_capture_unavailable"
            elif len(completed) >= 2 and all(
                t.get("metric", {}).get("capture_available") is False
                for t in completed[-2:]
            ):
                self.stop_reason = "repeated_setup_without_capture"
        cells = {(model, scope) for model in self.config.models
                 for scope in ("diff", "repository")}
        observed = {(t["model"], t["scope"]) for t in completed}
        if (not self.stop_reason and cells <= observed and
                all(t.get("systemic_access_failure") for t in completed)):
            self.stop_reason = "all_cells_have_access_failures"
        self.save()
        self.event(f"{trial['trial_id']} completed: {trial['conclusion']}; "
                   f"cost={trial['estimated_cost_usd'] if trial['estimated_cost_usd'] is not None else 'unknown'}")

    def poll(self) -> None:
        pending = [t for t in self.trials if t["state"] != "completed"]
        if not pending:
            return
        try:
            # <=60 total child trials in this unique branch/study; one page suffices.
            from urllib.parse import urlencode
            query = urlencode({"branch": self.config.branch, "event": "workflow_dispatch",
                               "per_page": 100})
            response = self.github.call(
                f"repos/{self.config.repo}/actions/workflows/{self.config.workflow}/runs?{query}")
            runs = response["workflow_runs"]
            self.discovery_failures = 0
        except (ApiError, subprocess.TimeoutExpired, KeyError, ValueError):
            self.discovery_failures += 1
            if self.discovery_failures >= 3:
                self.stop_reason = "observation_unavailable"
            self.save()
            return
        for trial in pending:
            matches = [r for r in runs if name_matches(r.get("display_title", ""),
                       self.config.study_id, trial["trial_id"])]
            if len(matches) > 1:
                self.stop_reason = "ambiguous_child_identity"
                trial["state"] = "ambiguous_child_identity"
                trial["matching_run_ids"] = [r["id"] for r in matches]
                continue
            if not matches:
                trial["discovery_polls"] += 1
                if trial["discovery_polls"] >= 10:
                    trial["state"] = "unresolved_dispatch"
                    self.stop_reason = "unresolved_dispatch"
                continue
            run = matches[0]
            if run.get("head_sha") != self.config.head_sha:
                trial["target_mismatch"] = True
                self.stop_reason = "child_target_mismatch"
            trial.update(run_id=run["id"], url=run.get("html_url"),
                         github_status=run["status"])
            if run["status"] == "completed":
                self.collect(trial, run)
            else:
                trial["state"] = run["status"]
        self.save()

    def run(self) -> int:
        self.event(f"Study {self.config.study_id}: finite trials on {self.config.branch}")
        while True:
            self.poll()
            elapsed = time.monotonic() - self.started
            if elapsed >= self.config.launch_seconds and not self.stop_reason:
                self.stop_reason = "launch_window_closed"
            while (not self.stop_reason and len(self.trials) < self.config.max_trials and
                   accounting(self.trials, self.config.reserve_usd)["active_or_unresolved_trials"]
                   < self.config.max_active and can_launch(self.trials, self.config)):
                self.dispatch()
            active = [t for t in self.trials if t["state"] != "completed"]
            if len(self.trials) >= self.config.max_trials and not self.stop_reason:
                self.stop_reason = "trial_limit_reached"
            if not active:
                if self.stop_reason:
                    break
                if not can_launch(self.trials, self.config):
                    self.stop_reason = "budget_reservation_limit"
                    break
            # A child missing from listings may never become observable. Preserve
            # its reservation and unresolved status, then finish at the end of the
            # final possible worker's 45-minute time limit.
            if elapsed >= self.config.launch_seconds + 45 * 60:
                self.stop_reason = "observation_deadline"
                break
            self.save()
            time.sleep(self.config.poll_seconds)
        self.ledger["finished_at"] = utc_now()
        self.save()
        self.event(f"Finished: {self.stop_reason}; {json.dumps(self.ledger['accounting'])}")
        expected_stop = self.stop_reason in {
            "trial_limit_reached", "launch_window_closed", "budget_reservation_limit",
        }
        return 0 if expected_stop and all(t["state"] == "completed" for t in self.trials) else 2


def main() -> int:
    try:
        return Study(Config.from_env()).run()
    except (ValueError, KeyError) as error:
        print(f"Controller configuration error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
