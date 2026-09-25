#!/usr/bin/env python3
"""Study-only, post-Action metrics and allowlisted report retention.

Reads STUDY_OUTPUT_DIR/capture and RUNNER_TEMP/codex-security-reports-* only.
Never traverses the disposable CLI runtime, auth homes, databases or sessions.
Missing usage is unknown, never zero spend. All prices are USD/million tokens.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import quote, quote_plus


RATES = {
    "gpt-6-luna": (0.1, 0.01, 0.125, 0.5),
    "gpt-6-sol": (2.0, 0.2, 2.5, 10.0),
    "gpt-6-astra": (10.0, 1.0, 12.5, 50.0),
}
CANONICAL = ("scan-manifest.json", "findings.json", "coverage.json", "report.md")


def secret_forms(environment: dict) -> list[str]:
    forms = set()
    for name in ("OPENAI_API_KEY", "CODEX_API_KEY", "GITHUB_TOKEN"):
        secret = environment.get(name)
        if not secret:
            continue
        variants = [secret, base64.b64encode(secret.encode()).decode(),
                    base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                    quote(secret, safe="~()*!.'-_"), quote(secret, safe="~()*!.'-_;,/?:@&=+$#"),
                    quote_plus(secret, safe="*-._"), json.dumps(secret, ensure_ascii=False)[1:-1]]
        for value in variants:
            forms.add(value)
            forms.add(re.sub(r"%[0-9A-F]{2}", lambda match: match[0].lower(), value))
    return sorted(forms, key=len, reverse=True)


def redacted(text: str, forms: list[str]) -> str:
    for value in forms:
        text = text.replace(value, "[REDACTED]")
    return text


def contains_secret(content: bytes, forms: list[str]) -> bool:
    return any(value.encode() in content for value in forms)


def read_regular(path: Path, root: Path) -> bytes:
    relative = path.relative_to(root)
    current = root
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe_report_root")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink_withheld")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("nonregular_file_withheld")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("outside_report_root")
    return path.read_bytes()


def estimate(model: str, usage: object) -> dict:
    unknown = {"estimated_usd_range": None, "budget_estimated_usd": None,
               "cost_status": "unknown_missing_usage"}
    if model not in RATES:
        return {**unknown, "cost_status": "unknown_model_pricing"}
    if not isinstance(usage, dict):
        return unknown
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    cached = usage.get("cached_input_tokens", 0)
    writes = usage.get("cache_write_input_tokens", usage.get("cache_write_tokens", 0))
    legacy_writes = usage.get("cache_write_tokens")
    if writes == 0 and isinstance(legacy_writes, int) and legacy_writes > 0:
        writes = legacy_writes
    values = [input_tokens, cached, writes, output_tokens]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        return {**unknown, "cost_status": "unknown_invalid_usage"}
    if cached + writes > input_tokens:
        return {**unknown, "cost_status": "unknown_invalid_usage"}
    writes_reported = usage.get("cache_write_input_tokens_reported") is not False and (
        "cache_write_input_tokens" in usage or "cache_write_tokens" in usage)
    rates = RATES[model]
    long_rates = [rates[0] * 2, rates[1] * 2, rates[2] * 2, rates[3] * 1.5]
    uncached = input_tokens - cached - writes
    minimum = (uncached * rates[0] + cached * rates[1] + writes * rates[2] + output_tokens * rates[3]) / 1e6
    # Without cache-write reporting, uncached input can include billed writes.
    maximum = (uncached * (long_rates[0] if writes_reported else max(long_rates[0], long_rates[2]))
               + cached * long_rates[1] + writes * long_rates[2] + output_tokens * long_rates[3]) / 1e6
    return {"estimated_usd_range": {"min": minimum, "max": maximum},
            "budget_estimated_usd": maximum, "cost_status": "estimated_from_aggregate_tokens",
            "usage": {"input_tokens": input_tokens, "cached_input_tokens": cached,
                      "cache_write_input_tokens": writes, "output_tokens": output_tokens,
                      "cache_write_input_tokens_reported": writes_reported}}


def result_document(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("turn"), dict) or isinstance(value.get("manifest"), dict):
        return value
    for key in ("data", "result"):
        nested = result_document(value.get(key))
        if nested:
            return nested
    return None


def reports(output: Path, environment: dict, forms: list[str]) -> tuple[list, list]:
    retained = []
    withheld = []
    temp = Path(environment.get("RUNNER_TEMP", "/nonexistent-runner-temp")).resolve()
    for root in sorted(temp.glob("codex-security-reports-*")):
        if root.is_symlink() or not root.is_dir():
            withheld.append({"root": root.name, "reason": "unsafe_report_root"})
            continue
        candidates = [root / name for name in CANONICAL]
        candidates.append(root / "checkpoint-head.json")
        checkpoints = root / "checkpoints"
        if checkpoints.is_symlink():
            withheld.append({"root": root.name, "path": "checkpoints", "reason": "symlink_withheld"})
        elif checkpoints.is_dir():
            candidates.extend(path for path in checkpoints.iterdir() if re.fullmatch(r"[a-f0-9]{64}\.json", path.name))
        drafts = root / "drafts"
        if drafts.is_symlink():
            withheld.append({"root": root.name, "path": "drafts", "reason": "symlink_withheld"})
        elif drafts.is_dir():
            candidates.extend(path for path in drafts.iterdir() if re.fullmatch(r"[a-f0-9-]{36}\.checkpoint\.json", path.name))
        for source in candidates:
            relative = source.relative_to(root)
            if not source.exists() and not source.is_symlink():
                continue
            try:
                content = read_regular(source, root)
                if contains_secret(content, forms):
                    raise ValueError("known_credential_withheld")
                destination = output / "reports" / root.name / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                retained.append({"root": root.name, "path": str(relative), "bytes": len(content),
                                 "saved_path": str(destination.relative_to(output))})
            except (OSError, ValueError) as error:
                withheld.append({"root": root.name, "path": str(relative),
                                 "reason": str(error) if isinstance(error, ValueError) else type(error).__name__})
    return retained, withheld


def classify(coverage: str | None, exit_code: object, action_outcome: str, scan_status: str | None) -> str:
    if coverage in ("partial", "unknown"):
        return "incomplete_coverage"
    if coverage == "complete":
        if exit_code == 1:
            return "complete_findings_gate"
        if exit_code == 0:
            return "complete" if action_outcome == "success" else "complete_scan_action_failure"
        return "scan_error_with_complete_coverage"
    if scan_status == "skipped":
        return "skipped"
    return "no_confirmed_complete_scan"


def failure_class(stderr: str) -> str | None:
    for pattern, label in (
        (r'classification="cost_limit_exceeded"|Scan stopped: (?:short-context budget baseline|estimated cost) [^\n]+ exceeded [^\n]+ limit|Reached the [^\n]+ cost limit\. More issues may remain\.', "estimated_budget_limit"),
        (r"insufficient_quota|quota (?:exceeded|exhausted)|credits? (?:exhausted|depleted)|usage limit", "quota_exhausted"),
        (r"missing.{0,30}(?:api.key|credentials)|set (?:openai_api_key|codex_api_key)", "missing_credentials"),
        (r"unsupported model|model.{0,40}not supported", "unsupported_model"),
        (r"model_not_found|model.{0,40}(?:not found|does not exist)", "model_unavailable"),
        (r"model access|(?:not authorized|do not have access).{0,60}model", "model_access"),
        (r"\b401\b|unauthorized|invalid.{0,15}(?:api.key|authentication|credentials)", "auth_error"),
    ):
        if re.search(pattern, stderr, flags=re.IGNORECASE):
            return label
    return None


def main(environment: dict | None = None) -> dict:
    environment = dict(os.environ if environment is None else environment)
    os.umask(0o077)
    output = Path(environment["STUDY_OUTPUT_DIR"])
    output.mkdir(parents=True, exist_ok=True)
    forms = secret_forms(environment)
    try:
        outputs = json.loads(redacted(environment.get("ACTION_OUTPUTS") or "{}", forms))
        if not isinstance(outputs, dict):
            outputs = {}
    except ValueError:
        outputs = {}
    model = environment.get("STUDY_MODEL", "")
    captures = []
    captured_results = []
    stderr_text = []
    capture_dir = output / "capture"
    if capture_dir.is_dir() and not capture_dir.is_symlink():
        for metadata_path in sorted(capture_dir.glob("scan-*.process.json")):
            capture = {"metadata_file": metadata_path.name}
            try:
                metadata = json.loads(read_regular(metadata_path, capture_dir))
                capture.update(metadata)
                stdout_name = metadata_path.name.removesuffix(".process.json") + ".stdout.txt"
                stderr_name = metadata_path.name.removesuffix(".process.json") + ".stderr.txt"
                raw = read_regular(capture_dir / stdout_name, capture_dir)
                stderr_text.append(read_regular(capture_dir / stderr_name, capture_dir).decode("utf-8", errors="replace"))
                capture["capture_available"] = metadata.get("observation_failed") is False
                document = result_document(json.loads(raw))
                captured_results.append(document)
                usage = document.get("turn", {}).get("usage") if document else None
                capture.update(estimate(model, usage))
                capture["stdout_parse_status"] = "result" if document else "no_result_document"
            except (OSError, ValueError, TypeError, AttributeError):
                capture.update(estimate(model, None), stdout_parse_status="unavailable_or_invalid")
                captured_results.append(None)
            capture.setdefault("capture_available", False)
            captures.append(capture)
    retained, withheld = reports(output, environment, forms)
    canonical_documents = {}
    report_parse_errors = []
    for entry in retained:
        if entry["path"] not in CANONICAL or not entry["path"].endswith(".json"):
            continue
        try:
            document = json.loads((output / entry["saved_path"]).read_bytes())
            canonical_documents.setdefault(entry["root"], {})[entry["path"]] = document
        except ValueError:
            report_parse_errors.append(entry["saved_path"])
    scan_records = []
    for root, documents in canonical_documents.items():
        manifest = documents.get("scan-manifest.json", {})
        scan = manifest.get("scan", {}) if isinstance(manifest, dict) else {}
        coverage = documents.get("coverage.json", {})
        findings = documents.get("findings.json", {})
        scan = scan if isinstance(scan, dict) else {}
        coverage = coverage if isinstance(coverage, dict) else {}
        findings = findings if isinstance(findings, dict) else {}
        finding_list = findings.get("findings")
        deferred = coverage.get("deferred")
        scan_records.append({"report_root": root, "scan_id": scan.get("id") or coverage.get("scanId"),
                             "manifest_status": scan.get("status"), "coverage": coverage.get("completeness"),
                             "finding_count": len(finding_list) if isinstance(finding_list, list) else None,
                             "deferred_count": len(deferred) if isinstance(deferred, list) else None,
                             "discarded_finding_count": sum(1 for item in (deferred if isinstance(deferred, list) else [])
                                 if isinstance(item, dict) and str(item.get("id", "")).startswith("discarded-finding-")),
                             "target": scan.get("target"), "producer": scan.get("producer"),
                             "canonical_documents_present": all(name in documents for name in CANONICAL[:3])})
    if not scan_records:
        for result in captured_results:
            if not result:
                continue
            coverage_document = result.get("coverage", {})
            manifest_document = result.get("manifest", {})
            findings_document = result.get("findings", {})
            scan = manifest_document.get("scan", {}) if isinstance(manifest_document, dict) else {}
            scan = scan if isinstance(scan, dict) else {}
            finding_list = findings_document.get("findings") if isinstance(findings_document, dict) else None
            scan_records.append({"source": "captured_stdout", "scan_id": scan.get("id"),
                                 "manifest_status": scan.get("status"),
                                 "coverage": coverage_document.get("completeness") if isinstance(coverage_document, dict) else None,
                                 "finding_count": len(finding_list) if isinstance(finding_list, list) else None,
                                 "canonical_documents_present": False})
    coverage = scan_records[0].get("coverage") if len(scan_records) == 1 else None
    if any(scan.get("coverage") in ("partial", "unknown") for scan in scan_records):
        coverage = "partial"
    exit_code = captures[0].get("exit_code") if len(captures) == 1 else None
    if exit_code is None:
        try:
            exit_code = int(outputs.get("exit-code", ""))
        except (ValueError, TypeError):
            pass
    outcome = environment.get("ACTION_OUTCOME", environment.get("STUDY_ACTION_OUTCOME", "unknown"))
    failure = failure_class("\n".join(stderr_text))
    signals = sorted({capture.get("signal") or ({130: "SIGINT", 143: "SIGTERM"}.get(capture.get("exit_code")))
                      for capture in captures
                      if capture.get("signal") or capture.get("exit_code") in (130, 143)})
    timeout_observed = outcome in ("timed_out", "timeout") or environment.get("STUDY_TIMED_OUT", "").lower() == "true"
    budget_limited = failure == "estimated_budget_limit"
    classification = (
        "censored_estimated_budget_limit" if budget_limited
        else "censored_timeout" if timeout_observed
        else "censored_signal" if signals
        else classify(coverage, exit_code, outcome, outputs.get("scan-status"))
    )
    costs_known = bool(captures) and all(capture.get("budget_estimated_usd") is not None for capture in captures)
    cost_range = {"min": sum(capture["estimated_usd_range"]["min"] for capture in captures),
                  "max": sum(capture["estimated_usd_range"]["max"] for capture in captures)} if costs_known else None
    metric = {
        "study_id": environment.get("STUDY_ID"), "trial_id": environment.get("TRIAL_ID", environment.get("STUDY_TRIAL_ID")),
        "model": model, "scope": environment.get("STUDY_SCOPE"), "effort": environment.get("STUDY_EFFORT", "low"),
        "run_id": environment.get("GITHUB_RUN_ID"), "run_attempt": environment.get("GITHUB_RUN_ATTEMPT"),
        "head_sha": environment.get("STUDY_HEAD_SHA", outputs.get("scanned-sha")),
        "base_sha": environment.get("STUDY_BASE_SHA"), "action_sha": environment.get("STUDY_ACTION_SHA"),
        "cli_version": environment.get("STUDY_CLI_VERSION"), "workflow_sha": environment.get("GITHUB_SHA"),
        "collected_at": datetime.now(timezone.utc).isoformat(), "action_outcome": outcome, "outputs": outputs,
        "capture_count": len(captures), "capture_available": bool(captures) and all(capture["capture_available"] for capture in captures),
        "captures": captures, "scans": scan_records, "failure_class": failure,
        "censored": budget_limited or timeout_observed or bool(signals),
        "censoring": {"estimated_budget_limit": budget_limited, "signal_terminated": bool(signals),
                      "signals": signals, "timeout_observed": timeout_observed,
                      "timeout_status": "observed" if timeout_observed else "unknown_signal_reason" if signals else "not_observed",
                      "note": "A termination signal alone does not establish whether the Action timed out or was canceled."},
        "coverage": coverage, "cli_exit_code": exit_code,
        "classification": classification,
        "estimated_usd_range": cost_range, "budget_estimated_usd": cost_range["max"] if cost_range else None,
        "cost_status": "estimated_from_aggregate_tokens" if costs_known else "unknown_missing_or_invalid_usage",
        "pricing": {"source": "https://developers.openai.com/api/docs/pricing", "service_tier": "standard",
                    "short_context_usd_per_million_input_cached_write_output": RATES.get(model),
                    "long_context_multipliers_input_cached_write_output": [2, 2, 2, 1.5],
                    "note": "Aggregate tokens do not identify per-request context tier; budget uses the upper estimate. Not a billing total."},
        "reports_retained": retained, "reports_withheld": withheld, "report_parse_errors": report_parse_errors,
    }
    # Diagnostic fields are redacted; canonical reports above are withheld intact.
    (output / "metric.json").write_text(redacted(json.dumps(metric, indent=2, sort_keys=True), forms) + "\n")
    return metric


if __name__ == "__main__":
    metric = main()
    print(json.dumps({key: metric[key] for key in ("classification", "capture_count", "budget_estimated_usd", "cost_status")}))
