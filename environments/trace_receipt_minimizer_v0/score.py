#!/usr/bin/env python3
"""Scorer for TraceReceiptMinimizerEnv v0."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any


ALLOWED_VERDICTS = {"supported", "contradicted", "unknown", "not_applicable"}
REQUIRED_TASK_FIELDS = {
    "schema_version",
    "task_id",
    "case_family",
    "claim",
    "available_artifacts",
    "available_field_paths",
    "visibility_limits",
    "allowed_verdicts",
}
REQUIRED_EXPECTED_FIELDS = {
    "task_id",
    "expected_verdict",
    "required_evidence_refs",
    "required_field_paths",
    "expected_missing_paths",
    "boundary_must_include",
    "do_not_claim_must_include",
    "minimal_evidence_sets",
}
REQUIRED_ANSWER_FIELDS = {
    "task_id",
    "claim_id",
    "selected_evidence_refs",
    "selected_field_paths",
    "verdict",
    "basis",
    "missing_evidence",
    "boundary",
    "do_not_claim",
}


@dataclass
class CaseScore:
    task_id: str
    score: float
    verdict_score: float
    evidence_score: float
    missing_evidence_score: float
    boundary_score: float
    do_not_claim_score: float
    burden_score: float
    false_support: bool
    missing_required_evidence: list[str]
    missing_required_fields: list[str]
    invented_evidence: list[str]
    evidence_burden: int
    no_false_support: bool
    boundary_quality: bool
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {
            "task_id": self.task_id,
            "score": round(self.score, 4),
            "verdict_score": round(self.verdict_score, 4),
            "evidence_score": round(self.evidence_score, 4),
            "missing_evidence_score": round(self.missing_evidence_score, 4),
            "boundary_score": round(self.boundary_score, 4),
            "do_not_claim_score": round(self.do_not_claim_score, 4),
            "burden_score": round(self.burden_score, 4),
            "false_support": self.false_support,
            "missing_required_evidence": self.missing_required_evidence,
            "missing_required_fields": self.missing_required_fields,
            "invented_evidence": self.invented_evidence,
            "evidence_burden": self.evidence_burden,
            "no_false_support": self.no_false_support,
            "boundary_quality": self.boundary_quality,
        }
        if self.error is not None:
            out["error"] = self.error
        return out


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _safe_relative(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{label} must be a non-empty string")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be relative and stay inside the case directory")
    return raw


def _validate_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of strings")
    return list(value)


def _contains_all_text(haystack_items: list[str], needles: list[str]) -> bool:
    haystack = "\n".join(haystack_items).lower()
    return all(needle.lower() in haystack for needle in needles)


def _missing_paths(answer: dict[str, Any]) -> list[str]:
    out = []
    for idx, item in enumerate(answer.get("missing_evidence", [])):
        if not isinstance(item, dict):
            raise ValueError(f"missing_evidence.{idx} must be an object")
        path = item.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError(f"missing_evidence.{idx}.path must be a non-empty string")
        why = item.get("why_it_matters")
        if why is not None and not isinstance(why, str):
            raise ValueError(f"missing_evidence.{idx}.why_it_matters must be a string when present")
        out.append(path)
    return out


def _answer_path(answers_dir: Path, task_id: str) -> Path:
    direct = answers_dir / f"{task_id}.json"
    nested = answers_dir / task_id / "answer.json"
    if direct.exists():
        return direct
    if nested.exists():
        return nested
    raise FileNotFoundError(f"missing answer for {task_id}: {direct} or {nested}")


def load_cases(cases_dir: Path) -> list[Path]:
    if not cases_dir.is_dir():
        raise ValueError(f"cases directory does not exist: {cases_dir}")
    cases = [path for path in sorted(cases_dir.iterdir()) if path.is_dir()]
    if not cases:
        raise ValueError(f"no cases found in {cases_dir}")
    return cases


def validate_task(case_dir: Path, task: dict[str, Any]) -> tuple[set[str], set[str], str]:
    missing = sorted(REQUIRED_TASK_FIELDS - set(task))
    task_id = str(task.get("task_id", case_dir.name))
    if missing:
        raise ValueError(f"{task_id}: task missing required fields: {', '.join(missing)}")
    if task["task_id"] != case_dir.name:
        raise ValueError(f"{task['task_id']}: task_id must match case directory name")
    claim = task["claim"]
    if not isinstance(claim, dict) or not isinstance(claim.get("claim_id"), str):
        raise ValueError(f"{task_id}: claim.claim_id must exist")
    allowed = set(_validate_str_list(task["allowed_verdicts"], f"{task_id}: allowed_verdicts"))
    if allowed != ALLOWED_VERDICTS:
        raise ValueError(f"{task_id}: allowed_verdicts must be exactly {sorted(ALLOWED_VERDICTS)}")
    _validate_str_list(task["visibility_limits"], f"{task_id}: visibility_limits")

    refs = set()
    artifacts = task["available_artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{task_id}: available_artifacts must be a non-empty list")
    for idx, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"{task_id}: available_artifacts.{idx} must be an object")
        rel = _safe_relative(artifact.get("path"), f"{task_id}: available_artifacts.{idx}.path")
        if not (case_dir / rel).is_file():
            raise ValueError(f"{task_id}: declared artifact does not exist: {rel}")
        refs.add(rel)

    fields = set(_validate_str_list(task["available_field_paths"], f"{task_id}: available_field_paths"))
    if not fields:
        raise ValueError(f"{task_id}: available_field_paths must be non-empty")
    return refs, fields, task["claim"]["claim_id"]


def validate_expected(
    task_id: str,
    expected: dict[str, Any],
    declared_refs: set[str],
    available_fields: set[str],
) -> None:
    missing = sorted(REQUIRED_EXPECTED_FIELDS - set(expected))
    if missing:
        raise ValueError(f"{task_id}: expected missing required fields: {', '.join(missing)}")
    if expected["task_id"] != task_id:
        raise ValueError(f"{task_id}: expected task_id mismatch")
    if expected["expected_verdict"] not in ALLOWED_VERDICTS:
        raise ValueError(f"{task_id}: invalid expected verdict: {expected['expected_verdict']}")
    required_refs = set(_validate_str_list(expected["required_evidence_refs"], f"{task_id}: required_evidence_refs"))
    undeclared = sorted(required_refs - declared_refs)
    if undeclared:
        raise ValueError(f"{task_id}: expected requires undeclared evidence refs: {', '.join(undeclared)}")
    required_fields = set(_validate_str_list(expected["required_field_paths"], f"{task_id}: required_field_paths"))
    unavailable_fields = sorted(required_fields - available_fields)
    if unavailable_fields:
        raise ValueError(f"{task_id}: expected requires unavailable field paths: {', '.join(unavailable_fields)}")
    _validate_str_list(expected["expected_missing_paths"], f"{task_id}: expected_missing_paths")
    _validate_str_list(expected["boundary_must_include"], f"{task_id}: boundary_must_include")
    _validate_str_list(expected["do_not_claim_must_include"], f"{task_id}: do_not_claim_must_include")
    minimal_sets = expected["minimal_evidence_sets"]
    if not isinstance(minimal_sets, list) or not minimal_sets:
        raise ValueError(f"{task_id}: minimal_evidence_sets must be a non-empty list")
    for idx, item in enumerate(minimal_sets):
        refs = set(_validate_str_list(item, f"{task_id}: minimal_evidence_sets.{idx}"))
        undeclared = sorted(refs - declared_refs)
        if undeclared:
            raise ValueError(f"{task_id}: minimal_evidence_sets.{idx} has undeclared refs: {', '.join(undeclared)}")


def validate_answer_shape(
    task_id: str,
    claim_id: str,
    answer: dict[str, Any],
) -> tuple[list[str], list[str], list[str], list[str]]:
    missing = sorted(REQUIRED_ANSWER_FIELDS - set(answer))
    if missing:
        raise ValueError(f"{task_id}: answer missing required fields: {', '.join(missing)}")
    if answer["task_id"] != task_id:
        raise ValueError(f"{task_id}: answer task_id mismatch")
    if answer["claim_id"] != claim_id:
        raise ValueError(f"{task_id}: answer claim_id mismatch")
    if answer["verdict"] not in ALLOWED_VERDICTS:
        raise ValueError(f"{task_id}: invalid answer verdict: {answer['verdict']}")
    if not isinstance(answer["basis"], str):
        raise ValueError(f"{task_id}: basis must be a string")
    selected_refs = _validate_str_list(answer["selected_evidence_refs"], f"{task_id}: selected_evidence_refs")
    selected_fields = _validate_str_list(answer["selected_field_paths"], f"{task_id}: selected_field_paths")
    boundary = _validate_str_list(answer["boundary"], f"{task_id}: boundary")
    do_not_claim = _validate_str_list(answer["do_not_claim"], f"{task_id}: do_not_claim")
    if not do_not_claim:
        raise ValueError(f"{task_id}: do_not_claim must be non-empty")
    _missing_paths(answer)

    return selected_refs, selected_fields, boundary, do_not_claim


def _burden_points(selected_refs: set[str], minimal_sets: list[list[str]]) -> float:
    best = 0.0
    for minimal in minimal_sets:
        minimal_set = set(minimal)
        if not minimal_set <= selected_refs:
            continue
        extra = len(selected_refs - minimal_set)
        best = max(best, max(0.0, 5.0 - float(extra)))
    return best


def score_case(case_dir: Path, answer: dict[str, Any]) -> CaseScore:
    task = _load_json(case_dir / "task.json")
    expected = _load_json(case_dir / "expected.json")
    declared_refs, available_fields, claim_id = validate_task(case_dir, task)
    task_id = task["task_id"]
    validate_expected(task_id, expected, declared_refs, available_fields)

    try:
        selected_refs, selected_fields, boundary, do_not_claim = validate_answer_shape(
            task_id,
            claim_id,
            answer,
        )
    except ValueError as exc:
        return _zero(task_id, str(exc))

    selected_ref_set = set(selected_refs)
    selected_field_set = set(selected_fields)
    invented = sorted((selected_ref_set - declared_refs) | (selected_field_set - available_fields))
    false_support = answer["verdict"] == "supported" and expected["expected_verdict"] in {"unknown", "contradicted"}
    missing_required = sorted(set(expected["required_evidence_refs"]) - selected_ref_set)
    missing_required_fields = sorted(set(expected["required_field_paths"]) - selected_field_set)
    missing_paths = set(_missing_paths(answer))
    expected_missing_paths = set(expected["expected_missing_paths"])

    if false_support:
        return _zero(task_id, "false support: supported verdict where expected verdict is not supported", false_support=True)
    if invented:
        return _zero(task_id, "answer selected evidence not visible in task: " + ", ".join(invented), invented=invented)

    verdict_score = 40.0 if answer["verdict"] == expected["expected_verdict"] else 0.0
    evidence_score = 20.0 if not missing_required and not missing_required_fields else 0.0
    missing_evidence_score = 15.0 if missing_paths == expected_missing_paths else 0.0
    boundary_score = 10.0 if _contains_all_text(boundary, expected["boundary_must_include"]) else 0.0
    do_not_claim_score = 10.0 if _contains_all_text(do_not_claim, expected["do_not_claim_must_include"]) else 0.0
    burden_score = _burden_points(selected_ref_set, expected["minimal_evidence_sets"])

    total = verdict_score + evidence_score + missing_evidence_score + boundary_score + do_not_claim_score + burden_score
    return CaseScore(
        task_id=task_id,
        score=total / 100.0,
        verdict_score=verdict_score / 40.0,
        evidence_score=evidence_score / 20.0,
        missing_evidence_score=missing_evidence_score / 15.0,
        boundary_score=boundary_score / 10.0,
        do_not_claim_score=do_not_claim_score / 10.0,
        burden_score=burden_score / 5.0,
        false_support=False,
        missing_required_evidence=missing_required,
        missing_required_fields=missing_required_fields,
        invented_evidence=[],
        evidence_burden=max(0, len(selected_ref_set) - min(len(set(item)) for item in expected["minimal_evidence_sets"])),
        no_false_support=True,
        boundary_quality=boundary_score > 0.0,
    )


def _zero(
    task_id: str,
    error: str,
    *,
    false_support: bool = False,
    invented: list[str] | None = None,
) -> CaseScore:
    return CaseScore(
        task_id=task_id,
        score=0.0,
        verdict_score=0.0,
        evidence_score=0.0,
        missing_evidence_score=0.0,
        boundary_score=0.0,
        do_not_claim_score=0.0,
        burden_score=0.0,
        false_support=false_support,
        missing_required_evidence=[],
        missing_required_fields=[],
        invented_evidence=invented or [],
        evidence_burden=0,
        no_false_support=not false_support,
        boundary_quality=False,
        error=error,
    )


def score_answers(cases_dir: Path, answers_dir: Path) -> dict[str, Any]:
    scores: list[CaseScore] = []
    for case_dir in load_cases(cases_dir):
        task_id = case_dir.name
        try:
            answer = _load_json(_answer_path(answers_dir, task_id))
        except (OSError, json.JSONDecodeError, FileNotFoundError, ValueError) as exc:
            scores.append(_zero(task_id, str(exc)))
            continue
        scores.append(score_case(case_dir, answer))

    average = sum(score.score for score in scores) / len(scores) if scores else 0.0
    return {
        "cases": len(scores),
        "average_score": round(average, 4),
        "case_scores": [score.as_dict() for score in scores],
    }


def _print_text(result: dict[str, Any]) -> None:
    print(f"cases: {result['cases']}")
    print(f"average_score: {result['average_score']:.4f}")
    for score in result["case_scores"]:
        suffix = f" error={score['error']}" if "error" in score else ""
        print(f"{score['task_id']}: {score['score']:.4f}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--answers", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable scoring output")
    args = parser.parse_args()

    try:
        result = score_answers(args.cases, args.answers)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
