#!/usr/bin/env python3
"""Regression tests for TraceReceiptMinimizerEnv v0 scoring."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from score import score_answers, score_case


ROOT = Path(__file__).resolve().parent
CASES = ROOT / "cases"
ANSWERS = ROOT / "answers"


def _by_task(result: dict) -> dict[str, dict]:
    return {item["task_id"]: item for item in result["case_scores"]}


def _load_answer(answer_dir: Path, task_id: str) -> dict:
    return json.loads((answer_dir / f"{task_id}.json").read_text(encoding="utf-8"))


class TraceReceiptMinimizerScoreTests(unittest.TestCase):
    def test_gold_scores_perfectly(self) -> None:
        result = score_answers(CASES, ANSWERS / "gold")
        self.assertEqual(result["cases"], 3)
        self.assertEqual(result["average_score"], 1.0)
        self.assertTrue(all(item["score"] == 1.0 for item in result["case_scores"]))

    def test_false_support_baseline_hard_zeroes_unknown_and_contradicted_cases(self) -> None:
        result = score_answers(CASES, ANSWERS / "baselines" / "naive_supported")
        scores = _by_task(result)
        self.assertEqual(result["average_score"], 0.2667)
        self.assertEqual(scores["001_cloudtrail_revocation_missing_unknown"]["score"], 0.0)
        self.assertTrue(scores["001_cloudtrail_revocation_missing_unknown"]["false_support"])
        self.assertEqual(scores["003_cloudtrail_revocation_before_action_contradicted"]["score"], 0.0)
        self.assertTrue(scores["003_cloudtrail_revocation_before_action_contradicted"]["false_support"])

    def test_inferred_absence_baseline_hard_zeroes_unknown_and_contradicted_cases(self) -> None:
        result = score_answers(CASES, ANSWERS / "baselines" / "infer_revocation_absence")
        scores = _by_task(result)
        self.assertEqual(result["average_score"], 0.2)
        self.assertEqual(scores["001_cloudtrail_revocation_missing_unknown"]["score"], 0.0)
        self.assertTrue(scores["001_cloudtrail_revocation_missing_unknown"]["false_support"])
        self.assertEqual(scores["003_cloudtrail_revocation_before_action_contradicted"]["score"], 0.0)
        self.assertTrue(scores["003_cloudtrail_revocation_before_action_contradicted"]["false_support"])

    def test_evidence_burden_and_under_evidence_are_separated(self) -> None:
        gold = score_answers(CASES, ANSWERS / "gold")
        full_trace = score_answers(CASES, ANSWERS / "baselines" / "full_trace")
        event_only = score_answers(CASES, ANSWERS / "baselines" / "event_only")
        self.assertEqual(gold["average_score"], 1.0)
        self.assertEqual(full_trace["average_score"], 0.98)
        self.assertEqual(event_only["average_score"], 0.3333)
        self.assertLess(full_trace["average_score"], gold["average_score"])
        self.assertGreater(full_trace["average_score"], event_only["average_score"])

    def test_invalid_verdict_vocabulary_is_zero(self) -> None:
        task_id = "001_cloudtrail_revocation_missing_unknown"
        answer = _load_answer(ANSWERS / "gold", task_id)
        answer["verdict"] = "probably"
        score = score_case(CASES / task_id, answer)
        self.assertEqual(score.score, 0.0)
        self.assertIn("invalid answer verdict", score.error or "")

    def test_invented_field_path_is_zero(self) -> None:
        task_id = "001_cloudtrail_revocation_missing_unknown"
        answer = _load_answer(ANSWERS / "gold", task_id)
        answer["selected_field_paths"].append("authorization.revocation_stream.checked_at")
        score = score_case(CASES / task_id, answer)
        self.assertEqual(score.score, 0.0)
        self.assertIn("not visible", score.error or "")

    def test_required_field_paths_are_load_bearing(self) -> None:
        task_id = "002_cloudtrail_revocation_explicit_null_supported"
        answer = _load_answer(ANSWERS / "gold", task_id)
        answer["selected_field_paths"] = []
        score = score_case(CASES / task_id, answer)
        self.assertEqual(score.score, 0.8)
        self.assertEqual(score.evidence_score, 0.0)
        self.assertIn("authorization.revoked_at", score.missing_required_fields)


if __name__ == "__main__":
    unittest.main()
