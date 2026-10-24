"""Evaluation harness for HackerRank Orchestrate: Ghost Data Still Exists.

Computes exact case-level, step-level, field-level, and sequence-order metrics
against reference truth (e.g. dataset/sample_output.csv).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class StepMismatch:
    step_no: int
    field_name: str
    expected: Any
    actual: Any


@dataclass
class CaseEvaluation:
    case_id: str
    status_match: bool
    expected_status: str
    actual_status: str
    step_count_expected: int
    step_count_actual: int
    sequence_match: bool
    field_mismatches: list[StepMismatch] = field(default_factory=list)

    @property
    def is_exact_match(self) -> bool:
        return (
            self.status_match
            and self.step_count_expected == self.step_count_actual
            and self.sequence_match
            and len(self.field_mismatches) == 0
        )


@dataclass
class EvaluationSummary:
    total_cases: int = 0
    status_correct: int = 0
    exact_case_matches: int = 0
    sequence_matches: int = 0
    total_steps_expected: int = 0
    total_steps_actual: int = 0
    total_fields_checked: int = 0
    total_fields_matched: int = 0
    case_results: list[CaseEvaluation] = field(default_factory=list)

    @property
    def status_accuracy(self) -> float:
        return (self.status_correct / self.total_cases * 100.0) if self.total_cases > 0 else 0.0

    @property
    def exact_case_accuracy(self) -> float:
        return (self.exact_case_matches / self.total_cases * 100.0) if self.total_cases > 0 else 0.0

    @property
    def sequence_accuracy(self) -> float:
        return (self.sequence_matches / self.total_cases * 100.0) if self.total_cases > 0 else 0.0

    @property
    def field_accuracy(self) -> float:
        return (self.total_fields_matched / self.total_fields_checked * 100.0) if self.total_fields_checked > 0 else 0.0


def load_output_csv(file_path: str | Path) -> dict[str, tuple[str, list[dict[str, Any]]]]:
    """Load and parse output.csv file.

    Returns:
        dict mapping case_id -> (deletion_status, parsed_steps_list)
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Output file not found: {path}")

    cases = {}
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required_cols = {"case_id", "deletion_status", "steps_json"}
        if not required_cols.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"CSV missing required columns: {required_cols - set(reader.fieldnames or [])}")

        for row in reader:
            case_id = row["case_id"].strip()
            status = row["deletion_status"].strip()
            raw_json = row.get("steps_json", "[]").strip()
            try:
                steps = json.loads(raw_json) if raw_json else []
                if not isinstance(steps, list):
                    steps = []
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse steps_json for {case_id}: {e}", file=sys.stderr)
                steps = []
            cases[case_id] = (status, steps)

    return cases


def evaluate_predictions(
    truth_cases: dict[str, tuple[str, list[dict[str, Any]]]],
    pred_cases: dict[str, tuple[str, list[dict[str, Any]]]],
) -> EvaluationSummary:
    """Evaluate predicted cases against ground truth."""
    summary = EvaluationSummary()
    summary.total_cases = len(truth_cases)

    # Standard fields checked per step
    step_fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

    for case_id in sorted(truth_cases.keys()):
        expected_status, expected_steps = truth_cases[case_id]
        if case_id not in pred_cases:
            summary.case_results.append(
                CaseEvaluation(
                    case_id=case_id,
                    status_match=False,
                    expected_status=expected_status,
                    actual_status="MISSING",
                    step_count_expected=len(expected_steps),
                    step_count_actual=0,
                    sequence_match=False,
                )
            )
            summary.total_steps_expected += len(expected_steps)
            continue

        actual_status, actual_steps = pred_cases[case_id]
        status_match = (expected_status == actual_status)
        if status_match:
            summary.status_correct += 1

        summary.total_steps_expected += len(expected_steps)
        summary.total_steps_actual += len(actual_steps)

        field_mismatches = []
        sequence_match = True

        if len(expected_steps) != len(actual_steps):
            sequence_match = False

        min_len = min(len(expected_steps), len(actual_steps))
        for idx in range(min_len):
            exp_step = expected_steps[idx]
            act_step = actual_steps[idx]

            # Check field-by-field
            for f in step_fields:
                summary.total_fields_checked += 1
                exp_val = exp_step.get(f)
                act_val = act_step.get(f)
                if exp_val == act_val:
                    summary.total_fields_matched += 1
                else:
                    sequence_match = False
                    field_mismatches.append(
                        StepMismatch(
                            step_no=idx + 1,
                            field_name=f,
                            expected=exp_val,
                            actual=act_val,
                        )
                    )

        # Unmatched extra steps count against field accuracy
        extra_steps = abs(len(expected_steps) - len(actual_steps))
        summary.total_fields_checked += extra_steps * len(step_fields)

        if sequence_match and (len(expected_steps) == len(actual_steps)):
            summary.sequence_matches += 1

        case_eval = CaseEvaluation(
            case_id=case_id,
            status_match=status_match,
            expected_status=expected_status,
            actual_status=actual_status,
            step_count_expected=len(expected_steps),
            step_count_actual=len(actual_steps),
            sequence_match=sequence_match,
            field_mismatches=field_mismatches,
        )
        summary.case_results.append(case_eval)

        if case_eval.is_exact_match:
            summary.exact_case_matches += 1

    return summary


def print_evaluation_report(summary: EvaluationSummary, verbose_failures: bool = True) -> None:
    """Print formatted evaluation report to stdout."""
    print("=" * 78)
    print(" HACKERRANK ORCHESTRATE: DELETION AUDIT EVALUATION REPORT")
    print("=" * 78)
    print(f"Total Cases Evaluated:       {summary.total_cases}")
    print(f"Exact Full-Case Matches:     {summary.exact_case_matches} / {summary.total_cases} ({summary.exact_case_accuracy:.2f}%)")
    print(f"Status Accuracy:             {summary.status_correct} / {summary.total_cases} ({summary.status_accuracy:.2f}%)")
    print(f"Sequence Order Accuracy:     {summary.sequence_matches} / {summary.total_cases} ({summary.sequence_accuracy:.2f}%)")
    print(f"Field-Level Precision:       {summary.total_fields_matched} / {summary.total_fields_checked} ({summary.field_accuracy:.2f}%)")
    print(f"Total Expected Steps:        {summary.total_steps_expected}")
    print(f"Total Actual Steps:          {summary.total_steps_actual}")
    print("=" * 78)

    failures = [c for c in summary.case_results if not c.is_exact_match]
    if not failures:
        print("PERFECT SCORE: All cases matched ground truth with 100.0% precision!")
        print("=" * 78)
        return

    print(f"\nFailed Cases ({len(failures)} total):")
    for f in failures:
        print(f"  [{f.case_id}] Status Match: {f.status_match} (Expected: {f.expected_status}, Actual: {f.actual_status})")
        print(f"            Steps: expected {f.step_count_expected}, got {f.step_count_actual} | Sequence Match: {f.sequence_match}")
        if verbose_failures and f.field_mismatches:
            print("            Mismatches:")
            for m in f.field_mismatches[:5]:  # limit to first 5 per case
                print(f"              - Step {m.step_no} field '{m.field_name}': expected '{m.expected}', got '{m.actual}'")
            if len(f.field_mismatches) > 5:
                print(f"              - ... and {len(f.field_mismatches) - 5} more mismatches")
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(description="Evaluate deletion audit predictions against ground truth.")
    parser.add_argument(
        "--truth",
        type=str,
        default="dataset/sample_output.csv",
        help="Path to ground truth CSV (default: dataset/sample_output.csv)",
    )
    parser.add_argument(
        "--pred",
        type=str,
        default=None,
        help="Path to prediction CSV (if omitted, tests truth against itself as sanity check)",
    )
    parser.add_argument(
        "--quiet-failures",
        action="store_true",
        help="Suppress detailed mismatch logs for failing cases",
    )
    args = parser.parse_args()

    truth_path = Path(args.truth)
    pred_path = Path(args.pred) if args.pred else truth_path

    print(f"Evaluating: {pred_path} against truth: {truth_path}\n")

    truth_cases = load_output_csv(truth_path)
    pred_cases = load_output_csv(pred_path)

    summary = evaluate_predictions(truth_cases, pred_cases)
    print_evaluation_report(summary, verbose_failures=not args.quiet_failures)

    if summary.exact_case_accuracy < 100.0 and args.pred is not None:
        sys.exit(1)


if __name__ == "__main__":
    main()
