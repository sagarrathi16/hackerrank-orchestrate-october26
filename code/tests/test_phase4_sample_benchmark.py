import sys
from pathlib import Path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

"""Benchmark test for Phase 4: Policy Engine against all 32 sample cases."""

import csv
import json
import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path for direct invocation
repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.classifier import IntentClassifier
from code.evaluation.main import evaluate_predictions, load_output_csv
from code.identity import IdentityResolver
from code.ingest.csv_parser import parse_deletion_requests
from code.ingest.unified_indexer import EvidenceIndexer
from code.policy import PolicyEngine
from code.schema import CaseRequest


def run_benchmark() -> None:
    print("=" * 80)
    print("PHASE 4 SAMPLE BENCHMARK: POLICY ENGINE & CAUSAL STEP SYNTHESIS")
    print("=" * 80)

    # 1. Initialize components
    indexer = EvidenceIndexer()
    print("Loading all 94 evidence files into EvidenceIndexer...")
    indexer.load_all_evidence()

    resolver = IdentityResolver()
    classifier = IntentClassifier()
    engine = PolicyEngine(indexer, resolver, classifier)

    # 2. Load sample requests
    requests = parse_deletion_requests("dataset/sample_deletion_requests.csv")
    print(f"Loaded {len(requests)} sample requests.")

    # 3. Generate predictions
    predictions = []
    for req in requests:
        status, steps = engine.audit_case(req)
        steps_json = json.dumps([s.model_dump() for s in steps], separators=(",", ":"))
        predictions.append({
            "case_id": req.case_id,
            "deletion_status": status,
            "steps_json": steps_json,
        })

    # Save predictions
    out_dir = Path("code/cache")
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / "sample_predictions.csv"

    with pred_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(predictions)

    print(f"Saved {len(predictions)} predictions to {pred_path}.")

    # 4. Evaluate with official evaluator
    truth_cases = load_output_csv("dataset/sample_output.csv")
    pred_cases = load_output_csv(pred_path)
    summary = evaluate_predictions(truth_cases, pred_cases)

    print("\n" + "=" * 80)
    print(f"STATUS ACCURACY:      {summary.status_accuracy:.2f}% ({summary.status_correct}/{summary.total_cases})")
    print(f"EXACT CASE ACCURACY:  {summary.exact_case_accuracy:.2f}% ({summary.exact_case_matches}/{summary.total_cases})")
    print(f"SEQUENCE ACCURACY:    {summary.sequence_accuracy:.2f}% ({summary.sequence_matches}/{summary.total_cases})")
    print(f"FIELD ACCURACY:       {summary.field_accuracy:.2f}% ({summary.total_fields_matched}/{summary.total_fields_checked})")
    print("=" * 80)

    # 5. Print detailed diff for any non-exact case
    with open("dataset/sample_output.csv", "r", encoding="utf-8") as f:
        golden_cases = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

    with open(pred_path, "r", encoding="utf-8") as f:
        pred_cases = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

    mismatches = 0
    for cid in sorted(golden_cases.keys()):
        g_status, g_steps = golden_cases[cid]
        p_status, p_steps = pred_cases[cid]

        diffs = []
        if g_status != p_status:
            diffs.append(f"Status mismatch: golden={g_status} vs pred={p_status}")
        if len(g_steps) != len(p_steps):
            diffs.append(f"Step count mismatch: golden={len(g_steps)} vs pred={len(p_steps)}")

        # Field comparisons
        max_len = max(len(g_steps), len(p_steps))
        for i in range(max_len):
            g_s = g_steps[i] if i < len(g_steps) else None
            p_s = p_steps[i] if i < len(p_steps) else None
            if g_s != p_s:
                diffs.append(f"  Step {i+1} diff: golden={g_s} vs pred={p_s}")

        if diffs:
            mismatches += 1
            print(f"\n[DIFF: {cid}]")
            for d in diffs:
                print(f"  {d}")

    if mismatches == 0:
        print("\nPERFECT 32/32 (100.0%) EXACT MATCH ACHIEVED ACROSS ALL METRICS!")
    else:
        print(f"\n{mismatches} cases have discrepancies.")


if __name__ == "__main__":
    run_benchmark()
