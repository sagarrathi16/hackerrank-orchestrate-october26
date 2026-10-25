"""Main Entry Point for HackerRank Orchestrate (October 2026): Ghost Data Still Exists.

Executes the full Right-to-Erasure deletion audit pipeline across all 518 cases in
dataset/deletion_requests.csv using the live LLM intent classifier, Transitive
Identity Engine, Multimodal Evidence Indexer, and Deterministic Policy Engine.
Outputs output.csv at the repository root.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Ensure repository root is on sys.path for direct invocation
repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.classifier import IntentClassifier
from code.identity import IdentityResolver
from code.ingest.csv_parser import parse_deletion_requests
from code.ingest.unified_indexer import EvidenceIndexer
from code.policy import PolicyEngine
from code.schema import CaseRequest


def run_pipeline(
    requests_path: str | Path = "dataset/deletion_requests.csv",
    output_path: str | Path = "output.csv",
    max_workers: int = 8,
) -> None:
    print("=" * 80)
    print("HACKERRANK ORCHESTRATE: GHOST DATA STILL EXISTS — AUDIT PIPELINE")
    print("=" * 80)

    # 1. Initialize Components
    print("\n[1/5] Initializing Evidence Indexer & Loading Multimodal Evidence...")
    indexer = EvidenceIndexer()
    indexer.load_all_evidence()
    print(f"      Indexed {len(indexer.all_records)} multimodal records across all systems.")

    print("\n[2/5] Initializing Transitive Identity Engine & Intent Classifier...")
    resolver = IdentityResolver()
    classifier = IntentClassifier()

    print("\n[3/5] Loading Evaluation Requests...")
    requests = parse_deletion_requests(requests_path)
    total_cases = len(requests)
    print(f"      Loaded {total_cases} cases from {requests_path}.")

    # 2. Concurrent Live LLM Intent Classification & Consensus Audit
    print(f"\n[4/5] Executing Live LLM Classification & Consensus Audit ({max_workers} workers)...")
    t0 = time.time()
    
    def classify_worker(req: CaseRequest):
        return req.case_id, classifier.classify_request(req.case_id, req.request_text)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(classify_worker, req): req.case_id for req in requests}
        completed = 0
        for f in as_completed(futures):
            completed += 1
            if completed % 50 == 0 or completed == total_cases:
                print(f"      Classified {completed}/{total_cases} cases (elapsed: {time.time() - t0:.1f}s)...")

    classify_duration = time.time() - t0
    print(f"      Completed all {total_cases} live LLM classifications in {classify_duration:.1f}s.")

    # 3. Policy Engine Audit & Causal Step Synthesis
    print("\n[5/5] Executing Policy Engine Audit & Synthesizing Causal Steps...")
    engine = PolicyEngine(indexer, resolver, classifier)

    results: list[dict[str, str]] = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for idx, req in enumerate(requests, start=1):
        status, steps = engine.audit_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1
        steps_json = json.dumps([s.model_dump() for s in steps], separators=(",", ":"))
        results.append({
            "case_id": req.case_id,
            "deletion_status": status,
            "steps_json": steps_json,
        })

    # Sort strictly by case_id (natural numerical order case_33..case_550)
    def case_sort_key(cid: str) -> int | str:
        try:
            return int(cid.split("_")[-1])
        except Exception:
            return cid

    results.sort(key=lambda r: case_sort_key(r["case_id"]))

    # 4. Write output.csv to repository root
    out_file = Path(output_path)
    with out_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nSuccessfully wrote {len(results)} evaluated cases to {out_file.resolve()}.")

    # 5. Contract Validation
    print("\n" + "=" * 80)
    print("OUTPUT VERIFICATION & CONTRACT AUDIT")
    print("=" * 80)

    # Check row count
    with out_file.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        data_rows = len(lines) - 1

    print(f"Total Data Rows in output.csv: {data_rows} (Expected: 518)")
    assert data_rows == 518, f"Expected 518 rows, found {data_rows}"

    # Check case sorting & JSON validity
    all_case_ids = [r["case_id"] for r in results]
    assert all_case_ids == sorted(all_case_ids, key=case_sort_key), "output.csv is not sorted by case_id!"

    for r in results:
        parsed_steps = json.loads(r["steps_json"])
        assert isinstance(parsed_steps, list), f"steps_json for {r['case_id']} is not a list!"
        for step_idx, step in enumerate(parsed_steps, start=1):
            assert step["step_no"] == step_idx, f"Step numbering non-consecutive in {r['case_id']}!"

    print("Status Breakdown across 518 Evaluation Cases:")
    for st, count in sorted(status_counts.items()):
        pct = (count / 518) * 100.0
        print(f"  - {st:<16}: {count:>4} ({pct:.1f}%)")

    tracker = classifier.tracker
    print("\nToken Telemetry & Cost Summary:")
    print(f"  - Model:             {tracker.model_name}")
    print(f"  - Total Calls:       {tracker.total_calls}")
    print(f"  - Live API Calls:    {tracker.live_calls}")
    print(f"  - Cached Calls:      {tracker.cached_calls}")
    print(f"  - Prompt Tokens:     {tracker.input_tokens:,}")
    print(f"  - Completion Tokens: {tracker.output_tokens:,}")
    print(f"  - Total Tokens:      {tracker.total_tokens:,}")
    print(f"  - Average Tokens:    {tracker.total_tokens / tracker.total_calls:.1f} per request")
    print(f"  - Estimated Cost:    ${tracker.estimated_cost_usd:.4f} USD")
    print(f"  - Disagreements:     {len(classifier.disagreements)} cases")

    print("\nPIPELINE COMPLETED SUCCESSFULLY WITH 100% CONTRACT CONFORMANCE.")
    print("=" * 80)


if __name__ == "__main__":
    run_pipeline()
