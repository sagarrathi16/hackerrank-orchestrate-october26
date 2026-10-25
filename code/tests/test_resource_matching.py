import sys
from pathlib import Path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import csv
import json
from code.identity import IdentityResolver
from code.ingest.unified_indexer import EvidenceIndexer

resolver = IdentityResolver()
indexer = EvidenceIndexer()
indexer.load_all_evidence()

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_outputs = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(f)}

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    requests = {r["case_id"]: r for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    activities = list(csv.DictReader(f))

# Index activities by resource_id
act_by_res = {}
for a in activities:
    r = a["resource_id"]
    if r:
        act_by_res.setdefault(r, []).append(a)

for cid in sorted(sample_outputs.keys()):
    req = requests[cid]
    audit_at = req["audit_at"]
    req_at = req["requested_at"]
    rep_at = req["reported_at"]
    ident = resolver.resolve_identity(req["email"], audit_at)

    # 1. Matched evidence records
    ev_records = indexer.get_records_for_identity(ident, audit_at)
    res_set = {(r.system_id, r.resource_id) for r in ev_records}

    # 2. Golden resources
    golden_steps = sample_outputs[cid]
    golden_res = {(s["system_id"], s["resource_id"]) for s in golden_steps}

    # Compare
    missing = golden_res - res_set
    extra = res_set - golden_res

    print(f"\n[{cid}] {req['email']} (user_id={ident.user_id})")
    print(f"  Golden: {len(golden_res)} | Matched: {len(res_set)}")
    if missing:
        print(f"  Missing: {sorted(missing)}")
    if extra:
        print(f"  Extra: {sorted(extra)}")
