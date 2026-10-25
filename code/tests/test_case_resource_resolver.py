import sys
from pathlib import Path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import csv
import json
from collections import defaultdict
from code.identity import IdentityResolver
from code.ingest.unified_indexer import EvidenceIndexer

resolver = IdentityResolver()
indexer = EvidenceIndexer()
indexer.load_all_evidence()

with open("dataset/sample_output.csv", "r", encoding="utf-8") as f:
    sample_outputs = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/sample_deletion_requests.csv", "r", encoding="utf-8") as f:
    requests = {r["case_id"]: r for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", "r", encoding="utf-8") as f:
    activities = list(csv.DictReader(f))

# Let's see: for each sample case, what are the golden resources vs our resolved resources?
for cid in sorted(sample_outputs.keys()):
    status, steps = sample_outputs[cid]
    golden_resources = {(s["system_id"], s["resource_id"]) for s in steps}
    req = requests[cid]
    audit_at = req["audit_at"]
    ident = resolver.resolve_identity(req["email"], audit_at)
    
    # 1. Direct evidence matches
    ev_records = indexer.get_records_for_identity(ident, audit_at)
    
    # Filter out decoy systems like legal_retention_service
    scoped_systems = {
        "account_service", "analytics_platform", "backup_service",
        "export_service", "identity_service", "integration_service",
        "search_service", "security_service", "support_platform"
    }
    
    resolved = {(r.system_id, r.resource_id) for r in ev_records if r.system_id in scoped_systems}
    
    diff_missing = golden_resources - resolved
    diff_extra = resolved - golden_resources
    
    print(f"[{cid}] Golden: {len(golden_resources)} | Matched: {len(resolved)} | Missing: {len(diff_missing)} | Extra: {len(diff_extra)}")
    if diff_missing:
        print(f"   Missing: {diff_missing}")
    if diff_extra:
        print(f"   Extra: {diff_extra}")
