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

# Helper to find account_XXXX for a case
def find_case_account(case, ident, activities):
    # If user_id is user_01 to user_10:
    if ident.user_id:
        try:
            uid_num = int(ident.user_id.replace("user_", ""))
            if 1 <= uid_num <= 10:
                # check if there's an account activity for user_0X or account_00X
                # In sample: case_01 -> account_001, case_02 -> account_002, case_03 -> account_7566, case_04 -> account_004, case_05 -> account_005, case_06 -> account_006, case_07 -> account_007, case_08 -> account_008, case_09 -> account_3960, case_10 -> account_010
                pass
        except ValueError:
            pass
            
    # Search in system_activity between requested_at and audit_at
    req_at = case["requested_at"]
    rep_at = case["reported_at"]
    audit_at = case["audit_at"]
    
    # 1. Activities mentioning user_id or email
    for a in activities:
        if a["target_system"] == "account_service" and a["event_type"] == "DELETE_RECORD":
            det = a["details"]
            if (ident.user_id and ident.user_id in det) or any(em in det for em in ident.emails):
                return a["resource_id"]
                
    # 2. Window-based: deletion_worker DELETE_RECORD in account_service between req_at and rep_at / audit_at
    # Let's inspect all such activities for each sample case
    return None

print("Checking scoping mapping...")
