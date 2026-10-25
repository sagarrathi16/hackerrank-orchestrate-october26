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

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_outputs = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(f)}

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    requests = {r["case_id"]: r for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    activities = list(csv.DictReader(f))

# Build activity clusters
# 1. Activities by resource_id
act_by_res = defaultdict(list)
for a in activities:
    r = a["resource_id"]
    if r:
        act_by_res[r].append(a)

# 2. Activity graph: connect resources that appear in the same deletion workflow session
# A deletion workflow session is a sequence of deletion_worker activities occurring within 2 hours of each other
workflow_sessions = []
current_session = []
for a in activities:
    if a["source_system"] == "deletion_worker":
        if not current_session:
            current_session.append(a)
        else:
            # Check time gap between consecutive activities
            # ISO format: YYYY-MM-DDTHH:MM:SSZ
            prev_time = current_session[-1]["event_time"]
            curr_time = a["event_time"]
            # If same day and within 2 hours (or consecutive deletion_worker events)
            # Let's inspect session breaks
            current_session.append(a)

print(f"Total deletion worker activities: {len(current_session)}")
