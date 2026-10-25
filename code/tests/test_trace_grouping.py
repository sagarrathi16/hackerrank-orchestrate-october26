import sys
from pathlib import Path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import re
from pathlib import Path

path = Path("dataset/evidence/logs/service_events_ap_south_20260915.log")
lines = path.read_text(encoding="utf-8").splitlines()

kv_regex = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s]+))')

traces = {}
for line in lines:
    kvs = dict((k, v1 or v2) for k, v1, v2 in kv_regex.findall(line))
    tid = kvs.get("trace_id")
    if tid:
        traces.setdefault(tid, []).append(kvs)

print(f"Total traces: {len(traces)}")
for tid, kvs_list in list(traces.items())[:10]:
    merged = {}
    for kvs in kvs_list:
        merged.update(kvs)
    print(f"Trace {tid}: res={merged.get('resource_id')} subj={merged.get('lookup_key') or merged.get('subject_key') or merged.get('correlation_key') or merged.get('subject_ref') or merged.get('match_key')}")
