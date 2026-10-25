import sys
from pathlib import Path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import re
from pathlib import Path

kv_regex = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s]+))')

for path in sorted(Path("dataset/evidence/logs").glob("*.log")):
    lines = path.read_text(encoding="utf-8").splitlines()
    traces = {}
    for line in lines:
        kvs = dict((k, v1 or v2) for k, v1, v2 in kv_regex.findall(line))
        tid = kvs.get("trace_id") or kvs.get("requestId")
        if tid:
            traces.setdefault(tid, []).append(kvs)
    print(f"\n{path.name}: {len(traces)} traces")
    for tid, kvs_list in list(traces.items())[:5]:
        merged = {}
        for kvs in kvs_list:
            merged.update(kvs)
        subj = merged.get("lookup_key") or merged.get("subject_key") or merged.get("correlation_key") or merged.get("subject_ref") or merged.get("match_key") or merged.get("scan_key") or merged.get("matched_value")
        print(f"  {tid}: res={merged.get('resource_id')} subj={subj}")
