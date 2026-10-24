"""Parser for log files in dataset/evidence/logs/ and text reports in dataset/evidence/records/."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from code.schema import EvidenceRecord


def parse_log_or_text_file(
    file_path: str | Path,
    file_id: str,
    captured_at: str,
    origin: str,
) -> list[EvidenceRecord]:
    """Parse log and text evidence files into EvidenceRecord objects."""
    path = Path(file_path)
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    records: list[EvidenceRecord] = []
    trace_groups: dict[str, list[dict[str, str]]] = {}

    # Format A: Pipe-separated shift handover / report lines
    # e.g.: - 2026-10-01T12:00:00Z | account_service | account_4248 | USER_PROFILE | NOT_FOUND | novak.tomasz@icloud.com
    # or: 2026-10-01T12:00:00Z | account_service | ...
    pipe_regex = re.compile(
        r"^[-*]?\s*(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:]+Z?)\s*\|\s*(?P<system>[^|]+)\s*\|\s*(?P<resource>[^|]+)\s*\|\s*(?P<category>[^|]+)\s*\|\s*(?P<status>[^|]+)\s*\|\s*(?P<subject>[^|]+)"
    )

    # Format B: Key=Value log lines
    # e.g.: 2026-03-15T07:00:00Z INFO service=downstream_delivery_service event=record_lookup seq=1 system="account_service" resource_id="account_022" record_type="USER_PROFILE" result="NOT_FOUND" subject_reference="zofia-novak@gmail.com"
    kv_regex = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s]+))')
    ts_regex = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:]+Z?)")

    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        # Check Format A
        m_pipe = pipe_regex.match(line_str)
        if m_pipe:
            ts = m_pipe.group("timestamp").strip()
            system = m_pipe.group("system").strip()
            resource = m_pipe.group("resource").strip()
            category = m_pipe.group("category").strip().upper()
            status = m_pipe.group("status").strip().upper()
            subject = m_pipe.group("subject").strip()

            email = subject if "@" in subject else None
            subj_ref = None if "@" in subject else (None if "no direct" in subject.lower() else subject)

            # Map status to state
            state = "PRESENT"
            if status in ["NOT_FOUND", "ABSENT", "DELETED"]:
                state = "ABSENT"
            elif status in ["FOUND", "PRESENT"]:
                state = "PRESENT"
            elif status in ["ANONYMIZED", "ANONYMOUS"]:
                state = "ANONYMIZED"
            elif status in ["REDACTED", "MASKED"]:
                state = "REDACTED"
            elif status in ["ACTIVE", "HEALTHY", "ENABLED"]:
                state = "ACTIVE"
            elif status in ["DISABLED", "INACTIVE", "STOPPED"]:
                state = "DISABLED"
            elif status in ["BLOCKED"]:
                state = "BLOCKED"
            elif status == "IDENTIFIABLE":
                state = "PRESENT"

            records.append(
                EvidenceRecord(
                    file_id=file_id,
                    origin=origin,
                    captured_at=ts or captured_at,
                    system_id=system,
                    resource_id=resource,
                    data_category=category,
                    state=state,
                    subject_reference=subj_ref,
                    email=email,
                    phone=None,
                    email_hash=None,
                    name=None,
                    attributes={"raw_status": status, "line": line_str},
                )
            )
            continue

        # Check Format B: Key-Value or JSON logs
        kv_pairs: dict[str, str] = {}
        if "{" in line_str and line_str.endswith("}"):
            try:
                json_part = line_str[line_str.index("{") :]
                raw_json = json.loads(json_part)
                for k, v in raw_json.items():
                    kv_pairs[str(k)] = str(v)
            except Exception:
                kv_pairs = {}

        if not kv_pairs:
            for k, v1, v2 in kv_regex.findall(line_str):
                kv_pairs[k] = (v1 if v1 else v2).strip('"')

        if kv_pairs:
            ts_match = ts_regex.search(line_str)
            ts = ts_match.group("timestamp") if ts_match else captured_at
            kv_pairs["__timestamp"] = ts
            kv_pairs["__line"] = line_str

            tid = kv_pairs.get("trace_id") or kv_pairs.get("requestId")
            if not tid:
                tid = f"line_{len(records)}_{ts}"
            trace_groups.setdefault(tid, []).append(kv_pairs)

    # Process all correlated traces
    for tid, kvs_list in trace_groups.items():
        merged: dict[str, str] = {}
        for kvs in kvs_list:
            for k, v in kvs.items():
                if v:
                    merged[k] = v

        resource_id = merged.get("resource_id", "")
        if not resource_id:
            continue

        ts = merged.get("__timestamp", captured_at)
        system_id = merged.get("system") or merged.get("service") or merged.get("source_system") or merged.get("target_system") or merged.get("function") or origin

        subject = (
            merged.get("subject_reference")
            or merged.get("lookup_key")
            or merged.get("subject_key")
            or merged.get("correlation_key")
            or merged.get("subject_ref")
            or merged.get("match_key")
            or merged.get("scan_key")
            or merged.get("matched_value")
            or merged.get("customer_reference")
            or ""
        )

        email = None
        phone = None
        subj_ref = None

        if "@" in subject:
            email = subject
        elif subject.startswith("+"):
            phone = subject
        elif subject and "no direct" not in subject.lower():
            subj_ref = subject

        # Check for user_id pattern in subject
        if not subj_ref and subject and re.match(r"^user_\d+$", subject, re.IGNORECASE):
            subj_ref = subject

        # Determine category and normalize system_id
        category = merged.get("record_type") or "USER_PROFILE"
        if "audit" in resource_id or "security" in system_id or "audit" in system_id:
            category = "SECURITY_AUDIT_LOG"
            system_id = "security_service"
        elif "search" in resource_id or "search" in system_id:
            category = "SEARCH_INDEX_ENTRY"
            system_id = "search_service"
        elif "analytic" in resource_id or "analytic" in system_id:
            category = "ANALYTICS_PROFILE"
            system_id = "analytics_platform"
        elif "account" in resource_id or "account" in system_id:
            category = "USER_PROFILE"
            system_id = "account_service"
        elif "data_flow" in resource_id or "connector" in system_id:
            category = "DATA_FLOW"
            system_id = "integration_service"
        elif "backup" in resource_id or "backup" in system_id:
            category = "BACKUP_ARCHIVE"
            system_id = "backup_service"
        elif "export" in resource_id or "export" in system_id:
            category = "USER_EXPORT"
            system_id = "export_service"
        elif "support" in resource_id or "support" in system_id:
            category = "SUPPORT_MESSAGE"
            system_id = "support_platform"

        # Determine state
        state = "PRESENT"
        http_status = merged.get("http_status")
        rows = merged.get("rows")
        result = str(merged.get("result", "")).upper()
        event = str(merged.get("event", "")).upper()
        enabled_val = str(merged.get("enabled", "")).lower()
        del_block = str(merged.get("deletion_block", "")).lower()
        eligible = str(merged.get("eligible", "")).lower()

        if http_status == "404" or rows == "0" or result in ["NOT_FOUND", "MISS"]:
            state = "ABSENT"
        elif category == "DATA_FLOW":
            if enabled_val == "true" or result == "ACTIVE" or "ENABLED" in event:
                state = "ACTIVE"
            else:
                state = "DISABLED"
        elif category == "BACKUP_ARCHIVE":
            if del_block == "false" or eligible == "true" or result == "ACTIVE":
                state = "ACTIVE"
            else:
                state = "BLOCKED"
        elif result == "ACTIVE" or "ACTIVE" in event or "HEALTHY" in event or "ENABLED" in event:
            state = "ACTIVE"
        elif result == "DISABLED" or "DISABLED" in event or "STOPPED" in event or "INACTIVE" in event:
            state = "DISABLED"
        elif result == "BLOCKED" or "BLOCKED" in event or del_block == "true":
            state = "BLOCKED"
        elif result == "REDACTED" or "MASKED" in event:
            state = "REDACTED"
        elif result == "ANONYMIZED" or "ANONYMOUS" in event:
            state = "ANONYMIZED"
        elif category == "SUPPORT_MESSAGE" and ("PII_SCAN" in event or result == "IDENTIFIABLE"):
            state = "PRESENT"

        records.append(
            EvidenceRecord(
                file_id=file_id,
                origin=origin,
                captured_at=ts,
                system_id=system_id,
                resource_id=resource_id,
                data_category=category,
                state=state,
                subject_reference=subj_ref,
                email=email,
                phone=phone,
                email_hash=None,
                name=None,
                attributes=merged,
            )
        )

    return records
