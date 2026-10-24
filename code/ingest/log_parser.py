"""Parser for log files in dataset/evidence/logs/ and text reports in dataset/evidence/records/."""

from __future__ import annotations

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

        # Check Format B: Key-Value logs
        kv_pairs: dict[str, str] = {}
        for k, v1, v2 in kv_regex.findall(line_str):
            kv_pairs[k] = v1 if v1 else v2

        if "resource_id" in kv_pairs or "lookup_key" in kv_pairs or "correlation_key" in kv_pairs or "subject_reference" in kv_pairs:
            ts_match = ts_regex.search(line_str)
            ts = ts_match.group("timestamp") if ts_match else captured_at

            resource_id = kv_pairs.get("resource_id", "")
            system_id = kv_pairs.get("system") or kv_pairs.get("source_system") or kv_pairs.get("target_system") or kv_pairs.get("function") or origin

            subject = kv_pairs.get("subject_reference") or kv_pairs.get("lookup_key") or kv_pairs.get("correlation_key") or kv_pairs.get("customer_reference") or ""
            email = subject if "@" in subject else None
            subj_ref = None if "@" in subject else (subject if subject else None)

            # Determine category
            category = kv_pairs.get("record_type") or "USER_PROFILE"
            if "search" in resource_id or "search" in system_id:
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
            elif "backup" in resource_id:
                category = "BACKUP_ARCHIVE"
                system_id = "backup_service"
            elif "export" in resource_id:
                category = "USER_EXPORT"
                system_id = "export_service"
            elif "support" in resource_id:
                category = "SUPPORT_MESSAGE"
                system_id = "support_platform"

            # Determine state
            state = "PRESENT"
            http_status = kv_pairs.get("http_status")
            rows = kv_pairs.get("rows")
            result = str(kv_pairs.get("result", "")).upper()
            event = str(kv_pairs.get("event", "")).upper()

            if http_status == "404" or rows == "0" or result in ["NOT_FOUND", "MISS"]:
                state = "ABSENT"
            elif http_status == "200" or rows == "1" or result in ["FOUND", "HIT"]:
                state = "PRESENT"
            elif result == "ACTIVE" or "ACTIVE" in event:
                state = "ACTIVE"
            elif result == "DISABLED" or "DISABLED" in event:
                state = "DISABLED"

            if resource_id:
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
                        phone=None,
                        email_hash=None,
                        name=None,
                        attributes=kv_pairs,
                    )
                )

    return records
