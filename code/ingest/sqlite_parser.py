"""Parser for SQLite snapshot export files in dataset/evidence/databases/."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from code.schema import EvidenceRecord


def parse_sqlite_snapshot(file_path: str | Path, file_id: str, captured_at: str, origin: str) -> list[EvidenceRecord]:
    """Execute a .sql snapshot dump in an in-memory SQLite database and extract all records."""
    path = Path(file_path)
    if not path.exists():
        return []

    sql_text = path.read_text(encoding="utf-8")
    
    conn = sqlite3.connect(":memory:")
    # Provide json_valid function if needed by CHECK constraints
    def _json_valid(text: str) -> int:
        try:
            json.loads(text)
            return 1
        except Exception:
            return 0

    conn.create_function("json_valid", 1, _json_valid)
    
    try:
        conn.executescript(sql_text)
    except Exception as e:
        print(f"Warning: error executing {path.name}: {e}")

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    records: list[EvidenceRecord] = []

    for table in tables:
        cursor.execute(f"PRAGMA table_info({table});")
        cols = [c[1] for c in cursor.fetchall()]
        
        cursor.execute(f"SELECT * FROM {table};")
        rows = cursor.fetchall()
        
        for row in rows:
            row_dict = dict(zip(cols, row))
            res_id = str(row_dict.get("resource_id", ""))
            origin_sys = str(row_dict.get("origin_system", ""))
            collection = str(row_dict.get("collection_name", ""))
            rec_json_str = str(row_dict.get("record_json", "{}"))
            
            try:
                rec_data = json.loads(rec_json_str)
            except Exception:
                rec_data = {}

            # Map category from collection_name or origin_system
            category = "UNKNOWN"
            if "profile" in collection or "account" in collection:
                category = "USER_PROFILE"
            elif "search" in collection:
                category = "SEARCH_INDEX_ENTRY"
            elif "analytic" in collection:
                category = "ANALYTICS_PROFILE"
            elif "support" in collection:
                category = "SUPPORT_MESSAGE"
            elif "export" in collection:
                category = "USER_EXPORT"
            elif "backup" in collection:
                category = "BACKUP_ARCHIVE"
            elif "connector" in collection or "data_flow" in collection:
                category = "DATA_FLOW"
            elif "security" in collection or "audit" in collection:
                category = "SECURITY_AUDIT_LOG"

            # Determine system_id
            system_id = origin_sys
            if not system_id:
                if "search" in res_id or "search" in table:
                    system_id = "search_service"
                elif "account" in res_id or "account" in table:
                    system_id = "account_service"
                elif "analytics" in res_id or "analytics" in table:
                    system_id = "analytics_platform"
                elif "support" in res_id or "support" in table:
                    system_id = "support_platform"
                elif "backup" in res_id or "backup" in table:
                    system_id = "backup_service"
                elif "data_flow" in res_id:
                    system_id = "integration_service"

            # State determination
            # Default is PRESENT unless specified
            state = "PRESENT"
            if category == "BACKUP_ARCHIVE":
                restore_allowed = rec_data.get("restore_allowed", False)
                state = "ACTIVE" if restore_allowed else "BLOCKED"
            elif category == "DATA_FLOW":
                enabled = rec_data.get("enabled", False)
                state = "ACTIVE" if enabled else "DISABLED"
            elif category == "ANALYTICS_PROFILE":
                # Check if anonymized or identifiable
                user_id = rec_data.get("user_id")
                email = rec_data.get("email")
                phone = rec_data.get("phone")
                email_hash = rec_data.get("email_hash")
                if not any([user_id, email, phone, email_hash]):
                    state = "ANONYMIZED"
                else:
                    state = "PRESENT"

            # Subject references
            subj_ref = rec_data.get("user_id") or rec_data.get("subject_reference") or rec_data.get("customer_reference")
            email = rec_data.get("email")
            if not email and "document" in rec_data and isinstance(rec_data["document"], dict):
                email = rec_data["document"].get("email")
                if not subj_ref:
                    subj_ref = rec_data["document"].get("customer_reference")
            
            phone = rec_data.get("phone")
            name = rec_data.get("full_name") or rec_data.get("display_name")
            email_hash = rec_data.get("email_hash")

            # Check if subject_selector in connector
            if not email and "subject_selector" in rec_data:
                sel = rec_data["subject_selector"]
                if "@" in str(sel):
                    email = sel
                else:
                    subj_ref = sel

            records.append(
                EvidenceRecord(
                    file_id=file_id,
                    origin=origin,
                    captured_at=captured_at,
                    system_id=system_id,
                    resource_id=res_id,
                    data_category=category,
                    state=state,
                    subject_reference=str(subj_ref) if subj_ref else None,
                    email=str(email) if email else None,
                    email_hash=str(email_hash) if email_hash else None,
                    phone=str(phone) if phone else None,
                    name=str(name) if name else None,
                    attributes={"table": table, **rec_data},
                )
            )

    conn.close()
    return records
