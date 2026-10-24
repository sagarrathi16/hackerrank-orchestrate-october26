"""Parser for structured JSON bundle files in dataset/evidence/records/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from code.schema import EvidenceRecord


def parse_json_evidence_file(
    file_path: str | Path,
    file_id: str,
    captured_at: str,
    origin: str,
) -> list[EvidenceRecord]:
    """Parse any JSON evidence file into a list of normalized EvidenceRecord models."""
    path = Path(file_path)
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    records: list[EvidenceRecord] = []

    # Case 1: customer_data_snapshot_bundle_*.json
    if "snapshots" in data:
        exp_at = data.get("exported_at", captured_at)
        source = data.get("source", origin)
        for snap in data["snapshots"]:
            snap_time = max(captured_at, snap.get("captured_at", captured_at))
            data_store = snap.get("data_store", "")
            collection = snap.get("collection", "")
            snap_records = snap.get("records", [])

            # Category determination
            cat = "USER_PROFILE"
            if "deleted" in collection or "tombstone" in collection or data_store == "identity_service":
                cat = "ACCOUNT_TOMBSTONE"
            elif "audit" in collection or data_store == "security_service":
                cat = "SECURITY_AUDIT_LOG"
            elif "search" in collection or data_store == "search_service":
                cat = "SEARCH_INDEX_ENTRY"
            elif "analytic" in collection or data_store == "analytics_platform":
                cat = "ANALYTICS_PROFILE"
            elif "support" in collection or data_store == "support_platform":
                cat = "SUPPORT_MESSAGE"
            elif "export" in collection or data_store == "export_service":
                cat = "USER_EXPORT"
            elif "backup" in collection or data_store == "backup_service":
                cat = "BACKUP_ARCHIVE"
            elif "connector" in collection or data_store == "integration_service":
                cat = "DATA_FLOW"

            # If snapshot collection is empty, record empty snapshot marker
            if not snap_records:
                records.append(
                    EvidenceRecord(
                        file_id=file_id,
                        origin=source,
                        captured_at=snap_time,
                        system_id=data_store,
                        resource_id=f"__EMPTY_COLLECTION__{collection}",
                        data_category=cat,
                        state="ABSENT",
                        subject_reference=None,
                        email=None,
                        phone=None,
                        email_hash=None,
                        name=None,
                        attributes={"empty_collection": collection, "data_store": data_store},
                    )
                )

            for r in snap_records:
                res_id = str(r.get("resource_id", ""))
                subj_ref = r.get("subject_reference") or r.get("customer_reference") or r.get("user_id")
                name = r.get("full_name") or r.get("name")
                email = r.get("email") or r.get("owner_email")
                phone = r.get("phone")
                email_hash = r.get("email_hash")

                # Nested document in search snapshots
                if "document" in r and isinstance(r["document"], dict):
                    doc = r["document"]
                    email = email or doc.get("email")
                    name = name or doc.get("display_name") or doc.get("full_name")
                    subj_ref = subj_ref or doc.get("customer_reference") or doc.get("user_id")

                if not email and "uploaded_by" in r:
                    up = str(r["uploaded_by"])
                    if "@" in up:
                        email = up
                    else:
                        subj_ref = subj_ref or up

                if not email and "lookup_value" in r:
                    lv = str(r["lookup_value"])
                    if "@" in lv:
                        email = lv
                    else:
                        subj_ref = subj_ref or lv

                # State determination
                state = "PRESENT"
                if cat == "ACCOUNT_TOMBSTONE":
                    # Check if PII remains or was redacted
                    if not any([name, email, phone, email_hash]):
                        state = "REDACTED"
                    else:
                        state = "PRESENT"
                elif cat == "ANALYTICS_PROFILE":
                    if not any([subj_ref, name, email, phone, email_hash]):
                        state = "ANONYMIZED"
                    else:
                        state = "PRESENT"

                records.append(
                    EvidenceRecord(
                        file_id=file_id,
                        origin=source,
                        captured_at=snap_time,
                        system_id=data_store,
                        resource_id=res_id,
                        data_category=cat,
                        state=state,
                        subject_reference=str(subj_ref) if subj_ref else None,
                        email=str(email) if email else None,
                        phone=str(phone) if phone else None,
                        email_hash=str(email_hash) if email_hash else None,
                        name=str(name) if name else None,
                        attributes={"collection": collection, **r},
                    )
                )

    # Case 2: service_resource_export_*.json
    elif "service_exports" in data:
        exp_at = data.get("exported_at", captured_at)
        source = data.get("source", origin)
        exports = data["service_exports"]

        for svc_name, collections in exports.items():
            if not isinstance(collections, dict):
                continue
            for coll_name, rec_list in collections.items():
                if not isinstance(rec_list, list):
                    continue

                cat = "USER_PROFILE"
                if "analytic" in svc_name or "analytic" in coll_name:
                    cat = "ANALYTICS_PROFILE"
                elif "search" in svc_name or "search" in coll_name:
                    cat = "SEARCH_INDEX_ENTRY"
                elif "backup" in svc_name or "backup" in coll_name:
                    cat = "BACKUP_ARCHIVE"
                elif "export" in svc_name or "export" in coll_name:
                    cat = "USER_EXPORT"
                elif "integration" in svc_name or "connector" in coll_name:
                    cat = "DATA_FLOW"
                elif "security" in svc_name or "audit" in coll_name:
                    cat = "SECURITY_AUDIT_LOG"
                elif "support" in svc_name or "ticket" in coll_name:
                    cat = "SUPPORT_MESSAGE"

                for r in rec_list:
                    res_id = str(r.get("resource_id", ""))
                    status_code = r.get("status_code")
                    obs_at = r.get("observed_at", exp_at)

                    # Special handling for search index_queries with nested hits
                    if "hits" in r and isinstance(r["hits"], dict) and "documents" in r["hits"]:
                        docs = r["hits"]["documents"]
                        total_hits = r["hits"].get("total", len(docs))
                        query_str = str(r.get("query", ""))
                        query_email = query_str if "@" in query_str else None

                        for doc in docs:
                            doc_res = str(doc.get("resource_id", "")) or res_id
                            doc_email = doc.get("email") or query_email
                            doc_subj = doc.get("customer_reference")
                            doc_name = doc.get("display_name")
                            doc_phone = doc.get("phone")
                            doc_hash = doc.get("email_hash")
                            doc_state = "PRESENT" if total_hits > 0 else "ABSENT"

                            records.append(
                                EvidenceRecord(
                                    file_id=file_id,
                                    origin=source,
                                    captured_at=obs_at,
                                    system_id=svc_name,
                                    resource_id=doc_res,
                                    data_category=cat,
                                    state=doc_state,
                                    subject_reference=str(doc_subj) if doc_subj else None,
                                    email=str(doc_email) if doc_email else None,
                                    phone=str(doc_phone) if doc_phone else None,
                                    email_hash=str(doc_hash) if doc_hash else None,
                                    name=str(doc_name) if doc_name else None,
                                    attributes={"status_code": status_code, "collection": coll_name, "query": query_str, **doc},
                                )
                            )
                        continue

                    subj_ref = r.get("customer_reference") or r.get("subject_reference")
                    email = r.get("email") or r.get("customer_email") or r.get("owner_email") or r.get("requester_email")
                    phone = r.get("phone") or r.get("owner_phone") or r.get("requester_phone")
                    email_hash = r.get("email_hash")
                    name = r.get("full_name") or r.get("name") or r.get("requester_name")

                    # If nested profile dict
                    if "profile" in r and isinstance(r["profile"], dict):
                        p = r["profile"]
                        email = email or p.get("email")
                        phone = phone or p.get("phone")
                        email_hash = email_hash or p.get("email_hash")
                        name = name or p.get("full_name") or p.get("name")
                        subj_ref = subj_ref or p.get("customer_reference")

                    # Handle subject_selector in connectors
                    if not email and "subject_selector" in r:
                        sel = str(r["subject_selector"])
                        if "@" in sel:
                            email = sel
                        else:
                            subj_ref = sel

                    state = "PRESENT"
                    if status_code == 404:
                        state = "ABSENT"
                    elif cat == "DATA_FLOW":
                        if "enabled" in r:
                            state = "ACTIVE" if r.get("enabled") else "DISABLED"
                        else:
                            status_str = str(r.get("status", "")).upper()
                            state = "ACTIVE" if "ACTIVE" in status_str or "HEALTHY" in status_str or "ENABLED" in status_str else "DISABLED"
                    elif cat == "BACKUP_ARCHIVE":
                        restore_allowed = r.get("restore_allowed", False)
                        state = "ACTIVE" if restore_allowed else "BLOCKED"
                    elif cat == "ANALYTICS_PROFILE":
                        if not any([subj_ref, name, email, phone, email_hash]):
                            state = "ANONYMIZED"
                        else:
                            state = "PRESENT"
                    elif cat == "SUPPORT_MESSAGE":
                        # If PII was removed/redacted
                        if not any([email, phone, name]):
                            state = "REDACTED"
                        else:
                            state = "PRESENT"

                    records.append(
                        EvidenceRecord(
                            file_id=file_id,
                            origin=source,
                            captured_at=obs_at,
                            system_id=svc_name,
                            resource_id=res_id,
                            data_category=cat,
                            state=state,
                            subject_reference=str(subj_ref) if subj_ref else None,
                            email=str(email) if email else None,
                            phone=str(phone) if phone else None,
                            email_hash=str(email_hash) if email_hash else None,
                            name=str(name) if name else None,
                            attributes={"status_code": status_code, "collection": coll_name, **r},
                        )
                    )

    # Case 3: Other JSON collections (connector_configurations, customer_export_manifest, customer_analytics_report, etc.)
    elif "records" in data:
        exp_at = data.get("exported_at") or data.get("captured_at") or captured_at
        source = data.get("origin") or data.get("source") or origin
        coll_name = str(data.get("collection", ""))

        for r in data["records"]:
            res_id = str(r.get("resource_id", ""))
            subj_ref = r.get("customer_reference") or r.get("subject_reference") or r.get("owner")
            name = r.get("full_name") or r.get("name")
            email = r.get("email") or r.get("owner")
            phone = r.get("phone")
            email_hash = r.get("email_hash")

            cat = "USER_PROFILE"
            system_id = origin
            if "connector" in path.name or "data_flow" in res_id:
                cat = "DATA_FLOW"
                system_id = "integration_service"
            elif "export" in path.name or "export" in res_id:
                cat = "USER_EXPORT"
                system_id = "export_service"
            elif "analytics" in path.name or "analytics" in res_id:
                cat = "ANALYTICS_PROFILE"
                system_id = "analytics_platform"
            elif "audit" in path.name or "audit_record" in res_id:
                cat = "SECURITY_AUDIT_LOG"
                system_id = "security_service"

            if not email and "subject_selector" in r:
                sel = str(r["subject_selector"])
                if "@" in sel:
                    email = sel
                else:
                    subj_ref = sel

            state = "PRESENT"
            if cat == "DATA_FLOW":
                status_str = str(r.get("status", "")).upper()
                state = "ACTIVE" if "ACTIVE" in status_str or "HEALTHY" in status_str or "ENABLED" in status_str else "DISABLED"
            elif cat == "ANALYTICS_PROFILE":
                if not any([subj_ref, name, email, phone, email_hash]):
                    state = "ANONYMIZED"
                else:
                    state = "PRESENT"

            records.append(
                EvidenceRecord(
                    file_id=file_id,
                    origin=source,
                    captured_at=exp_at,
                    system_id=system_id,
                    resource_id=res_id,
                    data_category=cat,
                    state=state,
                    subject_reference=str(subj_ref) if subj_ref else None,
                    email=str(email) if email else None,
                    phone=str(phone) if phone else None,
                    email_hash=str(email_hash) if email_hash else None,
                    name=str(name) if name else None,
                    attributes={"file_source": path.name, **r},
                )
            )

    return records
