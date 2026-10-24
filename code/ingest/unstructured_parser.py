"""Parser for offline multimodal extracted evidence in code/ingest/extracted_unstructured_evidence.json."""

from __future__ import annotations

import json
from pathlib import Path

from code.schema import EvidenceRecord


def parse_unstructured_evidence(
    manifest_path: str | Path = "code/ingest/extracted_unstructured_evidence.json",
) -> list[EvidenceRecord]:
    """Load all records from extracted_unstructured_evidence.json into normalized EvidenceRecord models."""
    path = Path(manifest_path)
    if not path.exists():
        raise FileNotFoundError(f"Unstructured evidence manifest not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    records: list[EvidenceRecord] = []
    for file_entry in data:
        file_id = file_entry["file_id"]
        origin = file_entry["origin"]
        captured_at = file_entry["captured_at"]

        for r in file_entry.get("records", []):
            records.append(
                EvidenceRecord(
                    file_id=file_id,
                    origin=origin,
                    captured_at=captured_at,
                    system_id=r["system_id"],
                    resource_id=r["resource_id"],
                    data_category=r["data_category"],
                    state=r["state"],
                    subject_reference=r.get("subject_reference"),
                    email=r.get("email"),
                    phone=r.get("phone"),
                    email_hash=r.get("email_hash"),
                    name=r.get("name"),
                    attributes=r.get("attributes", {}),
                )
            )

    return records
