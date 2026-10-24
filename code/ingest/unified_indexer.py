"""Unified in-memory indexer for all 94 evidence files in HackerRank Orchestrate."""

from __future__ import annotations

import csv
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from code.ingest.json_parser import parse_json_evidence_file
from code.ingest.log_parser import parse_log_or_text_file
from code.ingest.sqlite_parser import parse_sqlite_snapshot
from code.ingest.unstructured_parser import parse_unstructured_evidence
from code.schema import EvidenceRecord, ResolvedIdentity


class EvidenceIndexer:
    """In-memory multi-attribute grounded index over all evidence records."""

    def __init__(self) -> None:
        self.all_records: list[EvidenceRecord] = []
        self._by_email: dict[str, list[EvidenceRecord]] = defaultdict(list)
        self._by_user_id: dict[str, list[EvidenceRecord]] = defaultdict(list)
        self._by_resource_id: dict[str, list[EvidenceRecord]] = defaultdict(list)
        self._by_file_id: dict[str, list[EvidenceRecord]] = defaultdict(list)
        self.manifest: dict[str, dict[str, str]] = {}

    def load_all_evidence(self, manifest_path: str | Path = "dataset/evidence_files.csv") -> None:
        """Parse and index all 94 evidence files in dataset/."""
        path = Path(manifest_path)
        with path.open("r", encoding="utf-8") as f:
            manifest_rows = list(csv.DictReader(f))

        self.manifest = {r["file_id"]: r for r in manifest_rows}

        # 1. Unstructured manifest (15 PNG/PDF files)
        unstructured_records = parse_unstructured_evidence()
        for rec in unstructured_records:
            self._add_record(rec)

        unstructured_fids = {r.file_id for r in unstructured_records}

        # 2. Structured evidence files
        for item in manifest_rows:
            fid = item["file_id"]
            if fid in unstructured_fids:
                continue

            rel_path = item["file_path"].replace("/", os.sep)
            full_path = Path("dataset") / rel_path
            captured_at = item["captured_at"]
            origin = item["origin"]

            if not full_path.exists():
                continue

            if rel_path.endswith(".sql"):
                recs = parse_sqlite_snapshot(full_path, fid, captured_at, origin)
            elif rel_path.endswith(".json"):
                recs = parse_json_evidence_file(full_path, fid, captured_at, origin)
            elif rel_path.endswith(".log") or rel_path.endswith(".txt"):
                recs = parse_log_or_text_file(full_path, fid, captured_at, origin)
            else:
                recs = []

            for r in recs:
                self._add_record(r)

    def _add_record(self, record: EvidenceRecord) -> None:
        """Add a single record to internal indices."""
        self.all_records.append(record)

        if record.resource_id:
            self._by_resource_id[record.resource_id.lower()].append(record)

        if record.file_id:
            self._by_file_id[record.file_id].append(record)

        if record.email:
            self._by_email[record.email.strip().lower()].append(record)

        if record.subject_reference:
            subj = record.subject_reference.strip().lower()
            if "@" in subj:
                self._by_email[subj].append(record)
            else:
                self._by_user_id[subj].append(record)

    def get_records_for_identity(
        self,
        identity: ResolvedIdentity,
        audit_at: str,
    ) -> list[EvidenceRecord]:
        """Retrieve all evidence records matching an identity cluster captured at or before audit_at."""
        candidate_records: list[EvidenceRecord] = []
        seen_keys: set[tuple[str, str, str]] = set()

        # Query by emails
        for em in identity.emails:
            for rec in self._by_email.get(em.strip().lower(), []):
                if rec.captured_at <= audit_at:
                    key = (rec.file_id, rec.system_id, rec.resource_id)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        candidate_records.append(rec)

        # Query by user_id
        if identity.user_id:
            for rec in self._by_user_id.get(identity.user_id.strip().lower(), []):
                if rec.captured_at <= audit_at:
                    key = (rec.file_id, rec.system_id, rec.resource_id)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        candidate_records.append(rec)

        # Sort candidate records chronologically
        candidate_records.sort(key=lambda r: r.captured_at)
        return candidate_records

    def get_latest_record_for_resource(
        self,
        resource_id: str,
        audit_at: str,
    ) -> EvidenceRecord | None:
        """Get the latest chronological evidence record for a resource at or before audit_at."""
        recs = [
            r
            for r in self._by_resource_id.get(resource_id.strip().lower(), [])
            if r.captured_at <= audit_at
        ]
        if not recs:
            return None
        recs.sort(key=lambda r: r.captured_at)
        return recs[-1]

    def get_all_records_for_resource(
        self,
        resource_id: str,
        audit_at: str,
    ) -> list[EvidenceRecord]:
        """Get all chronological evidence records for a resource at or before audit_at."""
        recs = [
            r
            for r in self._by_resource_id.get(resource_id.strip().lower(), [])
            if r.captured_at <= audit_at
        ]
        recs.sort(key=lambda r: r.captured_at)
        return recs
