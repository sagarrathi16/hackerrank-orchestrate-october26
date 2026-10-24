"""Ingestion package for HackerRank Orchestrate: Ghost Data Still Exists."""

from code.ingest.csv_parser import (
    parse_deletion_requests,
    parse_deletion_rules,
    parse_evidence_files_manifest,
    parse_system_activity,
    parse_user_audit_log,
    parse_user_identities,
)
from code.ingest.json_parser import parse_json_evidence_file
from code.ingest.log_parser import parse_log_or_text_file
from code.ingest.sqlite_parser import parse_sqlite_snapshot
from code.ingest.unified_indexer import EvidenceIndexer
from code.ingest.unstructured_parser import parse_unstructured_evidence

__all__ = [
    "EvidenceIndexer",
    "parse_deletion_requests",
    "parse_deletion_rules",
    "parse_evidence_files_manifest",
    "parse_system_activity",
    "parse_user_audit_log",
    "parse_user_identities",
    "parse_sqlite_snapshot",
    "parse_json_evidence_file",
    "parse_log_or_text_file",
    "parse_unstructured_evidence",
]
