"""Deterministic parser for structured CSV files in dataset/."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from code.schema import CaseRequest


def parse_csv_file(file_path: str | Path) -> list[dict[str, str]]:
    """Parse a generic CSV file into a list of row dicts."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def parse_deletion_requests(file_path: str | Path) -> list[CaseRequest]:
    """Parse deletion_requests.csv or sample_deletion_requests.csv into CaseRequest models."""
    rows = parse_csv_file(file_path)
    requests = []
    for r in rows:
        requests.append(
            CaseRequest(
                case_id=r["case_id"].strip(),
                email=r["email"].strip(),
                requested_at=r["requested_at"].strip(),
                reported_status=r["reported_status"].strip(),
                reported_at=r["reported_at"].strip(),
                audit_at=r["audit_at"].strip(),
                request_text=r["request_text"].strip(),
            )
        )
    return requests


def parse_user_identities(file_path: str | Path = "dataset/user_identities.csv") -> dict[str, dict[str, str]]:
    """Parse user_identities.csv indexed by user_id."""
    rows = parse_csv_file(file_path)
    return {r["user_id"].strip(): r for r in rows}


def parse_user_audit_log(file_path: str | Path = "dataset/user_audit_log.csv") -> list[dict[str, str]]:
    """Parse user_audit_log.csv returning chronological list of identity changes."""
    return parse_csv_file(file_path)


def parse_system_activity(file_path: str | Path = "dataset/system_activity.csv") -> list[dict[str, str]]:
    """Parse system_activity.csv returning global workflow events."""
    return parse_csv_file(file_path)


def parse_deletion_rules(file_path: str | Path = "dataset/deletion_rules.csv") -> list[dict[str, str]]:
    """Parse deletion_rules.csv returning data treatment policies."""
    return parse_csv_file(file_path)


def parse_evidence_files_manifest(file_path: str | Path = "dataset/evidence_files.csv") -> dict[str, dict[str, str]]:
    """Parse evidence_files.csv indexed by file_id."""
    rows = parse_csv_file(file_path)
    return {r["file_id"].strip(): r for r in rows}
