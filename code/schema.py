"""Pydantic data models and schemas for HackerRank Orchestrate: Ghost Data Still Exists."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


# Allowed Phases
StepPhase = Literal["FINDING", "REMEDIATION", "VERIFICATION"]

# Allowed Operations
FindingOperation = Literal[
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]

RemediationOperation = Literal[
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]

VerificationOperation = Literal[
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

StepOperation = FindingOperation | RemediationOperation | VerificationOperation

# Allowed States
StepState = Literal[
    "PRESENT",
    "ABSENT",
    "REDACTED",
    "ANONYMIZED",
    "ACTIVE",
    "DISABLED",
    "BLOCKED",
]

# Deletion Status
DeletionStatus = Literal["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]

# Canonical sorting ranks
PHASE_RANK: dict[str, int] = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OPERATION_RANK: dict[str, int] = {
    # Findings
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    # Verification
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


class DeletionStep(BaseModel):
    """Represents a single step in steps_json."""

    model_config = ConfigDict(extra="forbid")

    step_no: int = Field(..., description="1-indexed consecutive step number")
    phase: StepPhase = Field(..., description="FINDING, REMEDIATION, or VERIFICATION")
    system_id: str = Field(..., description="Target system identifier")
    resource_id: str = Field(..., description="Target resource identifier")
    operation: StepOperation = Field(..., description="Allowed operation")
    state: StepState = Field(..., description="Observed or target state")
    evidence_id: str = Field(default="", description="Citing file_id/activity_id or empty string")

    def sort_key(self) -> tuple[int, int, str, str]:
        """Canonical 4-tuple sort key conforming to problem statement §126."""
        return (
            PHASE_RANK.get(self.phase, 99),
            OPERATION_RANK.get(self.operation, 99),
            self.system_id,
            self.resource_id,
        )


class CaseRequest(BaseModel):
    """Input case from deletion_requests.csv."""

    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


class ResolvedIdentity(BaseModel):
    """User identity cluster resolved through transitive closure."""

    user_id: str | None = None
    names: set[str] = Field(default_factory=set)
    emails: set[str] = Field(default_factory=set)
    phones: set[str] = Field(default_factory=set)
    email_hashes: set[str] = Field(default_factory=set)

    def matches(
        self,
        *,
        user_id: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        email_hash: str | None = None,
        name: str | None = None,
    ) -> bool:
        """Check if any attribute matches this identity cluster."""
        if user_id and self.user_id and user_id.lower() == self.user_id.lower():
            return True
        if email and email.strip().lower() in {e.lower() for e in self.emails}:
            return True
        if email_hash and email_hash.strip().lower() in {h.lower() for h in self.email_hashes}:
            return True
        if phone and phone.strip() in self.phones:
            return True
        if name and name.strip().lower() in {n.lower() for n in self.names}:
            return True
        return False


class EvidenceRecord(BaseModel):
    """A grounded record extracted from an evidence file or snapshot."""

    file_id: str
    origin: str
    captured_at: str
    system_id: str
    resource_id: str
    data_category: str
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    subject_reference: str | None = None
    email: str | None = None
    email_hash: str | None = None
    phone: str | None = None
    name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
