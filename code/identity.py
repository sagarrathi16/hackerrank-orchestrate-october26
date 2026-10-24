"""Transitive Identity Resolution Engine using Disjoint Set Union (DSU)."""

from __future__ import annotations

import csv
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from code.schema import ResolvedIdentity


class IdentityDSU:
    """Disjoint Set Union (Union-Find) with path compression."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def find(self, item: str) -> str:
        """Find the root representative for an item."""
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0
            return item

        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, item1: str, item2: str) -> None:
        """Union the sets containing item1 and item2."""
        root1 = self.find(item1)
        root2 = self.find(item2)

        if root1 == root2:
            return

        if self.rank[root1] < self.rank[root2]:
            self.parent[root1] = root2
        elif self.rank[root1] > self.rank[root2]:
            self.parent[root2] = root1
        else:
            self.parent[root2] = root1
            self.rank[root1] += 1


class IdentityResolver:
    """Resolves transitive user identities adhering to temporal cutoff (<= audit_at)."""

    def __init__(
        self,
        identities_path: str | Path = "dataset/user_identities.csv",
        audit_log_path: str | Path = "dataset/user_audit_log.csv",
    ) -> None:
        self.identities_path = Path(identities_path)
        self.audit_log_path = Path(audit_log_path)
        self._raw_identities: list[dict[str, str]] = []
        self._raw_audit_log: list[dict[str, str]] = []
        self._load_data()

    def _load_data(self) -> None:
        """Load tabular identities and audit logs."""
        with self.identities_path.open("r", encoding="utf-8") as f:
            self._raw_identities = list(csv.DictReader(f))

        with self.audit_log_path.open("r", encoding="utf-8") as f:
            self._raw_audit_log = list(csv.DictReader(f))

    def resolve_identity(self, email_or_identifier: str, audit_at: str) -> ResolvedIdentity:
        """Resolve a full identity cluster for an email or identifier at or before audit_at."""
        query_norm = email_or_identifier.strip().lower()

        dsu = IdentityDSU()

        # Attribute buckets per component root
        names_by_root: dict[str, set[str]] = defaultdict(set)
        user_id_by_root: dict[str, str] = {}
        emails_by_root: dict[str, set[str]] = defaultdict(set)
        phones_by_root: dict[str, set[str]] = defaultdict(set)
        hashes_by_root: dict[str, set[str]] = defaultdict(set)

        # 1. Base snapshot from user_identities.csv
        for row in self._raw_identities:
            uid = row["user_id"].strip()
            name = row["name"].strip()
            em = row["email"].strip().lower()
            phone = row["phone"].strip()
            em_hash = row["email_hash"].strip().lower()

            dsu.find(uid)
            if em:
                dsu.union(uid, em)
            if phone:
                dsu.union(uid, phone)
            if em_hash:
                dsu.union(uid, em_hash)

        # 2. Historical mutations from user_audit_log.csv (filtered by <= audit_at)
        for row in self._raw_audit_log:
            ev_time = row["event_time"].strip()
            if ev_time > audit_at:
                continue

            uid = row["user_id"].strip()
            fname = row["field_name"].strip()
            old_val = row["old_value"].strip()
            new_val = row["new_value"].strip()

            if fname == "email":
                if old_val:
                    dsu.union(uid, old_val.lower())
                if new_val:
                    dsu.union(uid, new_val.lower())
            elif fname == "phone":
                if old_val:
                    dsu.union(uid, old_val)
                if new_val:
                    dsu.union(uid, new_val)
            elif fname == "email_hash":
                if old_val:
                    dsu.union(uid, old_val.lower())
                if new_val:
                    dsu.union(uid, new_val.lower())

        # 3. Populate attributes into component roots
        # Add from user_identities
        for row in self._raw_identities:
            uid = row["user_id"].strip()
            root = dsu.find(uid)
            user_id_by_root[root] = uid

            if row["name"].strip():
                names_by_root[root].add(row["name"].strip())
            if row["email"].strip():
                emails_by_root[root].add(row["email"].strip().lower())
            if row["phone"].strip():
                phones_by_root[root].add(row["phone"].strip())
            if row["email_hash"].strip():
                hashes_by_root[root].add(row["email_hash"].strip().lower())

        # Add from user_audit_log (<= audit_at)
        for row in self._raw_audit_log:
            ev_time = row["event_time"].strip()
            if ev_time > audit_at:
                continue

            uid = row["user_id"].strip()
            root = dsu.find(uid)
            fname = row["field_name"].strip()
            old_val = row["old_value"].strip()
            new_val = row["new_value"].strip()

            if fname == "email":
                if old_val:
                    emails_by_root[root].add(old_val.lower())
                if new_val:
                    emails_by_root[root].add(new_val.lower())
            elif fname == "phone":
                if old_val:
                    phones_by_root[root].add(old_val)
                if new_val:
                    phones_by_root[root].add(new_val)
            elif fname == "email_hash":
                if old_val:
                    hashes_by_root[root].add(old_val.lower())
                if new_val:
                    hashes_by_root[root].add(new_val.lower())

        # 4. Find the target root for the query
        target_root = dsu.find(query_norm)

        # Collect and compute deterministic SHA-256 digests for all emails
        resolved_emails = emails_by_root.get(target_root, set())
        if query_norm and "@" in query_norm:
            resolved_emails.add(query_norm)

        resolved_hashes = set(hashes_by_root.get(target_root, set()))
        for em in resolved_emails:
            digest = hashlib.sha256(em.encode("utf-8")).hexdigest()
            resolved_hashes.add(digest)

        return ResolvedIdentity(
            user_id=user_id_by_root.get(target_root),
            names=names_by_root.get(target_root, set()),
            emails=resolved_emails,
            phones=phones_by_root.get(target_root, set()),
            email_hashes=resolved_hashes,
        )
