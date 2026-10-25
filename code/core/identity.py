"""Identity Graph Resolution Module.

Reconstructs canonical user identity profiles from current snapshots
(dataset/user_identities.csv) and historical audit records (dataset/user_audit_log.csv).
Provides bijective email-to-user resolution and identity attribute matching.
"""

from __future__ import annotations
import csv
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


def compute_email_hash(email: str) -> str:
    """Computes SHA-256 hex digest for normalized email string."""
    return hashlib.sha256(email.lower().strip().encode("utf-8")).hexdigest()


@dataclass
class UserProfile:
    """Canonical representation of a user's multi-temporal identity graph."""
    user_id: str
    name: str
    canonical_email: str
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)

    def matches_identifier(self, identifier: Optional[str]) -> bool:
        """Checks if a given string matches any of the user's identifiers."""
        if not identifier:
            return False
        ident_str = str(identifier).strip()
        ident_lower = ident_str.lower()

        if ident_str == self.user_id:
            return True
        if ident_lower in self.emails:
            return True
        if ident_str in self.phones:
            return True
        if ident_str in self.hashes or ident_lower in self.hashes:
            return True
        if ident_str in self.names:
            return True
        return False


class IdentityGraph:
    """Bijective resolver for user identity records."""

    def __init__(self, identities_csv_path: str, audit_log_csv_path: str) -> None:
        self.users: Dict[str, UserProfile] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self._load_identities(identities_csv_path)
        self._load_audit_history(audit_log_csv_path)
        self._build_index()

    def _load_identities(self, path: str) -> None:
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                email = row["email"].lower().strip()
                phone = row["phone"].strip()
                name = row["name"].strip()
                email_hash = row["email_hash"].strip()

                profile = UserProfile(
                    user_id=uid,
                    name=name,
                    canonical_email=email,
                    emails={email},
                    phones={phone} if phone else set(),
                    names={name} if name else set(),
                    hashes={email_hash, compute_email_hash(email)} if email_hash else {compute_email_hash(email)},
                )
                self.users[uid] = profile

    def _load_audit_history(self, path: str) -> None:
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                if uid not in self.users:
                    continue

                field_name = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()
                user = self.users[uid]

                if field_name == "email":
                    if old_val:
                        user.emails.add(old_val.lower())
                        user.hashes.add(compute_email_hash(old_val))
                    if new_val:
                        user.emails.add(new_val.lower())
                        user.hashes.add(compute_email_hash(new_val))
                elif field_name == "phone":
                    if old_val:
                        user.phones.add(old_val)
                    if new_val:
                        user.phones.add(new_val)
                elif field_name == "email_hash":
                    if old_val:
                        user.hashes.add(old_val)
                    if new_val:
                        user.hashes.add(new_val)

    def _build_index(self) -> None:
        for uid, user in self.users.items():
            for email in user.emails:
                self.email_to_uid[email] = uid
            for h in user.hashes:
                self.hash_to_uid[h.lower().strip()] = uid

    def resolve_by_email(self, email: str) -> Optional[UserProfile]:
        """Resolves an email (current or historical) to its UserProfile."""
        if not email:
            return None
        norm_email = email.lower().strip()
        uid = self.email_to_uid.get(norm_email)
        return self.users.get(uid) if uid else None

    def resolve_by_hash(self, email_hash: str) -> Optional[UserProfile]:
        """Resolves a SHA-256 email hash to its UserProfile."""
        if not email_hash:
            return None
        uid = self.hash_to_uid.get(email_hash.lower().strip())
        return self.users.get(uid) if uid else None

    def get_by_user_id(self, user_id: str) -> Optional[UserProfile]:
        """Retrieves user profile directly by canonical user_id."""
        return self.users.get(user_id.strip()) if user_id else None
