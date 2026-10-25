"""Request Intent Classification Module.

Determines whether a subject's request authorizes personal data deletion
under GDPR Art. 17 / CCPA or constitutes a non-deletion request (e.g.
GDPR Art. 15 Access, Art. 16 Rectification, Art. 20 Portability, Opt-out).
"""

from __future__ import annotations
import re

# Precise patterns identifying explicit non-deletion intents (access, rectification,
# data export, marketing opt-out, login help, retention requests).
NON_DELETION_PATTERNS = [
    re.compile(r"leave (?:the |my )?account active", re.IGNORECASE),
    re.compile(r"keep (?:the )?account", re.IGNORECASE),
    re.compile(r"not asking for deletion", re.IGNORECASE),
    re.compile(r"not a request to erase", re.IGNORECASE),
    re.compile(r"without removing", re.IGNORECASE),
    re.compile(r"leave my profile", re.IGNORECASE),
    re.compile(r"do not close", re.IGNORECASE),
    re.compile(r"marketing lists only", re.IGNORECASE),
    re.compile(r"this is an information request", re.IGNORECASE),
    re.compile(r"need help resetting", re.IGNORECASE),
    re.compile(r"continue using the service", re.IGNORECASE),
    re.compile(r"don\'?t delete", re.IGNORECASE),
]


def is_deletion_request(request_text: str) -> bool:
    """Classifies whether the request authorizes data deletion.

    Args:
        request_text: Natural language text from the customer.

    Returns:
        True if the request authorizes deletion, False if it is NOT_APPLICABLE.
    """
    if not request_text:
        return False

    text = request_text.strip()
    for pattern in NON_DELETION_PATTERNS:
        if pattern.search(text):
            return False

    return True
