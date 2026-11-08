"""
Logging for Falak, with automatic secret redaction.

Falak's logs must never contain WireGuard private keys, preshared keys,
or full configuration file contents that could include them. This
module provides:

  * ``redact_secrets``: a pure text-transform function that masks
    known-sensitive patterns in a string.
  * ``RedactingFilter``: a ``logging.Filter`` that applies
    ``redact_secrets`` to every log record before it is emitted,
    so redaction happens centrally rather than depending on every
    call site remembering to sanitize its own messages.
  * ``get_logger``: a factory that returns a configured logger with
    the redaction filter already attached.

This module does not decide *what* to log - only guarantees that
whatever is logged has known secret patterns masked first.
"""

from __future__ import annotations

import logging
import re

# WireGuard keys (private, public, and preshared) are 32 raw bytes
# base64-encoded, which is always 44 characters and always ends in
# a single '=' padding character. This pattern is specific enough to
# avoid matching ordinary words while catching any raw key that ends
# up in a log message or exception text.
_WG_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?!=)")

# Explicit WireGuard config key-value lines, e.g.:
#   PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
#   PresharedKey=abc123...
# Matched case-insensitively and redacted regardless of whether the
# value happens to match _WG_KEY_PATTERN (covers malformed/short values
# too, so a truncated or corrupted key is still never logged in full).
_WG_KEY_LINE_PATTERN = re.compile(
    r"(?im)^(?P<prefix>\s*(?:PrivateKey|PresharedKey)\s*=\s*)(?P<value>\S+)\s*$"
)

_REDACTED_MARKER = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Return ``text`` with known secret patterns masked.

    This is intentionally conservative: it only masks patterns that
    are specifically characteristic of WireGuard key material. It does
    not attempt general-purpose secret scanning.
    """
    if not text:
        return text

    redacted = _WG_KEY_LINE_PATTERN.sub(
        lambda m: f"{m.group('prefix')}{_REDACTED_MARKER}", text
    )
    redacted = _WG_KEY_PATTERN.sub(_REDACTED_MARKER, redacted)
    return redacted


class RedactingFilter(logging.Filter):
    """A logging filter that redacts secrets from every record.

    Applied to a handler or logger, this rewrites ``record.msg`` (and
    any already-formatted ``%s``-style args) so that secret material
    never reaches a log destination, including when the record args
    are merged into the message lazily by the logging module.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # If message formatting itself fails, don't block logging
            # entirely - fall back to redacting the raw msg field only.
            record.msg = redact_secrets(str(record.msg))
            record.args = ()
            return True

        record.msg = redact_secrets(message)
        record.args = ()
        return True


def get_logger(name: str, *, level: int = logging.INFO) -> logging.Logger:
    """Return a Falak logger configured with secret redaction.

    Safe to call multiple times with the same name; handlers are only
    attached once per logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(handler)

    # This logger's own records should not also be handled by the
    # root logger's handlers (avoids duplicate/unredacted output if
    # the root logger is ever configured elsewhere).
    logger.propagate = False

    return logger
