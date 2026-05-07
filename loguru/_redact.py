"""Patcher factory for scrubbing common secret patterns from log messages.

The :func:`redact` factory returns a patcher callable suitable for use with
:meth:`loguru._logger.Logger.patch` (or :meth:`Logger.configure`). The patcher
mutates ``record["message"]`` in place, replacing matches of well-known secret
patterns (passwords, API keys, tokens, ``Authorization`` headers) with the
literal string ``[REDACTED]``. Caller-supplied patterns are also supported.

The module deliberately uses an unannotated source signature so it remains
importable on Python 3.5 (Loguru's lower bound). Type information for static
type checkers lives in ``loguru/__init__.pyi``.
"""

import re

# Built-in patterns are written with two capture groups:
#   group 1 = the "prefix" we want to keep (e.g. ``password=``)
#   group 2 = the secret value we want to scrub
# Replacement is ``\g<1>[REDACTED]`` so the key/header name is preserved while
# the value is replaced. All built-ins are case-insensitive.
_VALUE_CHARS = r"[^\s\"',;}\)]+"

_BUILTIN_PATTERNS = [
    # password / passwd / pwd / pass
    re.compile(
        r"\b((?:password|passwd|pwd|pass)\s*[:=]\s*[\"']?)(" + _VALUE_CHARS + r")",
        re.IGNORECASE,
    ),
    # api_key / apikey / api-key / secret / client_secret
    re.compile(
        r"\b((?:api[_-]?key|apikey|client[_-]?secret|secret)\s*[:=]\s*[\"']?)"
        r"(" + _VALUE_CHARS + r")",
        re.IGNORECASE,
    ),
    # token / access_token / auth_token
    re.compile(
        r"\b((?:access[_-]?token|auth[_-]?token|token)\s*[:=]\s*[\"']?)" r"(" + _VALUE_CHARS + r")",
        re.IGNORECASE,
    ),
    # Authorization: Bearer <token> / Authorization: Token <token>
    re.compile(
        r"(Authorization\s*:\s*(?:Bearer|Token)\s+)(\S+)",
        re.IGNORECASE,
    ),
]

_BUILTIN_REPLACEMENT = r"\g<1>[REDACTED]"
_EXTRA_REPLACEMENT = "[REDACTED]"


def redact(*extra_patterns):
    """Build a patcher that scrubs secrets from ``record["message"]``.

    Each argument in ``extra_patterns`` may be either a regex source string or
    a pre-compiled regex object. String patterns are compiled once with
    ``re.IGNORECASE``; pre-compiled patterns are used as-is so callers retain
    full control of flags. Extra patterns replace the entire match with
    ``[REDACTED]`` (no capture-group preservation).
    """
    extras = []
    for pattern in extra_patterns:
        if isinstance(pattern, str):
            extras.append(re.compile(pattern, re.IGNORECASE))
        else:
            extras.append(pattern)

    def patcher(record):
        message = record["message"]
        for regex in _BUILTIN_PATTERNS:
            message = regex.sub(_BUILTIN_REPLACEMENT, message)
        for regex in extras:
            message = regex.sub(_EXTRA_REPLACEMENT, message)
        record["message"] = message

    return patcher
