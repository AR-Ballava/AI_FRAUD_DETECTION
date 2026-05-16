from __future__ import annotations

import html
import re
import unicodedata


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\ufeff]")


def sanitize_text(value: str, max_chars: int) -> str:
    normalized = unicodedata.normalize("NFKC", value or "")
    normalized = ZERO_WIDTH.sub("", normalized)
    normalized = CONTROL_CHARS.sub(" ", normalized)
    normalized = html.unescape(normalized)
    normalized = re.sub(r"[ \t]{2,}", " ", normalized)
    normalized = re.sub(r"\n{4,}", "\n\n\n", normalized).strip()
    if len(normalized) > max_chars:
        raise ValueError(f"Text exceeds maximum size of {max_chars} characters")
    return normalized

