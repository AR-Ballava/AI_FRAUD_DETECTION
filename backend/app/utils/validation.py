from __future__ import annotations

import mimetypes
from pathlib import Path


PDF_MIME_TYPES = {"application/pdf", "application/x-pdf", "application/octet-stream"}
TEXT_MIME_TYPES = {"text/plain", "application/octet-stream", "text/markdown"}


class ValidationError(ValueError):
    pass


def validate_file_upload(filename: str, content_type: str | None, data: bytes, max_bytes: int) -> str:
    if len(data) > max_bytes:
        raise ValidationError("File exceeds maximum upload size")
    if not data:
        raise ValidationError("Uploaded file is empty")

    safe_name = Path(filename or "upload").name.lower()
    guessed_type = mimetypes.guess_type(safe_name)[0]
    mime = (content_type or guessed_type or "").lower()

    if data.startswith(b"%PDF"):
        if mime and mime not in PDF_MIME_TYPES:
            raise ValidationError("PDF content does not match declared MIME type")
        return "pdf"

    if safe_name.endswith(".pdf") or mime == "application/pdf":
        raise ValidationError("Invalid PDF signature")

    if mime in TEXT_MIME_TYPES or safe_name.endswith((".txt", ".md", ".eml")):
        return "text"

    raise ValidationError("Only PDF and text-like uploads are supported")


def decode_text_file(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValidationError("Unable to decode uploaded text file")

