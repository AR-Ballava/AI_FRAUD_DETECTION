import base64
import io

from pypdf import PdfReader


class PdfExtractionError(ValueError):
    pass


def extract_text_from_pdf_bytes(data: bytes, max_bytes: int) -> str:
    if len(data) > max_bytes:
        raise PdfExtractionError("PDF exceeds configured maximum file size")
    if not data.startswith(b"%PDF"):
        raise PdfExtractionError("Uploaded content is not a valid PDF signature")

    try:
        reader = PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages[:40]:
            pages.append(page.extract_text() or "")
    except Exception as exc:  # pypdf can raise a broad family of parser exceptions.
        raise PdfExtractionError("Unable to extract text from PDF") from exc

    text = "\n".join(pages).strip()
    if not text:
        raise PdfExtractionError("No embedded PDF text found; OCR is required for this file")
    return text


def extract_text_from_base64_pdf(payload: str, max_bytes: int) -> str:
    try:
        data = base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise PdfExtractionError("Invalid base64 PDF payload") from exc
    return extract_text_from_pdf_bytes(data, max_bytes=max_bytes)

