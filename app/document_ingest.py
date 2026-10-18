"""Local text extraction for uploaded documents."""

from io import BytesIO
from pathlib import Path

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_PDF_PAGES = 10
MAX_IMAGE_PIXELS = 20_000_000


def _extract_document_unchecked(filename: str, raw: bytes) -> str:
    suffix = Path(filename).suffix.lower()

    if suffix in {".txt", ".md"}:
        return raw.decode("utf-8-sig")

    if suffix in {".png", ".jpg", ".jpeg"}:
        from PIL import Image
        import pytesseract

        with Image.open(BytesIO(raw)) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image exceeds the pixel limit.")
            image.load()
            return pytesseract.image_to_string(
                image.convert("RGB"), lang="spa+eng"
            )

    if suffix == ".pdf":
        import fitz
        import pytesseract
        from PIL import Image

        pages_text = []

        with fitz.open(stream=raw, filetype="pdf") as pdf:
            if pdf.page_count > MAX_PDF_PAGES:
                raise ValueError(
                    f"PDF exceeds the {MAX_PDF_PAGES}-page limit."
                )

            for page in pdf:
                text = page.get_text().strip()

                if not text:
                    pix = page.get_pixmap(
                        matrix=fitz.Matrix(1.5, 1.5),
                        alpha=False,
                    )
                    image = Image.open(BytesIO(pix.tobytes("png")))

                    if image.width * image.height > MAX_IMAGE_PIXELS:
                        raise ValueError(
                            "PDF page exceeds the pixel limit."
                        )

                    text = pytesseract.image_to_string(
                        image, lang="spa+eng"
                    )

                pages_text.append(text)

        return "\n\n".join(pages_text)

    if suffix == ".docx":
        from docx import Document

        document = Document(BytesIO(raw))
        paragraphs = [p.text for p in document.paragraphs]

        for table in document.tables:
            for row in table.rows:
                paragraphs.append(
                    " | ".join(cell.text for cell in row.cells)
                )

        return "\n".join(paragraphs)

    raise ValueError("Unsupported file type.")


def extract_document(filename: str, raw: bytes) -> str:
    """Extract text, converting parser failures into a safe ValueError.

    ValueError (our own limits), ImportError (missing optional libraries) and
    OSError (including a missing Tesseract binary) pass through unchanged so
    the UI can show a specific message. Anything else, such as a corrupt ZIP
    inside a DOCX or a malformed PDF, becomes a generic error that never
    includes file contents.
    """
    try:
        return _extract_document_unchecked(filename, raw)
    except (ValueError, ImportError, OSError):
        raise
    except Exception as exc:
        raise ValueError(
            "The file could not be read. It may be corrupt or not match its extension."
        ) from exc
