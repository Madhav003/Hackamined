"""
=============================================================================
PII Shield — Multi-Format Ingestion Module
=============================================================================
Handles text extraction from various document formats:
  • PDF  → PyMuPDF (fitz)
  • DOCX → python-docx
  • TXT  → Direct read with encoding detection
  • Images → Routed to OCR pipeline (see ocr_pipeline.py)

Presidio only accepts plain text, so this module acts as the
format-agnostic front door to the analysis pipeline.
=============================================================================
"""

import os
import logging

logger = logging.getLogger(__name__)


def extract_text_from_pdf(filepath: str) -> str:
    """
    Extract text from a PDF file using PyMuPDF (fitz).
    
    Handles multi-page PDFs and concatenates text from all pages.
    Falls back gracefully if a page contains only images (no extractable text).
    """
    import fitz  # PyMuPDF

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PDF file not found: {filepath}")

    doc = fitz.open(filepath)
    pages_text = []

    for page_num, page in enumerate(doc):
        text = page.get_text("text")
        if text.strip():
            pages_text.append(text)
            logger.debug("PDF page %d: extracted %d chars", page_num + 1, len(text))
        else:
            logger.warning("PDF page %d: no extractable text (may be image-only)", page_num + 1)

    doc.close()
    full_text = "\n\n".join(pages_text)
    logger.info("PDF ingestion complete: %d pages, %d total chars", len(pages_text), len(full_text))
    return full_text


def extract_text_from_docx(filepath: str) -> str:
    """
    Extract text from a DOCX file using python-docx.
    
    Extracts from:
      • Paragraphs (main body text)
      • Table cells (common in forms and structured documents)
    """
    from docx import Document

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"DOCX file not found: {filepath}")

    doc = Document(filepath)
    parts = []

    # Extract paragraphs
    for para in doc.paragraphs:
        if para.text.strip():
            parts.append(para.text)

    # Extract table cell content (ID cards, KYC forms often use tables)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text.strip():
                    parts.append(cell.text)

    full_text = "\n".join(parts)
    logger.info("DOCX ingestion complete: %d text segments, %d total chars",
                len(parts), len(full_text))
    return full_text


def extract_text_from_txt(filepath: str) -> str:
    """
    Read a plain text file with UTF-8 encoding (fallback to latin-1).
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Text file not found: {filepath}")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except UnicodeDecodeError:
        with open(filepath, "r", encoding="latin-1") as f:
            text = f.read()
        logger.warning("Fell back to latin-1 encoding for: %s", filepath)

    logger.info("TXT ingestion complete: %d chars from %s", len(text), filepath)
    return text


def extract_text_from_csv(filepath: str) -> str:
    """
    Read a CSV file and return its content as plain text.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except UnicodeDecodeError:
        with open(filepath, "r", encoding="latin-1") as f:
            text = f.read()

    logger.info("CSV ingestion complete: %d chars from %s", len(text), filepath)
    return text


def extract_text_from_xlsx(filepath: str) -> str:
    """
    Extract text from an Excel .xlsx file by reading all sheets.
    """
    import pandas as pd

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"XLSX file not found: {filepath}")

    xls = pd.ExcelFile(filepath)
    parts = []
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str)
        parts.append(df.fillna("").to_string(index=False))

    full_text = "\n\n".join(parts)
    logger.info("XLSX ingestion complete: %d sheets, %d total chars",
                len(xls.sheet_names), len(full_text))
    return full_text


def ingest_file(filepath: str) -> str:
    """
    Router: detect file type and dispatch to the appropriate extractor.
    
    Supported extensions: .pdf, .docx, .txt, .sql
    Images (.png, .jpg, .jpeg) are handled by ocr_pipeline.py directly.
    
    Returns:
        Extracted plain text from the file.
    """
    ext = os.path.splitext(filepath)[1].lower()

    extractors = {
        ".pdf":  extract_text_from_pdf,
        ".docx": extract_text_from_docx,
        ".txt":  extract_text_from_txt,
        ".csv":  extract_text_from_csv,
        ".xlsx": extract_text_from_xlsx,
        ".sql":  extract_text_from_txt,  # SQL files are plain text
    }

    if ext in extractors:
        logger.info("Ingesting %s file: %s", ext.upper(), os.path.basename(filepath))
        return extractors[ext](filepath)
    elif ext in (".png", ".jpg", ".jpeg", ".bmp", ".tiff"):
        # Route to OCR pipeline
        from ocr_pipeline import extract_text_from_image
        logger.info("Routing image to OCR pipeline: %s", os.path.basename(filepath))
        return extract_text_from_image(filepath)
    else:
        raise ValueError(f"Unsupported file format: {ext}")
