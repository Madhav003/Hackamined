"""
=============================================================================
PII Shield — File Handler Factory
=============================================================================
Handles extraction, sanitization, and reconstruction for each supported
file type. Each handler receives a sanitization callback:

    process_text_with_presidio(raw_text: str) -> str

This module NEVER calls Presidio directly — it delegates all NLP work
to the callback, keeping file I/O and AI concerns cleanly separated.

Supported formats:
  .txt / .csv  — plain-text read → sanitize → write
  .docx        — paragraph-level sanitization preserving formatting
  .pdf         — redact PII words with black boxes (PyMuPDF)
  .xlsx        — cell-level sanitization via pandas
  .sql         — delegated to existing sql_handler module
=============================================================================
"""

import logging
import os
from typing import Callable

logger = logging.getLogger(__name__)

# Type alias for the sanitization callback
SanitizeFn = Callable[[str], str]


# ---------------------------------------------------------------------------
# .txt / .csv handler
# ---------------------------------------------------------------------------

def handle_txt(input_path: str, output_path: str, sanitize: SanitizeFn) -> dict:
    """
    Read a plain-text or CSV file, sanitize it line-by-line to preserve
    row structure, and write the result.
    """
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
    except UnicodeDecodeError:
        with open(input_path, "r", encoding="latin-1") as f:
            raw_text = f.read()

    sanitized_text = sanitize(raw_text)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(sanitized_text)

    pii_count = _estimate_pii_count(raw_text, sanitized_text)
    logger.info("TXT/CSV handler: %s → %s (%d PII replacements)",
                os.path.basename(input_path), os.path.basename(output_path), pii_count)
    return {"status": "Success", "pii_count": pii_count, "output_path": output_path}


# ---------------------------------------------------------------------------
# .docx handler
# ---------------------------------------------------------------------------

def handle_docx(input_path: str, output_path: str, sanitize: SanitizeFn) -> dict:
    """
    Iterate through every paragraph and table cell in a .docx,
    sanitize PII, and save a new .docx preserving formatting.
    """
    from docx import Document

    doc = Document(input_path)
    pii_count = 0

    # Sanitize paragraphs
    for para in doc.paragraphs:
        if para.text.strip():
            original = para.text
            cleaned = sanitize(original)
            if cleaned != original:
                pii_count += _estimate_pii_count(original, cleaned)
                # Replace text while keeping runs for basic formatting
                _replace_paragraph_text(para, cleaned)

    # Sanitize table cells
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    if para.text.strip():
                        original = para.text
                        cleaned = sanitize(original)
                        if cleaned != original:
                            pii_count += _estimate_pii_count(original, cleaned)
                            _replace_paragraph_text(para, cleaned)

    doc.save(output_path)
    logger.info("DOCX handler: %s → %s (%d PII replacements)",
                os.path.basename(input_path), os.path.basename(output_path), pii_count)
    return {"status": "Success", "pii_count": pii_count, "output_path": output_path}


def _replace_paragraph_text(paragraph, new_text: str):
    """Replace all text in a paragraph's runs with new_text."""
    if not paragraph.runs:
        paragraph.text = new_text
        return
    # Put all new text in the first run, clear the rest
    paragraph.runs[0].text = new_text
    for run in paragraph.runs[1:]:
        run.text = ""


# ---------------------------------------------------------------------------
# .pdf handler  (PyMuPDF redaction — black boxes over PII)
# ---------------------------------------------------------------------------

def handle_pdf(input_path: str, output_path: str, sanitize: SanitizeFn) -> dict:
    """
    Extract text from each PDF page, identify PII word *positions* by
    comparing positioned word lists, then draw black redaction boxes
    over only those exact bounding boxes using PyMuPDF's redaction API.

    Uses page.get_text("words") so each word maps 1:1 to its bounding
    box — avoids the old search_for() approach that redacted ALL
    occurrences of a word on the page.
    """
    import fitz  # PyMuPDF
    from analyzer_engine import analyze_text
    from context_rules import apply_context_rules

    doc = fitz.open(input_path)
    pii_count = 0
    original_parts = []
    sanitized_parts = []

    # Lazy-import pipeline to get the shared analyzer instance
    from app import get_pipeline
    pipeline = get_pipeline()

    for page in doc:
        page_text = page.get_text("text")
        if not page_text.strip():
            continue

        # Text preview: sanitize the natural page text (preserves newlines)
        original_parts.append(page_text)
        sanitized_parts.append(sanitize(page_text))

        # ----- Visual PDF redaction using word-level positions -----
        word_tuples = page.get_text("words")
        # Each tuple: (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        if not word_tuples:
            continue

        # Build word list from positioned words (1:1 with bounding boxes)
        orig_words = [w[4] for w in word_tuples]
        reconstructed = " ".join(orig_words)

        # Use Presidio to get exact character offsets of PII in the
        # reconstructed string, then map those offsets to word indices.
        results = analyze_text(pipeline.analyzer, reconstructed)
        results = apply_context_rules(reconstructed, results)

        # Build a char-offset → word-index map
        word_char_starts = []  # char offset where each word begins
        offset = 0
        for word in orig_words:
            word_char_starts.append(offset)
            offset += len(word) + 1  # +1 for the space separator

        pii_indices = set()
        for entity in results:
            # Find all word indices whose character range overlaps this entity
            for i, w_start in enumerate(word_char_starts):
                w_end = w_start + len(orig_words[i])
                # Overlap check: word [w_start, w_end) vs entity [entity.start, entity.end)
                if w_start < entity.end and w_end > entity.start:
                    pii_indices.add(i)

        pii_count += len(pii_indices)

        # Redact only the specific PII word bounding boxes
        for idx in pii_indices:
            rect = fitz.Rect(word_tuples[idx][:4])
            page.add_redact_annot(rect, fill=(0, 0, 0))

        if pii_indices:
            page.apply_redactions()

    doc.save(output_path, garbage=4, deflate=True)
    doc.close()

    original_text = "\n\n".join(original_parts)
    sanitized_text = "\n\n".join(sanitized_parts)

    logger.info("PDF handler: %s → %s (%d PII words redacted)",
                os.path.basename(input_path), os.path.basename(output_path), pii_count)
    return {
        "status": "Success",
        "pii_count": pii_count,
        "output_path": output_path,
        "original_text": original_text,
        "sanitized_text": sanitized_text,
    }


def _find_pii_words(original: str, sanitized: str) -> list:
    """
    Compare original text with sanitized text using difflib to find
    original words that were replaced by PII redaction tags.
    Uses SequenceMatcher to handle word-count changes (e.g. two-word
    names replaced by a single [REDACTED] tag) without cascading
    false positives.
    """
    import difflib

    orig_words = original.split()
    san_words = sanitized.split()
    pii_words = []

    matcher = difflib.SequenceMatcher(None, orig_words, san_words, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # 'replace' or 'delete': the original words were PII
        if tag in ("replace", "delete"):
            for k in range(i1, i2):
                cleaned = orig_words[k].strip(".,;:!?\"'()[]{}")
                if cleaned and len(cleaned) > 1:
                    pii_words.append(cleaned)

    return list(dict.fromkeys(pii_words))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# .xlsx handler
# ---------------------------------------------------------------------------

def handle_xlsx(input_path: str, output_path: str, sanitize: SanitizeFn) -> dict:
    """
    Read an Excel workbook with pandas, apply sanitization to every
    string cell, and export to a new .xlsx.
    Limits to 1000 rows per sheet to avoid timeouts on large files.
    """
    import pandas as pd

    MAX_ROWS = 1000
    xls = pd.ExcelFile(input_path, engine="openpyxl")
    pii_count = 0
    truncated = False
    original_parts = []
    sanitized_parts = []

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for sheet_name in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str,
                               engine="openpyxl", nrows=MAX_ROWS)

            # Check if the sheet was truncated
            df_check = pd.read_excel(xls, sheet_name=sheet_name, dtype=str,
                                     engine="openpyxl", nrows=MAX_ROWS + 1)
            if len(df_check) > MAX_ROWS:
                truncated = True

            # Capture original text before sanitization
            original_parts.append(df.fillna("").to_string(index=False))

            for col in df.columns:
                for idx in df.index:
                    val = df.at[idx, col]
                    if isinstance(val, str) and val.strip():
                        cleaned = sanitize(val)
                        if cleaned != val:
                            pii_count += _estimate_pii_count(val, cleaned)
                            df.at[idx, col] = cleaned

            # Capture sanitized text after sanitization
            sanitized_parts.append(df.fillna("").to_string(index=False))

            df.to_excel(writer, sheet_name=sheet_name, index=False)

    original_text = "\n\n".join(original_parts)
    sanitized_text = "\n\n".join(sanitized_parts)
    if truncated:
        note = f"\n\n[NOTE: Only the first {MAX_ROWS} rows per sheet were processed.]"
        original_text += note
        sanitized_text += note

    logger.info("XLSX handler: %s → %s (%d PII replacements%s)",
                os.path.basename(input_path), os.path.basename(output_path),
                pii_count, ", truncated" if truncated else "")
    return {
        "status": "Success",
        "pii_count": pii_count,
        "output_path": output_path,
        "original_text": original_text,
        "sanitized_text": sanitized_text,
    }


# ---------------------------------------------------------------------------
# Router — picks the right handler based on file extension
# ---------------------------------------------------------------------------

HANDLERS = {
    ".txt":  handle_txt,
    ".csv":  handle_txt,    # CSV is plain text
    ".docx": handle_docx,
    ".pdf":  handle_pdf,
    ".xlsx": handle_xlsx,
    # .sql is handled separately via sql_handler.py (already works)
}


def process_file(input_path: str, output_dir: str, sanitize: SanitizeFn) -> dict:
    """
    Route a file to the correct handler based on its extension.

    Args:
        input_path:  Path to the uploaded file.
        output_dir:  Directory where the sanitized file will be saved.
        sanitize:    Callback — process_text_with_presidio(text) -> str.

    Returns:
        dict with keys: status, pii_count, output_path
    """
    ext = os.path.splitext(input_path)[1].lower()
    basename = os.path.basename(input_path)
    name, _ = os.path.splitext(basename)
    output_path = os.path.join(output_dir, f"{name}_sanitized{ext}")

    os.makedirs(output_dir, exist_ok=True)

    handler = HANDLERS.get(ext)
    if handler is None:
        raise ValueError(f"Unsupported file type: {ext}")

    return handler(input_path, output_path, sanitize)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _estimate_pii_count(original: str, sanitized: str) -> int:
    """Rough PII count by counting words that differ between original and sanitized."""
    orig_words = original.split()
    san_words = sanitized.split()
    count = 0
    for o, s in zip(orig_words, san_words):
        if o != s:
            count += 1
    return max(count, 1) if original != sanitized else 0
