"""
=============================================================================
PII Shield — SQL Dump Handler
=============================================================================
Safely parses .sql files to sanitize PII in data payloads (INSERT INTO
statements) without breaking SQL syntax or DDL statements.

DESIGN CHALLENGE:
    SQL dumps mix structural commands (CREATE TABLE, ALTER TABLE, indexes)
    with data commands (INSERT INTO ... VALUES ...). We must:
      1. Identify INSERT statements and extract string values
      2. Run Presidio ONLY on the string literals (not column names or SQL keywords)
      3. Replace detected PII in those values
      4. Reassemble the SQL file with sanitized values
      5. Leave all DDL and non-INSERT statements completely untouched

    This is crucial for database migration pipelines where dumps
    must remain syntactically valid after sanitization.
=============================================================================
"""

import re
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


def parse_insert_statements(sql_content: str) -> List[dict]:
    """
    Parse INSERT INTO statements from a SQL dump.
    
    Returns a list of dicts, each containing:
      - 'full_match': the complete INSERT statement string
      - 'table_name': target table
      - 'values_section': the VALUES (...), (...) portion
      - 'start': character offset in original content
      - 'end': character offset in original content
    """
    # Regex to match INSERT INTO statements
    # Handles: INSERT INTO table_name VALUES (...);
    # Also:    INSERT INTO table_name (col1, col2) VALUES (...);
    pattern = re.compile(
        r"(INSERT\s+INTO\s+[`\"']?(\w+)[`\"']?\s*"  # INSERT INTO table_name
        r"(?:\([^)]*\)\s*)?"                          # Optional column list
        r"VALUES\s*"                                   # VALUES keyword
        r"((?:\([^)]*\)\s*,?\s*)+))"                  # One or more value tuples
        r"\s*;",                                       # Terminating semicolon
        re.IGNORECASE | re.DOTALL,
    )

    inserts = []
    for match in pattern.finditer(sql_content):
        inserts.append({
            "full_match":     match.group(0),
            "table_name":     match.group(2),
            "values_section": match.group(3),
            "start":          match.start(),
            "end":            match.end(),
        })

    logger.info("Found %d INSERT statements in SQL dump", len(inserts))
    return inserts


def extract_string_values(values_section: str) -> List[Tuple[str, int, int]]:
    """
    Extract quoted string literals from a VALUES clause.
    
    Returns list of (value, start_offset, end_offset) tuples.
    Ignores numeric values, NULL, and SQL keywords.
    
    Handles:
      • Single-quoted strings: 'John Doe'
      • Escaped quotes: 'O\\'Brien'
    """
    # Match single-quoted strings, handling escaped quotes
    pattern = re.compile(r"'((?:[^'\\]|\\.)*)'")
    
    values = []
    for match in pattern.finditer(values_section):
        value = match.group(1)
        # Skip empty strings and obviously non-PII values
        if value.strip():
            values.append((value, match.start(), match.end()))
    
    return values


def sanitize_sql_file(
    sql_content: str,
    analyze_fn,
    anonymize_fn,
) -> str:
    """
    Process a SQL dump: find INSERT statements, sanitize PII in string
    values, and return the modified SQL with all DDL intact.
    
    Args:
        sql_content: Raw SQL dump text
        analyze_fn:  Function(text) -> List[RecognizerResult]
        anonymize_fn: Function(text, results) -> str
        
    Returns:
        Sanitized SQL dump text
    """
    inserts = parse_insert_statements(sql_content)
    
    if not inserts:
        logger.info("No INSERT statements found — returning SQL unchanged")
        return sql_content

    # Process from the end to preserve character offsets
    sanitized = sql_content
    replacements = []

    for insert_info in reversed(inserts):
        values_section = insert_info["values_section"]
        string_values = extract_string_values(values_section)

        new_values_section = values_section
        # Process from end to preserve offsets within the values section
        for value, start, end in reversed(string_values):
            # Run Presidio on this string value
            results = analyze_fn(value)
            
            if results:
                sanitized_value = anonymize_fn(value, results)
                # Replace in the values section
                original_quoted = new_values_section[start:end]
                new_quoted = f"'{sanitized_value}'"
                new_values_section = (
                    new_values_section[:start] +
                    new_quoted +
                    new_values_section[end:]
                )
                logger.debug("Sanitized value in table '%s': '%s' -> '%s'",
                           insert_info["table_name"], value[:20], sanitized_value[:20])

        # Reconstruct the full INSERT statement
        if new_values_section != values_section:
            new_insert = insert_info["full_match"].replace(values_section, new_values_section)
            sanitized = (
                sanitized[:insert_info["start"]] +
                new_insert +
                sanitized[insert_info["end"]:]
            )
            replacements.append(insert_info["table_name"])

    logger.info("Sanitized INSERT statements in %d tables: %s",
                len(replacements), ", ".join(replacements))
    return sanitized


def process_sql_file(
    filepath: str,
    analyze_fn,
    anonymize_fn,
    output_path: str | None = None,
) -> str:
    """
    End-to-end SQL file sanitization.
    
    Reads a .sql file, sanitizes PII in INSERT values,
    and optionally writes the result to an output file.
    
    Returns the sanitized SQL content.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        sql_content = f.read()

    sanitized = sanitize_sql_file(sql_content, analyze_fn, anonymize_fn)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sanitized)
        logger.info("Sanitized SQL written to: %s", output_path)

    return sanitized
