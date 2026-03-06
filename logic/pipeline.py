"""
=============================================================================
PII Shield — Main Pipeline Orchestrator
=============================================================================
Ties all modules together into a single end-to-end processing pipeline.

Workflow:
  1. File Upload → Format Detection → Text Extraction
  2. Presidio Analysis → Custom Indian Recognizers + Built-in
  3. Dual-State Processing → Masked View + Encrypted Raw
  4. Threat Intelligence → Risk Score + Threat Level
  5. Audit Logging → SHA-256 Hash-Chain Entry
  6. Return structured result to Admin

This module serves as the main entry point for the PII Shield system.
=============================================================================
"""

import json
import logging
import os
import sys

from analyzer_engine import create_analyzer, create_anonymizer, analyze_text, anonymize_text
from dual_state import generate_dual_state
from encryption import AESCipher, FPECipher
from threat_intel import generate_threat_report, format_threat_report_text
from audit_logger import AuditLogger
from sql_handler import process_sql_file
from ingestion import ingest_file

logger = logging.getLogger(__name__)


class PIIShieldPipeline:
    """
    Main orchestrator for the PII Shield system.
    
    Coordinates all modules to process documents through the full
    detection → sanitization → encryption → reporting pipeline.
    """

    def __init__(self):
        # Initialize all engines
        self.analyzer = create_analyzer()
        self.anonymizer = create_anonymizer()
        self.aes_cipher = AESCipher()
        self.fpe_cipher = FPECipher()
        self.audit_logger = AuditLogger()
        logger.info("PII Shield Pipeline initialized")

    def process_document(self, filepath: str, user: str = "system") -> dict:
        """
        End-to-end document processing.
        
        Args:
            filepath: Path to the uploaded file
            user: Username/email of the uploader
            
        Returns:
            dict with:
              - filename: Original filename
              - masked_text: PII-redacted text
              - entities: List of detected entities with details
              - threat_report: Full threat intelligence report
              - audit_entries: Number of audit log entries created
        """
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filepath)[1].lower()

        # ---- Step 1: Audit — Log upload ----
        self.audit_logger.log(user, "UPLOAD", f"File uploaded: {filename}")

        # ---- Step 2: Text Extraction ----
        if ext == ".sql":
            # Special handling for SQL files
            return self._process_sql(filepath, user)

        text = ingest_file(filepath)
        self.audit_logger.log(user, "EXTRACT", f"Extracted {len(text)} chars from {filename}")

        # ---- Step 3: PII Analysis ----
        results = analyze_text(self.analyzer, text)
        self.audit_logger.log(
            user, "ANALYZE",
            f"Detected {len(results)} PII entities in {filename}"
        )

        # ---- Step 4: Dual-State Processing ----
        dual_state = generate_dual_state(
            text, results, self.aes_cipher, self.fpe_cipher
        )
        self.audit_logger.log(user, "ENCRYPT", f"Generated dual-state record for {filename}")

        # ---- Step 5: Threat Intelligence ----
        threat_report = generate_threat_report(filename, results, len(text))
        self.audit_logger.log(
            user, "REPORT",
            f"Threat level: {threat_report['threat_assessment']['threat_level']} "
            f"(score: {threat_report['threat_assessment']['risk_score']})"
        )

        # ---- Step 6: Compile Result ----
        result = {
            "filename": filename,
            "file_type": ext,
            "original_length": len(text),
            "masked_text": dual_state.masked_text,
            "entities": [
                {
                    "type": e.entity_type,
                    "masked": e.masked_text,
                    "encryption_method": e.encryption_method,
                    "confidence": e.confidence,
                    "position": f"{e.start}-{e.end}",
                }
                for e in dual_state.entities
            ],
            "threat_report": threat_report,
            "audit_chain_valid": self.audit_logger.verify_chain(),
            "audit_entries": self.audit_logger.get_entry_count(),
        }

        logger.info("Pipeline complete for '%s': %d entities, threat=%s",
                    filename, len(results),
                    threat_report["threat_assessment"]["threat_level"])
        return result

    def _process_sql(self, filepath: str, user: str) -> dict:
        """Handle SQL file processing with special INSERT-aware parsing."""
        filename = os.path.basename(filepath)

        # Read the SQL content
        with open(filepath, "r", encoding="utf-8") as f:
            sql_content = f.read()

        # Define analysis/anonymization functions for the SQL handler
        def analyze_fn(text):
            return analyze_text(self.analyzer, text)

        def anonymize_fn(text, results):
            return anonymize_text(self.anonymizer, text, results)

        # Also run full analysis on the entire SQL text for threat assessment
        full_results = analyze_text(self.analyzer, sql_content)

        # Sanitize the SQL file
        output_path = filepath.replace(".sql", "_sanitized.sql")
        sanitized = process_sql_file(filepath, analyze_fn, anonymize_fn, output_path)

        self.audit_logger.log(user, "SQL_SANITIZE",
                            f"Sanitized SQL dump: {filename} → {os.path.basename(output_path)}")

        # Generate threat report
        threat_report = generate_threat_report(filename, full_results, len(sql_content))
        self.audit_logger.log(
            user, "REPORT",
            f"SQL threat level: {threat_report['threat_assessment']['threat_level']}"
        )

        return {
            "filename": filename,
            "file_type": ".sql",
            "original_length": len(sql_content),
            "sanitized_sql_path": output_path,
            "masked_text": sanitized[:500] + "..." if len(sanitized) > 500 else sanitized,
            "entities": [
                {
                    "type": r.entity_type,
                    "confidence": r.score,
                    "position": f"{r.start}-{r.end}",
                }
                for r in full_results
            ],
            "threat_report": threat_report,
            "audit_chain_valid": self.audit_logger.verify_chain(),
            "audit_entries": self.audit_logger.get_entry_count(),
        }

    def process_text(self, text: str, source_name: str = "direct_input", user: str = "system") -> dict:
        """
        Process raw text directly (e.g., from a chatbot interface).
        Useful for the Admin chatbot integration.
        """
        self.audit_logger.log(user, "INPUT", f"Direct text input: {source_name} ({len(text)} chars)")

        results = analyze_text(self.analyzer, text)
        dual_state = generate_dual_state(text, results, self.aes_cipher, self.fpe_cipher)
        threat_report = generate_threat_report(source_name, results, len(text))

        self.audit_logger.log(
            user, "ANALYZE",
            f"Text analysis complete: {len(results)} entities, "
            f"threat={threat_report['threat_assessment']['threat_level']}"
        )

        return {
            "source": source_name,
            "masked_text": dual_state.masked_text,
            "entities": [
                {
                    "type": e.entity_type,
                    "masked": e.masked_text,
                    "encryption_method": e.encryption_method,
                    "confidence": e.confidence,
                }
                for e in dual_state.entities
            ],
            "threat_report": threat_report,
            "audit_chain_valid": self.audit_logger.verify_chain(),
        }


# ===========================================================================
# CLI Demo Entry Point
# ===========================================================================

def run_demo():
    """Run a comprehensive demo of the PII Shield pipeline."""
    print("\n" + "=" * 70)
    print("       PII SHIELD — Enterprise PII Detection & Sanitization")
    print("       Hackathon Demo — HACKAMINED Track")
    print("=" * 70)

    pipeline = PIIShieldPipeline()

    # ---- Demo 1: Direct Text Processing ----
    demo_text = """
    Employee Record — Confidential
    
    Name: Rajesh Kumar Sharma
    Email: rajesh.sharma@techcorp.in
    Phone: +91 9876543210
    Aadhaar: 2234 5678 9018
    PAN Card: ABCPK1234F
    Credit Card: 4111-1111-1111-1111
    
    Emergency Contact: Priya Sharma, priya.sharma@gmail.com
    Address: 42 MG Road, Bengaluru, Karnataka 560001
    
    Note: Employee ID EMP00451 and Roll Number 2345678901 are internal
    identifiers and should NOT be flagged as PII.
    """

    print("\n" + "-" * 70)
    print("  DEMO 1: Processing Employee Record (Direct Text)")
    print("-" * 70)
    print("\n  ► Original Text:")
    for line in demo_text.strip().split("\n"):
        print(f"    {line}")

    result = pipeline.process_text(demo_text, "employee_record.txt", "admin@piishield.com")

    print("\n  ► Masked Text (Safe for Analysts):")
    for line in result["masked_text"].strip().split("\n"):
        print(f"    {line}")

    print(f"\n  ► Entities Detected: {len(result['entities'])}")
    for entity in result["entities"]:
        print(f"    • {entity['type']:<20s}  Masked: {entity['masked']:<30s}  "
              f"Encrypted via: {entity['encryption_method']}  "
              f"Confidence: {entity['confidence']:.2f}")

    # Print threat report
    print("\n" + format_threat_report_text(result["threat_report"]))

    # ---- Demo 2: SQL File Processing ----
    sample_sql_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample.sql")
    if os.path.exists(sample_sql_path):
        print("\n" + "-" * 70)
        print("  DEMO 2: Processing SQL Dump")
        print("-" * 70)

        sql_result = pipeline.process_document(sample_sql_path, "admin@piishield.com")
        print(f"\n  ► SQL Entities Found: {len(sql_result['entities'])}")
        print(f"  ► Threat Level: {sql_result['threat_report']['threat_assessment']['threat_level']}")
        if "sanitized_sql_path" in sql_result:
            print(f"  ► Sanitized SQL: {sql_result['sanitized_sql_path']}")

    # ---- Demo 3: Sample Text File ----
    sample_txt_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_text.txt")
    if os.path.exists(sample_txt_path):
        print("\n" + "-" * 70)
        print("  DEMO 3: Processing Text File")
        print("-" * 70)

        txt_result = pipeline.process_document(sample_txt_path, "admin@piishield.com")
        print(f"\n  ► Entities Found: {len(txt_result['entities'])}")
        print(f"  ► Threat Level: {txt_result['threat_report']['threat_assessment']['threat_level']}")
        print(f"\n  ► Masked Text Preview:")
        for line in txt_result["masked_text"][:500].split("\n"):
            print(f"    {line}")

    # ---- Audit Chain Verification ----
    print("\n" + "-" * 70)
    print("  AUDIT CHAIN VERIFICATION")
    print("-" * 70)
    chain_valid = pipeline.audit_logger.verify_chain()
    print(f"\n  ► Chain Integrity: {'✓ VALID' if chain_valid else '✗ TAMPERED'}")
    print(f"  ► Total Entries: {pipeline.audit_logger.get_entry_count()}")

    # Show a few audit entries
    entries = pipeline.audit_logger.get_entries()
    print("\n  ► Recent Audit Entries:")
    for entry in entries[-5:]:
        print(f"    [{entry['timestamp'][:19]}] {entry['user']}: "
              f"{entry['action']} — {entry['details'][:60]}")
        print(f"      Hash: {entry['entry_hash'][:32]}...")

    print("\n" + "=" * 70)
    print("  Demo complete. All modules operational.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_demo()
