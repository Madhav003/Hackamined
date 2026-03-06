"""
=============================================================================
PII Shield — Comprehensive Test Suite
=============================================================================
Tests all modules: recognizers, encryption, threat level, audit logger,
SQL handler, dual-state processing, and the full pipeline.

Run with:  python -m pytest test_pipeline.py -v
=============================================================================
"""

import json
import os
import sys
import tempfile
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(__file__))


# ===========================================================================
# TEST 1: Custom Indian PII Recognizers
# ===========================================================================

class TestAadhaarRecognizer:
    """Test Indian Aadhaar Number detection and false-positive rejection."""

    def setup_method(self):
        from recognizers import IndianAadhaarRecognizer
        self.recognizer = IndianAadhaarRecognizer()

    def test_valid_aadhaar_spaced(self):
        """Should detect a valid spaced Aadhaar number (passes Verhoeff checksum)."""
        assert self.recognizer.validate_result("2234 5678 9018") is True

    def test_valid_aadhaar_continuous(self):
        """Should detect a valid continuous Aadhaar number (passes Verhoeff checksum)."""
        assert self.recognizer.validate_result("223456789018") is True

    def test_reject_starting_with_0(self):
        """Aadhaar never starts with 0 — reject."""
        assert self.recognizer.validate_result("023456789012") is False

    def test_reject_starting_with_1(self):
        """Aadhaar never starts with 1 — reject."""
        assert self.recognizer.validate_result("123456789012") is False

    def test_reject_all_same_digits(self):
        """Trivial patterns like 222222222222 should be rejected."""
        assert self.recognizer.validate_result("222222222222") is False

    def test_reject_10_digit_roll_number(self):
        """10-digit roll numbers should NOT match (wrong digit count)."""
        assert self.recognizer.validate_result("2345678901") is False

    def test_reject_non_digit(self):
        """Non-digit strings should be rejected."""
        assert self.recognizer.validate_result("ABCD12345678") is False


class TestPanRecognizer:
    """Test Indian PAN Number detection and false-positive rejection."""

    def setup_method(self):
        from recognizers import IndianPanRecognizer
        self.recognizer = IndianPanRecognizer()

    def test_valid_pan_person(self):
        """Valid PAN for a person (4th char = P)."""
        assert self.recognizer.validate_result("ABCPK1234F") is True

    def test_valid_pan_company(self):
        """Valid PAN for a company (4th char = C)."""
        assert self.recognizer.validate_result("AAACR5678M") is True

    def test_reject_invalid_entity_type(self):
        """4th character must be a valid entity type code."""
        assert self.recognizer.validate_result("ABCQK1234F") is False  # Q is invalid

    def test_reject_employee_id_prefix(self):
        """Employee IDs starting with EMP should be rejected."""
        assert self.recognizer.validate_result("EMPPA1234B") is False

    def test_reject_wrong_length(self):
        """PAN must be exactly 10 characters."""
        assert self.recognizer.validate_result("ABCPK1234") is False
        assert self.recognizer.validate_result("ABCPK1234FF") is False


# ===========================================================================
# TEST 2: AES-256 Encryption
# ===========================================================================

class TestAESEncryption:
    """Test AES-256-GCM encrypt/decrypt roundtrip."""

    def setup_method(self):
        from encryption import AESCipher
        self.cipher = AESCipher()

    def test_roundtrip(self):
        """Encrypt then decrypt should return the original plaintext."""
        plaintext = "Rajesh Kumar — Aadhaar: 2234 5678 9018"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypted_has_required_fields(self):
        """Encrypted output must contain ciphertext, nonce, and tag."""
        encrypted = self.cipher.encrypt("test data")
        assert "ciphertext" in encrypted
        assert "nonce" in encrypted
        assert "tag" in encrypted

    def test_different_ciphertexts_for_same_plaintext(self):
        """Same plaintext should produce different ciphertexts (semantic security)."""
        e1 = self.cipher.encrypt("identical text")
        e2 = self.cipher.encrypt("identical text")
        assert e1["ciphertext"] != e2["ciphertext"]  # Different nonce → different ciphertext

    def test_tamper_detection(self):
        """Modifying ciphertext should cause decryption to fail."""
        encrypted = self.cipher.encrypt("sensitive data")
        # Tamper with the ciphertext
        encrypted["ciphertext"] = encrypted["ciphertext"][:-4] + "XXXX"
        with pytest.raises(Exception):  # ValueError or MAC check failure
            self.cipher.decrypt(encrypted)


# ===========================================================================
# TEST 3: Format-Preserving Encryption
# ===========================================================================

class TestFPEEncryption:
    """Test FF3-1 Format-Preserving Encryption."""

    def setup_method(self):
        from encryption import FPECipher
        self.cipher = FPECipher()

    def test_roundtrip_credit_card(self):
        """16-digit credit card: encrypt → decrypt should roundtrip."""
        cc = "4111111111111111"
        encrypted = self.cipher.encrypt_numeric(cc)
        decrypted = self.cipher.decrypt_numeric(encrypted)
        assert decrypted == cc

    def test_length_preserved_credit_card(self):
        """FPE output must have the SAME length as input."""
        cc = "4111111111111111"
        encrypted = self.cipher.encrypt_numeric(cc)
        assert len(encrypted) == len(cc)
        assert encrypted.isdigit()

    def test_roundtrip_phone(self):
        """10-digit phone number roundtrip."""
        phone = "9876543210"
        encrypted = self.cipher.encrypt_numeric(phone)
        decrypted = self.cipher.decrypt_numeric(encrypted)
        assert decrypted == phone

    def test_length_preserved_phone(self):
        """Phone number length should be preserved."""
        phone = "9876543210"
        encrypted = self.cipher.encrypt_numeric(phone)
        assert len(encrypted) == 10
        assert encrypted.isdigit()

    def test_encrypted_differs_from_original(self):
        """Encrypted value should differ from the original."""
        cc = "4111111111111111"
        encrypted = self.cipher.encrypt_numeric(cc)
        assert encrypted != cc  # Extremely unlikely to be the same

    def test_reject_non_numeric(self):
        """FPE should reject non-numeric input."""
        with pytest.raises(ValueError):
            self.cipher.encrypt_numeric("ABCD1234EFGH")

    def test_reject_too_short(self):
        """FF3-1 requires minimum 6 characters."""
        with pytest.raises(ValueError):
            self.cipher.encrypt_numeric("12345")


# ===========================================================================
# TEST 4: Threat Level Algorithm
# ===========================================================================

class TestThreatLevel:
    """Test threat level scoring and classification."""

    def _make_result(self, entity_type: str, score: float):
        """Create a mock RecognizerResult."""
        from presidio_analyzer import RecognizerResult
        return RecognizerResult(
            entity_type=entity_type,
            start=0,
            end=10,
            score=score,
        )

    def test_low_threat(self):
        """Single low-weight entity should be LOW threat."""
        from threat_intel import calculate_threat_score, determine_threat_level
        results = [self._make_result("PERSON", 0.8)]  # 2 * 0.8 = 1.6
        score = calculate_threat_score(results)
        assert determine_threat_level(score) == "LOW"

    def test_medium_threat(self):
        """Mix of medium-weight entities should be MEDIUM."""
        from threat_intel import calculate_threat_score, determine_threat_level
        results = [
            self._make_result("EMAIL_ADDRESS", 0.9),  # 4 * 0.9 = 3.6
            self._make_result("PHONE_NUMBER", 0.85),   # 5 * 0.85 = 4.25
            self._make_result("PERSON", 0.7),           # 2 * 0.7 = 1.4
            self._make_result("PERSON", 0.8),           # 2 * 0.8 = 1.6
        ]
        score = calculate_threat_score(results)
        assert determine_threat_level(score) == "MEDIUM"  # Total ≈ 10.85

    def test_high_threat(self):
        """Financial PII should push to HIGH threat."""
        from threat_intel import calculate_threat_score, determine_threat_level
        results = [
            self._make_result("CREDIT_CARD", 0.95),   # 9 * 0.95 = 8.55
            self._make_result("IN_AADHAAR", 0.9),     # 10 * 0.9 = 9.0
            self._make_result("IN_PAN", 0.85),        # 8 * 0.85 = 6.8
            self._make_result("EMAIL_ADDRESS", 0.8),   # 4 * 0.8 = 3.2
            self._make_result("PHONE_NUMBER", 0.8),    # 5 * 0.8 = 4.0
        ]
        score = calculate_threat_score(results)
        assert determine_threat_level(score) == "HIGH"  # Total ≈ 31.55

    def test_critical_threat(self):
        """Multiple high-sensitivity records should be CRITICAL."""
        from threat_intel import calculate_threat_score, determine_threat_level
        results = [
            self._make_result("IN_AADHAAR", 0.95),    # 10 * 0.95 = 9.5
            self._make_result("IN_AADHAAR", 0.9),     # 10 * 0.9 = 9.0
            self._make_result("CREDIT_CARD", 0.95),    # 9 * 0.95 = 8.55
            self._make_result("CREDIT_CARD", 0.90),    # 9 * 0.9 = 8.1
            self._make_result("IN_PAN", 0.85),         # 8 * 0.85 = 6.8
            self._make_result("IN_PAN", 0.80),         # 8 * 0.8 = 6.4
            self._make_result("US_SSN", 0.9),          # 10 * 0.9 = 9.0
            self._make_result("EMAIL_ADDRESS", 0.8),   # 4 * 0.8 = 3.2
        ]
        score = calculate_threat_score(results)
        assert determine_threat_level(score) == "CRITICAL"  # Total ≈ 60.55

    def test_threat_report_structure(self):
        """Threat report should have required fields."""
        from threat_intel import generate_threat_report
        results = [self._make_result("EMAIL_ADDRESS", 0.9)]
        report = generate_threat_report("test.txt", results, 100)
        assert "threat_assessment" in report
        assert "entity_breakdown" in report
        assert "recommended_actions" in report
        assert report["threat_assessment"]["threat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ===========================================================================
# TEST 5: Tamper-Evident Audit Logger
# ===========================================================================

class TestAuditLogger:
    """Test SHA-256 hash-chain audit logging."""

    def setup_method(self):
        from audit_logger import AuditLogger
        self.log_file = tempfile.mktemp(suffix=".json")
        self.logger = AuditLogger(log_file=self.log_file)

    def teardown_method(self):
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

    def test_log_and_verify(self):
        """Valid chain should pass verification."""
        self.logger.log("admin", "UPLOAD", "test_file.csv")
        self.logger.log("admin", "SCAN", "Found 5 entities")
        self.logger.log("admin", "REPORT", "Threat level: HIGH")
        assert self.logger.verify_chain() is True

    def test_tamper_detection(self):
        """Modifying an entry should break the chain."""
        self.logger.log("admin", "UPLOAD", "file.csv")
        self.logger.log("admin", "SCAN", "3 entities")
        
        # Tamper with the first entry's details
        self.logger._chain[0].details = "TAMPERED DATA"
        assert self.logger.verify_chain() is False

    def test_hash_chain_linkage(self):
        """Each entry's prev_hash should match the previous entry's hash."""
        self.logger.log("user1", "ACTION1", "details1")
        self.logger.log("user2", "ACTION2", "details2")
        
        entries = self.logger.get_entries()
        assert entries[0]["prev_hash"] == "0" * 64  # Genesis
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    def test_empty_chain_valid(self):
        """Empty chain should pass verification."""
        assert self.logger.verify_chain() is True

    def test_persistence(self):
        """Chain should persist to disk and reload correctly."""
        self.logger.log("admin", "TEST", "persistence test")
        
        # Create a new logger instance pointing to the same file
        from audit_logger import AuditLogger
        new_logger = AuditLogger(log_file=self.log_file)
        assert new_logger.get_entry_count() == 1
        assert new_logger.verify_chain() is True


# ===========================================================================
# TEST 6: SQL Handler
# ===========================================================================

class TestSqlHandler:
    """Test SQL dump parsing and sanitization."""

    def test_parse_insert_statements(self):
        """Should correctly identify INSERT statements."""
        from sql_handler import parse_insert_statements
        
        sql = """
        CREATE TABLE test (id INT, name VARCHAR(100));
        INSERT INTO test VALUES (1, 'John Doe');
        INSERT INTO test VALUES (2, 'Jane Smith');
        ALTER TABLE test ADD COLUMN email VARCHAR(255);
        """
        inserts = parse_insert_statements(sql)
        assert len(inserts) == 2
        assert inserts[0]["table_name"] == "test"

    def test_extract_string_values(self):
        """Should extract quoted string values from VALUES clause."""
        from sql_handler import extract_string_values
        
        values = "(1, 'John Doe', 'john@email.com', NULL, 42)"
        strings = extract_string_values(values)
        assert len(strings) == 2
        assert strings[0][0] == "John Doe"
        assert strings[1][0] == "john@email.com"

    def test_ddl_preserved(self):
        """CREATE TABLE and ALTER TABLE should be unchanged."""
        from sql_handler import sanitize_sql_file
        
        sql = """CREATE TABLE test (
    id INT PRIMARY KEY,
    name VARCHAR(100)
);

INSERT INTO test VALUES (1, 'test data');

ALTER TABLE test ADD COLUMN phone VARCHAR(20);
"""
        # Use identity functions (no actual PII detection)
        sanitized = sanitize_sql_file(sql, lambda t: [], lambda t, r: t)
        assert "CREATE TABLE test" in sanitized
        assert "ALTER TABLE test ADD COLUMN phone" in sanitized


# ===========================================================================
# TEST 7: Dual-State Processing
# ===========================================================================

class TestDualState:
    """Test masked view generation and encrypted records."""

    def test_mask_email(self):
        """Email should be partially masked: j***@email.com."""
        from dual_state import _mask_entity
        masked = _mask_entity("john.doe@email.com", "EMAIL_ADDRESS")
        assert masked.startswith("j")
        assert "@email.com" in masked
        assert "*" in masked

    def test_mask_phone(self):
        """Phone should show last 4 digits."""
        from dual_state import _mask_entity
        masked = _mask_entity("9876543210", "PHONE_NUMBER")
        assert masked.endswith("3210")
        assert "X" in masked

    def test_mask_credit_card(self):
        """Credit card should show last 4 digits."""
        from dual_state import _mask_entity
        masked = _mask_entity("4111111111111111", "CREDIT_CARD")
        assert masked.endswith("1111")
        assert "X" in masked

    def test_mask_aadhaar(self):
        """Aadhaar should show last 4 digits."""
        from dual_state import _mask_entity
        masked = _mask_entity("2234 5678 9018", "IN_AADHAAR")
        assert "9018" in masked
        assert "X" in masked

    def test_mask_name(self):
        """Name should be fully redacted."""
        from dual_state import _mask_entity
        assert _mask_entity("Rajesh Kumar", "PERSON") == "[REDACTED_NAME]"


# ===========================================================================
# TEST 8: Full Pipeline Integration
# ===========================================================================

class TestFullPipeline:
    """Integration tests for the complete pipeline."""

    def setup_method(self):
        # Clean up any audit log from previous tests
        for f in ["audit_log.json"]:
            if os.path.exists(f):
                os.remove(f)

    def teardown_method(self):
        for f in ["audit_log.json"]:
            if os.path.exists(f):
                os.remove(f)

    def test_text_processing(self):
        """Full pipeline should detect PII and return masked text."""
        from pipeline import PIIShieldPipeline

        pipeline = PIIShieldPipeline()
        text = """
        Name: Rajesh Kumar
        Email: rajesh@example.com
        Phone: +91 9876543210
        Aadhaar: 2234 5678 9018
        PAN: ABCPK1234F
        Credit Card: 4111111111111111
        """
        result = pipeline.process_text(text, "test_input", "tester")

        # Should have detected entities
        assert len(result["entities"]) > 0
        # Masked text should not contain raw email
        assert "rajesh@example.com" not in result["masked_text"]
        # Should have a threat report
        assert "threat_report" in result
        assert result["threat_report"]["threat_assessment"]["threat_level"] in [
            "LOW", "MEDIUM", "HIGH", "CRITICAL"
        ]
        # Audit chain should be valid
        assert result["audit_chain_valid"] is True

    def test_pipeline_with_no_pii(self):
        """Text without PII should return LOW threat level."""
        from pipeline import PIIShieldPipeline

        pipeline = PIIShieldPipeline()
        text = "This is a normal document with no personal information."
        result = pipeline.process_text(text, "clean_doc", "tester")

        assert len(result["entities"]) == 0
        assert result["threat_report"]["threat_assessment"]["threat_level"] == "LOW"

    def test_sample_text_file(self):
        """Process the sample_text.txt file through the full pipeline."""
        from pipeline import PIIShieldPipeline

        sample_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_text.txt")
        if not os.path.exists(sample_path):
            pytest.skip("Sample text file not found")

        pipeline = PIIShieldPipeline()
        result = pipeline.process_document(sample_path, "tester")

        assert len(result["entities"]) > 0
        assert "threat_report" in result
        assert result["audit_chain_valid"] is True


# ===========================================================================
# Entry point for direct execution
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
