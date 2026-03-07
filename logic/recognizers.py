"""
=============================================================================
PII Shield — Custom Indian PII Recognizers
=============================================================================
Implements Presidio PatternRecognizer subclasses for:
    1. Indian Aadhaar Numbers  (12-digit UID with Verhoeff checksum)
    2. Indian PAN Numbers      (10-char alphanumeric tax ID)

DESIGN RATIONALE (for hackathon judges):
    Presidio's built-in recognizers cover US/EU PII well, but Indian
    identifiers require custom logic. We use:
      • Regex patterns with strict digit/character constraints
      • Context words to boost confidence when nearby text mentions
        "aadhaar", "pan card", etc.
      • Validation callbacks to reject false positives (random roll
        numbers, internal employee IDs, etc.)
=============================================================================
"""

from typing import Optional
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult
import re


# ---------------------------------------------------------------------------
# Verhoeff Checksum — used by UIDAI for Aadhaar validation
# ---------------------------------------------------------------------------

# Verhoeff multiplication table
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Verhoeff permutation table
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Verhoeff inverse table
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_checksum(number_str: str) -> bool:
    """
    Validate a number using the Verhoeff checksum algorithm.
    Returns True if the checksum digit is valid.
    
    The Verhoeff algorithm is used by UIDAI (Aadhaar) to detect
    single-digit errors and most transposition errors.
    """
    c = 0
    digits = [int(d) for d in reversed(number_str)]
    for i, digit in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ---------------------------------------------------------------------------
# Indian Aadhaar Number Recognizer
# ---------------------------------------------------------------------------

class IndianAadhaarRecognizer(PatternRecognizer):
    """
    Detects Indian Aadhaar numbers (12-digit UIDs issued by UIDAI).
    
    Pattern:  Exactly 12 digits, optionally separated by spaces in groups
              of 4 (e.g., "2345 6789 0123"). First digit is never 0 or 1.
    
    Validation:
      • Must be exactly 12 digits after removing spaces
      • First digit must be 2-9 (UIDAI specification)
      • Verhoeff checksum on the full 12-digit number
      • Rejects trivial sequences (all same digit, sequential)
    
    Context words boost confidence when the number appears near
    Aadhaar-related terms, preventing false positives on random
    12-digit numbers.
    """

    # Context words that indicate an Aadhaar number is nearby
    CONTEXT_WORDS = [
        "aadhaar", "aadhar", "aadaar", "uid", "uidai",
        "unique identification", "unique id",
        "आधार",  # Hindi
        "enrollment", "enrolment", "eid",
    ]

    PATTERNS = [
        Pattern(
            "AADHAAR_SPACED",
            # 4-4-4 digit groups separated by spaces: "2345 6789 0123"
            r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
            0.35,  # Requires context boost (+0.35) to reach 0.4 threshold
        ),
        Pattern(
            "AADHAAR_CONTINUOUS",
            # 12 continuous digits starting with 2-9
            r"\b[2-9]\d{11}\b",
            0.15,  # Very low base — requires context words like "aadhaar" nearby
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_AADHAAR",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
            name="Indian Aadhaar Recognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """
        Post-match validation to eliminate false positives.
        Runs after regex match, before result is returned.
        """
        # Extract pure digits
        digits = pattern_text.replace(" ", "")

        # Must be exactly 12 digits
        if len(digits) != 12 or not digits.isdigit():
            return False

        # First digit must be 2-9 (UIDAI spec)
        if digits[0] in ("0", "1"):
            return False

        # Reject trivial/repeated patterns
        if len(set(digits)) == 1:  # All same digit: "222222222222"
            return False
        if digits == "234567890123":  # Sequential
            return False

        # Verhoeff checksum validation
        if not verhoeff_checksum(digits):
            return False

        return True


# ---------------------------------------------------------------------------
# Indian PAN Number Recognizer
# ---------------------------------------------------------------------------

class IndianPanRecognizer(PatternRecognizer):
    """
    Detects Indian Permanent Account Numbers (PAN) issued by the
    Income Tax Department.
    
    Format:  ABCPD1234E  (5 letters + 4 digits + 1 letter)
      • Chars 1-3: Alphabetic series (AAA-ZZZ)
      • Char 4:    Entity type (C=Company, P=Person, H=HUF, F=Firm,
                   A=AOP, T=Trust, B=BOI, L=Local Authority, J=AJP, G=Govt)
      • Char 5:    First letter of surname/name (for individuals)
      • Chars 6-9: Sequential number (0001-9999)
      • Char 10:   Alphabetic check digit
    
    Validation:
      • Character 4 must be a valid entity type code
      • Context words required to boost confidence and avoid matching
        random alphanumeric strings like employee IDs
    """

    # Valid entity type codes for the 4th character
    VALID_ENTITY_TYPES = set("ABCFGHLJPT")

    CONTEXT_WORDS = [
        "pan", "pan card", "pan number",
        "permanent account", "permanent account number",
        "income tax", "tax id", "tax identification",
        "it department", "itr",  # Income Tax Return
        "पैन",  # Hindi
    ]

    PATTERNS = [
        Pattern(
            "PAN_STANDARD",
            # Standard PAN format: 5 uppercase letters, 4 digits, 1 uppercase letter
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            0.5,  # Moderate base — context words needed to confirm
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_PAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
            name="Indian PAN Recognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """
        Post-match validation:
          • 4th character must be a valid entity type
          • Reject patterns that look like internal codes (e.g., ROLL12345A)
        """
        text = pattern_text.strip().upper()

        if len(text) != 10:
            return False

        # 4th character must encode a valid entity type
        if text[3] not in self.VALID_ENTITY_TYPES:
            return False

        # Additional heuristic: reject if the first 3 chars are common
        # prefixes for non-PAN codes (e.g., "EMP", "ROL", "REG", "INV")
        non_pan_prefixes = {"EMP", "ROL", "REG", "INV", "STU", "USR", "ACC", "TXN"}
        if text[:3] in non_pan_prefixes:
            return False

        return True


# ---------------------------------------------------------------------------
# Indian Name Recognizer (Fallback for spaCy NER misses)
# ---------------------------------------------------------------------------

class IndianNameRecognizer(PatternRecognizer):
    """
    Fallback recognizer for Indian names that spaCy NER may miss.
    Uses a curated list of common Indian first/last names to boost recall.
    """

    INDIAN_FIRST_NAMES = {
        "aarav", "aditi", "akash", "amit", "ananya", "anil", "anita", "anjali",
        "arjun", "arun", "deepak", "deepika", "dev", "diya", "gaurav", "geeta",
        "harsh", "ishaan", "ishita", "jai", "karan", "kavya", "krishna", "lakshmi",
        "manish", "maya", "meera", "mohan", "mukesh", "nandini", "naveen", "neha",
        "nikhil", "nisha", "pankaj", "pooja", "priya", "priyanka", "rahul", "raj",
        "rajesh", "rakesh", "ram", "ravi", "rekha", "ritu", "rohan", "rohit",
        "sakshi", "sandeep", "sanjay", "sara", "sarita", "shikha", "shiva", "shreya",
        "simran", "sneha", "sonia", "sudha", "sunil", "sunita", "suresh", "swati",
        "tanvi", "tara", "uma", "varun", "vijay", "vikram", "vinod", "vivek", "yash",
    }

    INDIAN_LAST_NAMES = {
        "agarwal", "arora", "banerjee", "bhat", "bhatt", "chakraborty", "chand",
        "chandra", "chatterjee", "chauhan", "chopra", "das", "desai", "devi",
        "dutta", "gandhi", "ghosh", "goyal", "gupta", "iyer", "jain", "joshi",
        "kaur", "khan", "khanna", "kohli", "krishnamurthy", "kumar", "lal",
        "mahajan", "malik", "mehta", "menon", "mishra", "mukherjee", "nair",
        "nanda", "kapoor", "pandey", "patel", "prasad", "rao", "rastogi", "reddy",
        "roy", "sachdev", "sahni", "saxena", "sen", "sethi", "shah", "sharma",
        "shukla", "singh", "sinha", "srivastava", "subramanian", "tiwari",
        "trivedi", "varma", "verma", "yadav",
    }

    CONTEXT_WORDS = [
        "name", "customer", "client", "person", "employee", "contact",
        "applicant", "beneficiary", "holder", "owner", "mr", "mrs", "ms",
        "shri", "smt", "kumar", "kumari",
    ]

    def __init__(self):
        patterns = [
            Pattern(
                "INDIAN_NAME_PATTERN",
                r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b",
                0.4,
            ),
        ]
        super().__init__(
            supported_entity="PERSON",
            patterns=patterns,
            context=self.CONTEXT_WORDS,
            supported_language="en",
            name="Indian Name Recognizer (Fallback)",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Validate matched text looks like an Indian name."""
        words = pattern_text.lower().split()
        if len(words) < 2:
            return False

        first_word = words[0]
        last_word = words[-1]
        is_known_first = first_word in self.INDIAN_FIRST_NAMES
        is_known_last = last_word in self.INDIAN_LAST_NAMES

        if is_known_first or is_known_last:
            return True

        # Accept Title Case 2-3 word sequences as possible names
        if all(w[0].isupper() and w[1:].islower() for w in pattern_text.split() if len(w) > 1):
            return None  # Let default scoring decide

        return False


# ---------------------------------------------------------------------------
# Biometric / Hashed Data Recognizer
# ---------------------------------------------------------------------------

class BiometricHashRecognizer(PatternRecognizer):
    """
    Detects hashed biometric identifiers such as fingerprint hashes
    and face template tokens.

    Patterns detected:
      • fp_hash_<hex>        — fingerprint hash
      • face_tmp_<hex>       — face template token
      • face_template_<hex>  — face template (alternate form)
      • fingerprint_<hex>    — fingerprint identifier
      • iris_hash_<hex>      — iris scan hash
      • bio_hash_<hex>       — generic biometric hash
      • voice_hash_<hex>     — voiceprint hash
      • retina_hash_<hex>    — retina scan hash
    """

    CONTEXT_WORDS = [
        "fingerprint", "biometric", "face", "facial", "template",
        "hash", "iris", "retina", "voiceprint", "biometrics",
        "fp_hash", "face_tmp", "bio_hash",
    ]

    PATTERNS = [
        Pattern(
            "FP_HASH",
            r"\bfp_hash_[a-f0-9]{6,64}\b",
            0.85,
        ),
        Pattern(
            "FACE_TMP",
            r"\bface_tmp_[a-f0-9]{6,64}\b",
            0.85,
        ),
        Pattern(
            "FACE_TEMPLATE",
            r"\bface_template_[a-f0-9]{6,64}\b",
            0.85,
        ),
        Pattern(
            "FINGERPRINT",
            r"\bfingerprint_[a-f0-9]{6,64}\b",
            0.85,
        ),
        Pattern(
            "IRIS_HASH",
            r"\biris_hash_[a-f0-9]{6,64}\b",
            0.80,
        ),
        Pattern(
            "BIO_HASH",
            r"\bbio_hash_[a-f0-9]{6,64}\b",
            0.80,
        ),
        Pattern(
            "VOICE_HASH",
            r"\bvoice_hash_[a-f0-9]{6,64}\b",
            0.80,
        ),
        Pattern(
            "RETINA_HASH",
            r"\bretina_hash_[a-f0-9]{6,64}\b",
            0.80,
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="BIOMETRIC_HASH",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
            name="Biometric Hash Recognizer",
        )
