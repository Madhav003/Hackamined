# PII Shield — Technical Documentation

> **Enterprise-grade PII Detection, Sanitization & Threat Assessment Platform**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Backend — Logic Layer](#4-backend--logic-layer)
   - [Pipeline Orchestrator (pipeline.py)](#41-pipeline-orchestrator-pipelinepy)
   - [Text Extraction & Ingestion (ingestion.py)](#42-text-extraction--ingestion-ingestionpy)
   - [PII Analysis Engine (analyzer_engine.py)](#43-pii-analysis-engine-analyzer_enginepy)
   - [Custom Indian Recognizers (recognizers.py)](#44-custom-indian-recognizers-recognizerspy)
   - [Dual-State Records (dual_state.py)](#45-dual-state-records-dual_statepy)
   - [Encryption (encryption.py)](#46-encryption-encryptionpy)
   - [Threat Intelligence (threat_intel.py)](#47-threat-intelligence-threat_intelpy)
   - [Audit Logger (audit_logger.py)](#48-audit-logger-audit_loggerpy)
   - [Table Processor (table_processor.py)](#49-table-processor-table_processorpy)
   - [SQL Handler (sql_handler.py)](#410-sql-handler-sql_handlerpy)
   - [OCR Pipeline (ocr_pipeline.py)](#411-ocr-pipeline-ocr_pipelinepy)
   - [File Handlers (file_handlers.py)](#412-file-handlers-file_handlerspy)
   - [Configuration (config.py)](#413-configuration-configpy)
5. [Flask API Server (app.py)](#5-flask-api-server-apppy)
6. [Frontend — React/Tailwind UI](#6-frontend--reacttailwind-ui)
7. [Frontend–Backend Integration](#7-frontendbackend-integration)
8. [File Processing Pipeline — End-to-End Flow](#8-file-processing-pipeline--end-to-end-flow)
9. [PII Detection Algorithms](#9-pii-detection-algorithms)
10. [Encryption Methodology](#10-encryption-methodology)
11. [Threat Scoring & Risk Assessment](#11-threat-scoring--risk-assessment)
12. [Audit Trail & Tamper Detection](#12-audit-trail--tamper-detection)
13. [Database Schema](#13-database-schema)
14. [Security Model & Compliance](#14-security-model--compliance)
15. [Deployment & Configuration](#15-deployment--configuration)

---

## 1. Project Overview

**PII Shield** is an AI-powered document scanning platform that detects, sanitizes, and encrypts Personally Identifiable Information (PII) across multiple file formats. Built for a hackathon under the name **Hackamined**, the system combines Microsoft's Presidio NLP framework with custom Indian-locale recognizers, dual-state encryption (AES-256-GCM + FF3-1 Format-Preserving Encryption), and a real-time threat intelligence engine.

### What It Does

| Capability | Description |
|---|---|
| **Multi-format scanning** | Processes `.txt`, `.csv`, `.pdf`, `.docx`, `.xlsx`, `.sql`, `.png`, `.jpg` |
| **PII detection** | Identifies names, emails, phone numbers, Aadhaar, PAN, credit cards, SSNs, IPs, dates, URLs |
| **Dual-state storage** | Produces a **masked view** (safe for analysts) and an **encrypted raw** (recoverable by admins) |
| **Threat assessment** | Scores documents by risk (LOW / MEDIUM / HIGH / CRITICAL) based on entity types and confidence |
| **Audit chain** | SHA-256 hash-chained log entries — tamper-evident, SOX-compliant |
| **Role-based access** | Admin sees everything; users see only sanitized outputs |

### Target Compliance

- **GDPR** — Encryption (Article 32), data minimisation, processing records
- **PCI-DSS** — Format-preserving encryption for card numbers, access controls
- **India DPDP Act** — Reasonable security safeguards, consent management
- **SOX Section 802** — Immutable audit trail

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              FRONTEND  (React 18 / Tailwind CSS)             │
│                                                              │
│   Login ─ Signup ─ Dashboards ─ Upload ─ Viewers ─ Analytics │
│                                                              │
│              Firebase Auth  +  Cloud Firestore               │
└──────────────────────┬───────────────────────────────────────┘
                       │  REST API  (JSON over HTTP)
                       │  POST /api/scan, /analyze, /analyze_table
                       │
┌──────────────────────┴───────────────────────────────────────┐
│              BACKEND  (Flask / Python 3.13)                   │
│                                                              │
│   app.py ──────────── Routes & Request Handlers              │
│     │                                                        │
│     ├── pipeline.py ──── PIIShieldPipeline (orchestrator)    │
│     │     ├── ingestion.py ──── Text extraction              │
│     │     ├── analyzer_engine.py ── Presidio config          │
│     │     ├── recognizers.py ──── Custom Indian recognizers  │
│     │     ├── dual_state.py ──── Masked + encrypted views    │
│     │     ├── encryption.py ──── AES-256-GCM & FF3-1 FPE    │
│     │     ├── threat_intel.py ── Risk scoring                │
│     │     ├── audit_logger.py ── Hash-chain audit log        │
│     │     ├── sql_handler.py ─── SQL dump sanitisation       │
│     │     └── ocr_pipeline.py ── Tesseract OCR               │
│     │                                                        │
│     ├── table_processor.py ── Cell-by-cell table processing  │
│     ├── file_handlers.py ──── Format-specific sanitised file │
│     └── config.py ──────────── Centralised configuration     │
│                                                              │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│              DATA PERSISTENCE                                │
│                                                              │
│   Cloud Firestore ── users, files (frontend state)           │
│   SQLite ──────────── documents, pii_records, threat_reports │
│   audit_log.json ──── Hash-chained audit entries             │
│   sanitized_files/ ── Output files (PDF, DOCX, XLSX, TXT)   │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

### Backend

| Library | Version | Purpose |
|---|---|---|
| **Flask** | ≥ 3.0.0 | Web framework, REST API |
| **presidio-analyzer** | ≥ 2.2.0 | PII detection engine (Microsoft) |
| **presidio-anonymizer** | ≥ 2.2.0 | PII masking / replacement |
| **PyCryptodome** | ≥ 3.20.0 | AES-256-GCM authenticated encryption |
| **ff3** | ≥ 1.0.0 | FF3-1 Format-Preserving Encryption (NIST SP 800-38G) |
| **PyMuPDF (fitz)** | ≥ 1.24.0 | PDF text extraction & redaction |
| **python-docx** | ≥ 1.1.0 | DOCX paragraph & table parsing |
| **pandas** | ≥ 2.0.0 | Excel/CSV data handling |
| **openpyxl** | ≥ 3.1.0 | XLSX read/write engine for pandas |
| **pytesseract** | ≥ 0.3.10 | Python binding for Tesseract OCR |
| **opencv-python-headless** | ≥ 4.9.0 | Image preprocessing for OCR |
| **Pillow** | ≥ 10.0.0 | Image I/O support |
| **pytest** | ≥ 8.0.0 | Unit testing |
| **spaCy** | (Presidio dep) | NER for person/location detection |
| **SQLite** | (stdlib) | Local relational database |
| **Python** | 3.13 | Runtime |

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| **React** | 18.x (CDN) | UI rendering via Babel in-browser transpilation |
| **Tailwind CSS** | Latest (CDN) | Utility-first styling |
| **Firebase Auth** | 10.9.0 | Email/password authentication |
| **Cloud Firestore** | 10.9.0 | Real-time NoSQL document database |
| **Firebase Storage** | 10.9.0 | File blob storage |
| **Lucide Icons** | CDN | SVG icon library |

### Algorithms Used

| Algorithm | Where | Purpose |
|---|---|---|
| **AES-256-GCM** | encryption.py | Authenticated symmetric encryption for text PII |
| **FF3-1 FPE** (Feistel network) | encryption.py | Format-preserving encryption for numeric PII |
| **SHA-256** | audit_logger.py | Hash chain for tamper-evident audit log |
| **Verhoeff checksum** | recognizers.py | Aadhaar number validation |
| **Luhn algorithm** | Presidio built-in | Credit card number validation |
| **spaCy NER** (transformer/CNN) | Presidio built-in | Named Entity Recognition for person/location |
| **Tesseract LSTM** | ocr_pipeline.py | Optical Character Recognition |
| **Adaptive Gaussian thresholding** | ocr_pipeline.py | Image binarisation for OCR preprocessing |
| **Bilateral filter** | ocr_pipeline.py | Edge-preserving noise removal |
| **Weighted risk scoring** | threat_intel.py | Entity-weight × confidence threat calculation |

---

## 4. Backend — Logic Layer

### 4.1 Pipeline Orchestrator (`pipeline.py`)

The `PIIShieldPipeline` class is the central orchestrator that ties every backend module together.

#### Class: `PIIShieldPipeline`

```python
class PIIShieldPipeline:
    def __init__(self)
    def process_document(self, filepath: str, user: str) -> dict
    def _process_sql(self, filepath: str, user: str) -> dict
    def process_text(self, text: str, source_name: str, user: str) -> dict
```

#### `__init__()`
Initialises all sub-systems:
- Presidio `AnalyzerEngine` and `AnonymizerEngine` (via `analyzer_engine.py`)
- AES-256-GCM cipher and FF3-1 FPE cipher (via `encryption.py`)
- `DualStateProcessor` (via `dual_state.py`)
- `ThreatIntelligenceEngine` (via `threat_intel.py`)
- `AuditLogger` (via `audit_logger.py`)

#### `process_document(filepath, user)`

End-to-end flow for files:

1. **Audit log** — records the UPLOAD action
2. **Text extraction** — calls `ingest_file(filepath)` to pull plain text from any supported format
3. **SQL detection** — if `.sql` extension, routes to `_process_sql()` for INSERT-level sanitisation
4. **Presidio analysis** — runs the analyzer with all built-in + custom recognizers
5. **Dual-state generation** — produces masked text + encrypted entities
6. **Threat intelligence** — calculates risk score and threat level
7. **Audit chain verification** — validates the entire hash chain
8. **Returns** structured result dict

#### `process_text(text, source_name, user)`

Same pipeline but accepts a raw string instead of a file path. Used by the `/analyze` API route for direct text input.

#### Return Structure

```json
{
  "filename": "invoice.pdf",
  "original_length": 5432,
  "masked_text": "Dear [REDACTED_NAME], your card XXXX-XXXX-XXXX-1234 ...",
  "entities": [
    {
      "type": "CREDIT_CARD",
      "masked": "XXXX-XXXX-XXXX-1234",
      "encryption_method": "FF3-1-FPE",
      "confidence": 0.95,
      "position": "123-139"
    }
  ],
  "threat_report": {
    "threat_assessment": { "threat_level": "HIGH", "risk_score": 45.3 },
    "entity_breakdown": { ... },
    "recommended_actions": [ ... ]
  },
  "audit_chain_valid": true,
  "audit_entries": 6
}
```

---

### 4.2 Text Extraction & Ingestion (`ingestion.py`)

Routes files to format-specific extractors and returns plain text.

| Function | Formats | Library |
|---|---|---|
| `extract_text_from_pdf(path)` | `.pdf` | PyMuPDF (`fitz`) — iterates all pages |
| `extract_text_from_docx(path)` | `.docx` | python-docx — paragraphs + table cells |
| `extract_text_from_txt(path)` | `.txt`, `.sql` | stdlib — UTF-8 with latin-1 fallback |
| `extract_text_from_csv(path)` | `.csv` | stdlib — plain text read |
| `extract_text_from_xlsx(path)` | `.xlsx` | pandas `ExcelFile` → `DataFrame.to_string()` |
| `extract_text_from_image(path)` | `.png`, `.jpg`, `.jpeg` | Tesseract OCR via `ocr_pipeline.py` |
| `ingest_file(path)` | All above | Router — maps extension → extractor |

The router (`ingest_file`) uses a dictionary mapping extensions to extractor functions. If the extension is not found it raises `ValueError("Unsupported file format")`.

---

### 4.3 PII Analysis Engine (`analyzer_engine.py`)

Configures and wraps Microsoft Presidio's analysis and anonymisation components.

#### `create_analyzer() → AnalyzerEngine`

Returns a Presidio `AnalyzerEngine` with:
- All built-in recognizers (PERSON, EMAIL_ADDRESS, CREDIT_CARD, PHONE_NUMBER, US_SSN, IP_ADDRESS, LOCATION, DATE_TIME, URL, etc.)
- **Custom recognizers** registered: `IndianAadhaarRecognizer`, `IndianPanRecognizer`, `IndianNameRecognizer`

#### `create_anonymizer() → AnonymizerEngine`

Returns a stateless Presidio `AnonymizerEngine` used to apply operators (replace, mask, hash) to detected entities.

#### `analyze_text(analyzer, text, entities, score_threshold)`

Calls `analyzer.analyze()` with language `"en"` and the configured entity list and minimum confidence threshold (default 0.4).

#### `anonymize_text(anonymizer, text, results, operators)`

Applies masking operators to the text based on analysis results:

| Entity Type | Operator | Behaviour |
|---|---|---|
| `PERSON` | Replace | `[REDACTED_NAME]` |
| `EMAIL_ADDRESS` | Mask | First 6 chars masked: `j***@domain.com` |
| `CREDIT_CARD` | Mask | Show last 4: `XXXX-XXXX-XXXX-1234` |
| `IN_AADHAAR` | Mask | Show last 4: `XXXX XXXX 1234` |
| `IN_PAN` | Replace | `[REDACTED_PAN]` |
| `PHONE_NUMBER` | Mask | First 6 digits masked |
| `US_SSN` | Replace | `[REDACTED_SSN]` |
| Default | Replace | `[REDACTED]` |

---

### 4.4 Custom Indian Recognizers (`recognizers.py`)

Three custom Presidio `PatternRecognizer` subclasses that handle India-specific PII formats not covered by Presidio's built-in recognizers.

#### `IndianAadhaarRecognizer`

- **What:** Detects 12-digit Aadhaar numbers (India's biometric national ID)
- **Patterns:**
  - `AADHAAR_SPACED`: `[2-9]\d{3}\s\d{4}\s\d{4}` — e.g. `2345 6789 0123` (base score 0.35)
  - `AADHAAR_CONTINUOUS`: `[2-9]\d{11}` — e.g. `234567890123` (base score 0.15, needs context)
- **Validation:** **Verhoeff checksum algorithm** — the same algorithm used by UIDAI to validate real Aadhaar numbers. Uses multiplication (D), permutation (P), and inverse tables to detect single-digit errors and transposition errors.
- **Context words:** `aadhaar`, `aadhar`, `uid`, `uidai`, `unique identification`, `enrollment`, `आधार` (Hindi)
- Confidence boosted by +0.3–0.5 when context words appear nearby.

#### `IndianPanRecognizer`

- **What:** Detects 10-character PAN (Permanent Account Number) — India's tax identifier
- **Format:** `[A-Z]{5}[0-9]{4}[A-Z]`
  - Characters 1–3: Alphabetic series code
  - Character 4: Entity type — `C` (Company), `P` (Person), `H` (HUF), `F` (Firm), `A` (AOP), `T` (Trust), `B` (BOI), `L` (Local Authority), `J` (AJP), `G` (Government)
  - Character 5: First letter of surname
  - Characters 6–9: Sequential number `0001`–`9999`
  - Character 10: Alphabetic check digit
- **Validation:** 4th character must be a valid entity type; rejects false-positive prefixes like `EMP`, `ROL`, `REG`, `INV`
- **Context words:** `pan`, `pan card`, `permanent account`, `income tax`, `itr`

#### `IndianNameRecognizer`

- **What:** Catches common Indian names that spaCy's English NER model often misses
- **Pattern:** 2–3 word Title Case sequences
- **Validation:** Matches against curated lists of 100+ common Indian first names and last names
- **Use case:** Fallback recognizer that fires at a lower confidence threshold to catch names like `Aarav Sharma`, `Priya Patel`, `Rajesh Kumar` that spaCy might miss

---

### 4.5 Dual-State Records (`dual_state.py`)

Generates two parallel representations of every detected PII entity.

#### Concept

| View | Audience | Example |
|---|---|---|
| **Masked** | Analysts, users | `j***@example.com`, `XXXX XXXX 1234` |
| **Encrypted** | Admins with keys | AES ciphertext or FPE-encrypted number |

#### Masking Strategies

| Entity Type | Masked Output |
|---|---|
| `EMAIL_ADDRESS` | `j***@domain.com` (first char + asterisks) |
| `PHONE_NUMBER` | `XXXXXX7890` (last 4 visible) |
| `CREDIT_CARD` | `XXXX-XXXX-XXXX-1234` (last 4 visible) |
| `IN_AADHAAR` | `XXXX XXXX 1234` (last 4 visible) |
| `IN_PAN` | `AB*****E` (first 2 + last 1) |
| `PERSON` | `[REDACTED_NAME]` |
| `US_SSN` | `[REDACTED_SSN]` |

#### Encryption Routing

- **FPE eligible** (numeric, fixed-format): `CREDIT_CARD`, `PHONE_NUMBER`, `IN_AADHAAR` → FF3-1
- **Everything else**: `PERSON`, `EMAIL_ADDRESS`, `IN_PAN`, `US_SSN`, etc. → AES-256-GCM

#### Data Classes

```python
@dataclass
class PIIEntity:
    entity_type: str            # "CREDIT_CARD", "IN_AADHAAR", etc.
    original_text: str          # The raw PII value
    masked_text: str            # Human-readable redaction
    encrypted_data: dict | str  # AES-GCM dict or FPE string
    encryption_method: str      # "AES-256-GCM" or "FF3-1-FPE"
    confidence: float           # 0.0–1.0
    start: int                  # Character offset (start)
    end: int                    # Character offset (end)

@dataclass
class DualStateRecord:
    original_length: int
    masked_text: str
    entities: List[PIIEntity]
    entity_count: int
```

---

### 4.6 Encryption (`encryption.py`)

Implements a dual encryption architecture to handle different PII data types optimally.

#### AES-256-GCM (Authenticated Encryption)

Used for all non-numeric PII (names, emails, addresses, etc.).

| Property | Value |
|---|---|
| Algorithm | AES (Advanced Encryption Standard) |
| Mode | GCM (Galois/Counter Mode) |
| Key size | 256 bits (32 bytes) |
| Nonce | Random per encryption (96 bits) |
| Auth tag | 128 bits (detects tampering) |

```
Input:  "John Doe"
Output: { ciphertext: "aBcD1234...", nonce: "xYzW...", tag: "pQrS..." }
         (all base64-encoded)
```

**Security properties:**
- **Confidentiality** — only the key holder can decrypt
- **Integrity** — the authentication tag reveals any tampering
- **Semantic security** — identical plaintexts produce different ciphertexts (random nonce)

#### FF3-1 Format-Preserving Encryption (Feistel Network)

Used for numeric PII (credit cards, phone numbers, Aadhaar) where the output must have the **same length and character set** as the input.

| Property | Value |
|---|---|
| Algorithm | FF3-1 (NIST SP 800-38G) |
| Key size | 128 bits (16 bytes) |
| Tweak | 7 bytes (salt) |
| Radix | 10 (digits 0–9 only) |

```
Input:  "4532111111111111"   (16-digit credit card)
Output: "7293048156823741"   (16-digit encrypted — same length, only digits)
```

**Why FPE for numeric data:**
- Database schemas stay intact (`BIGINT(16)` still valid after encryption)
- PCI-DSS compliant tokenisation
- Encrypted values remain queryable / indexable
- Preserves format for downstream systems

---

### 4.7 Threat Intelligence (`threat_intel.py`)

Calculates a composite risk score for each document based on the types and confidence of detected PII.

#### Risk Weights by Entity Type

| Entity Type | Weight | Rationale |
|---|---|---|
| `IN_AADHAAR` | 10 | National biometric ID — extremely sensitive |
| `US_SSN` | 10 | Primary identity theft vector |
| `CREDIT_CARD` | 9 | PCI-DSS regulated financial data |
| `IN_PAN` | 8 | Tax identifier — financial fraud risk |
| `PHONE_NUMBER` | 5 | SIM-swap attack vector |
| `EMAIL_ADDRESS` | 4 | Phishing / social engineering vector |
| `IP_ADDRESS` | 3 | Network reconnaissance data |
| `LOCATION` | 3 | Physical security risk |
| `DATE_TIME` | 2 | Low risk alone; high risk when combined |
| `PERSON` | 2 | Name alone = low risk |
| `URL` | 1 | Minimal direct risk |

#### Scoring Formula

```
entity_score = WEIGHT[entity_type] × confidence
risk_score   = Σ(all entity_scores)
```

**Example:** A document with 1 Aadhaar (confidence 0.95) and 1 credit card (confidence 0.92):
```
risk_score = (10 × 0.95) + (9 × 0.92) = 9.5 + 8.28 = 17.78 → MEDIUM
```

#### Threat Level Thresholds

| Level | Score Range | Recommended Actions |
|---|---|---|
| **LOW** | < 10 | Standard handling, log access |
| **MEDIUM** | 10–30 | Mask before sharing, 24-hour review cycle |
| **HIGH** | 30–60 | Immediate restrict, 4-hour DPO notification |
| **CRITICAL** | ≥ 60 | Urgent quarantine, 1-hour escalation, breach assessment |

#### Report Structure

```json
{
  "threat_assessment": {
    "threat_level": "HIGH",
    "risk_score": 45.3,
    "total_entities_detected": 12,
    "unique_entity_types": 5
  },
  "entity_breakdown": {
    "CREDIT_CARD": { "count": 2, "avg_confidence": 0.95, "risk_weight": 9 },
    "IN_AADHAAR": { "count": 1, "avg_confidence": 0.90, "risk_weight": 10 }
  },
  "top_detections": [ ... ],
  "recommended_actions": [ "IMMEDIATE: Restrict document access", ... ]
}
```

---

### 4.8 Audit Logger (`audit_logger.py`)

Implements a **blockchain-inspired tamper-evident hash chain** for regulatory compliance.

#### How It Works

Each audit entry's hash depends on all previous entries. Modifying any entry invalidates the entire chain downstream.

```
Entry 1:  hash("ts|user|UPLOAD|details|0000...0000")     → H₁
Entry 2:  hash("ts|user|EXTRACT|details|H₁")             → H₂
Entry 3:  hash("ts|user|ANALYZE|details|H₂")             → H₃
...
```

#### Entry Structure

```python
@dataclass
class AuditEntry:
    timestamp: str        # ISO 8601
    user: str             # Email or username
    action: str           # UPLOAD | EXTRACT | ANALYZE | ENCRYPT | REPORT | SQL_SANITIZE
    details: str          # Human-readable description
    prev_hash: str        # SHA-256 of previous entry
    entry_hash: str       # SHA-256(timestamp|user|action|details|prev_hash)
```

- The **genesis entry's** `prev_hash` is `"0" × 64` (64 zeros).
- Hash computation: `SHA-256(timestamp + "|" + user + "|" + action + "|" + details + "|" + prev_hash)`

#### Key Methods

| Method | Description |
|---|---|
| `log(user, action, details)` | Appends a new entry, computes hash, persists to JSON |
| `verify_chain()` | Walks the entire chain and returns `True` if all hashes validate, `False` if tampered |
| `get_entries()` | Returns all audit entries |
| `get_entry_count()` | Returns chain length |

#### Persistence

Entries are persisted to `audit_log.json`. The file is loaded on startup and the chain is verified.

#### Compliance Use

- **SOX Section 802** — immutable audit trail
- **GDPR Article 30** — records of processing activities
- **PCI-DSS Requirement 10** — access monitoring and logging
- **India DPDP Act** — security safeguards documentation

---

### 4.9 Table Processor (`table_processor.py`)

Handles ASCII pipe-delimited tables with **cell-by-cell PII processing** while preserving column alignment.

#### Class: `AsciiTableProcessor`

```
Input:
| Name         | Aadhaar         | Email              |
|------------- |---------------- |------------------- |
| Rajesh Kumar | 2345 6789 0123  | rajesh@company.com |

Output:
| [REDACTED]   | XXXX XXXX 0123  | r***@company.com   |
|------------- |---------------- |------------------- |
| [REDACTED]   | XXXX XXXX 0123  | r***@company.com   |
```

#### Key Features

1. **Quasi-identifier column detection** — classifies columns as PII or non-PII based on header keywords (`aadhaar`, `pan`, `name`, `email`, `phone`, `address`, `ssn` → PII; `number`, `digit`, `id`, `code`, `serial`, `roll` → non-PII)
2. **Cell-by-cell analysis** — each cell processed individually with column context as a confidence boost
3. **Alignment preservation** — detects column widths and pads sanitised values to maintain table structure
4. **Configurable modes:**
   - `twelve_digit_mode`: `"mask_last_4"` | `"full_mask"` | `"redact"` | `"ignore"` — how to handle 12-digit numbers
   - `name_mode`: `"redact"` | `"mask_first"` | `"hash"` — how to handle detected names

---

### 4.10 SQL Handler (`sql_handler.py`)

Sanitises PII inside SQL dump files without breaking the SQL syntax.

#### Challenge

SQL dumps mix DDL (`CREATE TABLE`, `ALTER`) with DML (`INSERT INTO`). The handler must sanitise data values without corrupting the SQL structure.

#### Pipeline

1. `parse_insert_statements(sql_content)` — regex extracts all `INSERT INTO ... VALUES (...)` statements
2. `extract_string_values(values_section)` — extracts quoted string literals, handling escaped quotes (`'O\'Brien'`)
3. `sanitize_sql_file(sql_content, analyze_fn, anonymize_fn)` — processes from **end to start** (to preserve character offsets), runs Presidio on each string value, reconstructs the INSERT statement

```sql
-- Input
INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com');

-- Output
INSERT INTO users (name, email) VALUES ('[REDACTED_NAME]', 'j***@example.com');
```

All DDL statements (`CREATE`, `ALTER`, `DROP`) are left untouched.

---

### 4.11 OCR Pipeline (`ocr_pipeline.py`)

Extracts text from images using Tesseract OCR with computer vision preprocessing.

#### Step 1 — Image Preprocessing (`preprocess_image`)

1. Load image with OpenCV
2. Convert BGR → Grayscale
3. **Bilateral filter** — removes noise while preserving edges (important for text clarity)
4. **Adaptive Gaussian threshold** — binarises the image, handling uneven lighting across the page

#### Step 2 — Text Extraction (`extract_text_from_image`)

- Runs Tesseract OCR with:
  - **PSM 6** — assume a single uniform block of text
  - **OEM 3** — LSTM neural network engine (highest accuracy)

#### Step 3 — PII Processing (`process_image_for_pii`)

- Extracts text → runs Presidio analysis → applies anonymisation
- Returns `{ extracted_text, entities_found, redacted_text }`

---

### 4.12 File Handlers (`file_handlers.py`)

A **handler factory** that produces sanitised output files in their original format (not just text).

#### Handler Registry

```python
HANDLERS = {
    ".txt": handle_txt,
    ".csv": handle_txt,     # CSV treated as plain text
    ".docx": handle_docx,
    ".pdf": handle_pdf,
    ".xlsx": handle_xlsx,
}
```

#### Each Handler's Signature

```python
def handle_FORMAT(input_path: str, output_path: str, sanitize: Callable[[str], str]) -> dict
```

The `sanitize` callback is `process_text_with_presidio()` from `app.py` — it takes raw text and returns Presidio-sanitised text.

#### Handler Details

| Handler | What It Does |
|---|---|
| `handle_txt` | Reads file (UTF-8/latin-1 fallback), sanitises entire text, writes output `.txt` |
| `handle_docx` | Iterates paragraphs + table cells, sanitises each text run, preserves bold/italic formatting, saves `.docx` |
| `handle_pdf` | Extracts text per page, diffs original vs sanitised to find PII words, draws **black redaction rectangles** over PII locations using PyMuPDF, saves redacted `.pdf` |
| `handle_xlsx` | Loads with pandas, applies cell-by-cell sanitisation, exports to new `.xlsx` via openpyxl |

#### Router Function

```python
def process_file(input_path: str, output_dir: str, sanitize: SanitizeFn) -> dict:
    # Resolves handler by extension, calls it, returns result dict
    # { "status": "Success", "pii_count": int, "output_path": str }
```

---

### 4.13 Configuration (`config.py`)

Centralised settings for all backend modules.

| Setting | Value | Description |
|---|---|---|
| `AES_KEY` | Random 32 bytes | AES-256 encryption key (regenerated per run for demo) |
| `FPE_KEY` | Random 16 bytes | FF3-1 encryption key |
| `FPE_TWEAK` | Random 7 bytes | FF3-1 tweak parameter |
| `ENTITY_TYPES` | List | Presidio entity type codes to detect |
| `MIN_CONFIDENCE_SCORE` | 0.4 | Minimum confidence threshold for entity acceptance |
| `ENTITY_RISK_WEIGHTS` | Dict | Risk weights per entity type (for threat scoring) |
| `THREAT_THRESHOLDS` | `{LOW: 10, MEDIUM: 30, HIGH: 60}` | Score → threat level mapping |
| `AUDIT_LOG_FILE` | `audit_log.json` | Audit chain persistence path |
| `DATABASE_PATH` | `pii_shield.db` | SQLite database path |
| `TESSERACT_CMD` | Optional | Override path for Tesseract binary |

---

## 5. Flask API Server (`app.py`)

The Flask application exposes REST endpoints and handles CORS for cross-origin requests from the frontend (served from `file://` or `localhost`).

### Routes

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scan` | **Primary endpoint** — receives base64 file data, runs the full pipeline, returns sanitised results + sanitised file data-URI |
| `POST` | `/analyze` | Text-only analysis (for textarea input) |
| `POST` | `/analyze_table` | ASCII table cell-by-cell processing |
| `POST` | `/upload` | Multipart file upload with SQLite metadata storage |
| `GET` | `/download/<file_id>` | Download a sanitised file by ID |
| `GET` | `/` | Serves the `templates/index.html` page |
| `GET` | `/health` | Health check endpoint |

### `/api/scan` — Main Endpoint (Detail)

This is the route the frontend actually calls. Flow:

1. Receives JSON: `{ fileData: "data:*;base64,...", fileName: "doc.pdf", user: "email" }`
2. Decodes base64 → writes to temp file
3. Checks if the content is an ASCII table → routes to `table_processor` if yes
4. Calls `file_handlers.process_file()` to produce a sanitised output file (PDF/DOCX/XLSX/TXT)
5. Reads the sanitised file → encodes as a base64 data-URI (`data:mime/type;base64,...`)
6. Calls `pipeline.process_document()` for the full analysis (entities, threat report, etc.)
7. Returns JSON with `sanitizedFileData` (data-URI), `masked_text`, `entities`, `threat_level`, `risk_score`, etc.
8. Cleans up temp files

### Helper Functions

| Function | Purpose |
|---|---|
| `get_pipeline()` | Lazy-initialises `PIIShieldPipeline` (Presidio's NLP models are slow to load) |
| `get_table_processor()` | Lazy-initialises `AsciiTableProcessor` |
| `process_text_with_presidio(text)` | Callback wrapper — analyzes + anonymises text via Presidio. Used as the `sanitize` argument for `file_handlers` |
| `is_ascii_table(text)` | Detects pipe-delimited tables by counting `|` characters across lines |
| `init_db()` | Creates SQLite `documents` table if it doesn't exist |

---

## 6. Frontend — React/Tailwind UI

The frontend is built as **single-page React applications** embedded in HTML files, transpiled in-browser via Babel. All pages share the same Firebase configuration and Tailwind styling.

### Pages

| Page | Role | Access |
|---|---|---|
| `Login.html` | Email/password authentication | Public |
| `Signup.html` | User registration with role selection (User / Admin) | Public |
| `Dashboard.html` | Admin overview — total files, PII entities, threat distribution | Admin |
| `UserDashboard.html` | User overview — own sanitised files, security status | User |
| `Upload.html` | Drag-drop file upload → automatic scan → results modal | Admin |
| `ViewFiles.html` | Admin file browser — view original, sanitised text, entities | Admin |
| `SanitizedFilesViewer.html` | View sanitised file content (masked text preview) | User |
| `DownloadSanitized.html` | Download sanitised files | User |
| `DownloadPII.html` | Download encrypted PII data (admin only) | Admin |
| `SearchSanitized.html` | Search files by name, date, entity type | User |
| `StatisticalAnalysis.html` | Analytics charts — entity distribution, threat trends | Admin |
| `UserStatisticalAnalysis.html` | User's own PII statistics | User |
| `ManageUsers.html` | User administration — roles, status, credentials | Admin |
| `AuditLogs.html` | View tamper-evident audit trail | Admin |

### Authentication Model

- **Firebase Auth** handles email/password login with bcrypt hashing
- On login, the user's `role` is read from Firestore (`users` collection)
- **Admin** is redirected to `Dashboard.html`; **User** to `UserDashboard.html`
- Each page checks `firebaseAuth.currentUser` on load — redirects to `Login.html` if unauthenticated

### Upload & Scan Flow (`Upload.html`)

1. User drags/drops or selects files (allowed: `.txt`, `.csv`, `.pdf`, `.docx`, `.xlsx`, `.sql`, `.png`, `.jpg`, `.jpeg`)
2. File is read as base64 via `FileReader.readAsDataURL()`
3. Metadata is saved to Firestore `files` collection (status: `uploaded`)
4. `scanFile()` is called:
   - Sets status → `processing`
   - POSTs to `/api/scan` with `{ fileData, fileName, user }`
   - On success: saves `scanResults` + `sanitizedFileData` to Firestore, sets status → `completed`
   - On failure: saves `scanError`, sets status → `error`
5. Results modal shows: threat level badge, risk score, entity count, entity breakdown, masked text preview

---

## 7. Frontend–Backend Integration

### Data Flow

```
Frontend (Upload.html)
   │
   │  POST /api/scan
   │  Body: { fileData: "data:application/pdf;base64,JVBERi...",
   │          fileName: "report.pdf",
   │          user: "admin@example.com" }
   │
   ▼
Backend (app.py /api/scan)
   │
   │  1. Decode base64 → temp file
   │  2. file_handlers.process_file() → sanitised file
   │  3. pipeline.process_document() → analysis results
   │  4. Encode sanitised file → base64 data-URI
   │
   │  Response: {
   │    success: true,
   │    masked_text: "...",
   │    sanitizedFileData: "data:application/pdf;base64,...",
   │    entities: [...],
   │    threat_level: "HIGH",
   │    risk_score: 45.2,
   │    entity_breakdown: {...},
   │    recommended_actions: [...]
   │  }
   │
   ▼
Frontend (Upload.html scanFile())
   │
   │  Firestore update:
   │  files/{docId} = {
   │    status: "completed",
   │    scanResults: { threat_level, risk_score, entity_count, ... },
   │    sanitizedFileData: "data:application/pdf;base64,..."
   │  }
   │
   ▼
Viewer Pages (SanitizedFilesViewer.html, DownloadSanitized.html)
   │
   │  Read from Firestore:
   │  - Preview: decode sanitizedFileData → display content
   │  - Download: create <a> link with sanitizedFileData as href
```

### Key Integration Points

| Frontend Action | API Call | Backend Handler | Database |
|---|---|---|---|
| Upload file | `POST /api/scan` | `api_scan()` → `pipeline.process_document()` + `file_handlers.process_file()` | Firestore `files` |
| Analyse text | `POST /analyze` | `analyze_text_route()` → `pipeline.process_text()` | — |
| Process table | `POST /analyze_table` | `analyze_table_route()` → `process_ascii_table()` | — |
| View results | Firestore read | — | Firestore `files/{id}.scanResults` |
| Download sanitised | Firestore read | — | Firestore `files/{id}.sanitizedFileData` |
| View audit logs | Firestore read | — | Firestore `audit_logs` |

---

## 8. File Processing Pipeline — End-to-End Flow

```
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: USER UPLOADS FILE                                      │
│ Upload.html → FileReader.readAsDataURL() → base64 string       │
│ Metadata saved to Firestore (status: "uploaded")               │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 2: BACKEND RECEIVES REQUEST                               │
│ POST /api/scan → decode base64 → write temp file               │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 3: TEXT EXTRACTION (ingestion.py)                          │
│ .pdf → PyMuPDF    .docx → python-docx    .xlsx → pandas        │
│ .txt/.csv → read   .sql → read    .png/.jpg → Tesseract OCR    │
│ → Output: plain text string                                    │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 4: TABLE DETECTION                                        │
│ is_ascii_table() checks for pipe delimiters                    │
│ If table → table_processor.py (cell-by-cell)                   │
│ If not  → continue to step 5                                   │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 5: PII ANALYSIS (analyzer_engine.py + recognizers.py)     │
│ Presidio AnalyzerEngine runs all recognizers:                  │
│ • Built-in: PERSON, EMAIL, CREDIT_CARD, PHONE, SSN, IP, etc.  │
│ • Custom:   IN_AADHAAR (Verhoeff), IN_PAN, INDIAN_NAME        │
│ Minimum confidence threshold: 0.4                              │
│ → Output: list of RecognizerResult                             │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 6: DUAL-STATE GENERATION (dual_state.py)                  │
│ For each entity:                                               │
│   Masked view:    "XXXX-XXXX-XXXX-1234", "[REDACTED_NAME]"    │
│   Encrypted view: AES-256-GCM (text) or FF3-1 FPE (numeric)   │
│ → Output: DualStateRecord (masked_text + encrypted entities)   │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 7: SANITISED FILE GENERATION (file_handlers.py)           │
│ Produces a sanitised copy in the original format:              │
│   .pdf → black redaction boxes over PII regions                │
│   .docx → sanitised paragraphs with formatting preserved       │
│   .xlsx → cell-by-cell replacement                             │
│   .txt/.csv → full text replacement                            │
│ → Output: sanitised file in sanitized_files/ directory         │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 8: THREAT SCORING (threat_intel.py)                       │
│ risk_score = Σ(weight[type] × confidence)                      │
│ Maps to: LOW (<10) | MEDIUM (10-30) | HIGH (30-60) | CRIT (≥60)│
│ → Output: threat report with level, score, actions             │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 9: AUDIT CHAIN (audit_logger.py)                          │
│ Records: UPLOAD → EXTRACT → ANALYZE → ENCRYPT → REPORT        │
│ Each entry hashed with SHA-256 chained to previous             │
│ → Output: verified chain (audit_chain_valid: true/false)       │
└─────────────────────────┬──────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│ STEP 10: RESPONSE TO FRONTEND                                  │
│ JSON: { success, masked_text, sanitizedFileData (data-URI),    │
│         entities, threat_level, risk_score, entity_breakdown,  │
│         recommended_actions }                                  │
│                                                                │
│ Frontend saves to Firestore → viewer pages display results     │
└────────────────────────────────────────────────────────────────┘
```

---

## 9. PII Detection Algorithms

### Built-in Presidio Recognizers

| Entity | Detection Method | Validation |
|---|---|---|
| `PERSON` | spaCy NER (transformer/CNN model) | NLP confidence score |
| `EMAIL_ADDRESS` | Regex `[\w.-]+@[\w.-]+\.\w+` | Format validation |
| `CREDIT_CARD` | Regex for 13–19 digit patterns | **Luhn algorithm** checksum |
| `PHONE_NUMBER` | Regex with country prefixes | Context word boost |
| `US_SSN` | Regex `\d{3}-\d{2}-\d{4}` | Area number validation |
| `IP_ADDRESS` | IPv4/IPv6 regex patterns | Range validation |
| `LOCATION` | spaCy NER + gazetteer | NLP confidence |
| `DATE_TIME` | Multi-format date/time regex | Contextual validation |
| `URL` | URI regex | Format validation |

### Custom Indian Recognizers

| Entity | Pattern | Validation Algorithm | Context Boost |
|---|---|---|---|
| `IN_AADHAAR` | 12 digits, first ∈ [2–9] | **Verhoeff checksum** (D/P/inverse tables) | "aadhaar", "uid", "uidai", "आधार" |
| `IN_PAN` | `[A-Z]{5}[0-9]{4}[A-Z]` | 4th char entity-type validation; reject EMP/ROL/REG/INV | "pan", "permanent account", "income tax" |
| `INDIAN_NAME` | 2–3 word Title Case | Curated list of 100+ Indian first/last names | "name", "customer", "employee" |

### Confidence Scoring

```
final_score = min(base_score + context_boost, 1.0)
```

- **Base score:** Determined by the recognizer (pattern complexity, validation result)
- **Context boost:** +0.3 to +0.5 if header/nearby text contains relevant keywords
- **Acceptance threshold:** 0.4 (configurable in `config.py`, lowered to 0.3 for table processing)

---

## 10. Encryption Methodology

### Dual Encryption Architecture

```
                    Detected PII Entity
                           │
                    ┌──────┴──────┐
                    │             │
              Numeric?        Text?
           (CC, Phone,     (Name, Email,
            Aadhaar)        PAN, SSN)
                │              │
                ▼              ▼
          FF3-1 FPE      AES-256-GCM
       (format-preserving)  (authenticated)
                │              │
                ▼              ▼
          Same length      Ciphertext +
          Same charset     Nonce + Tag
          (queryable)      (tamper-proof)
```

### AES-256-GCM — For Text PII

```
Key:   32 bytes (256 bits), randomly generated
Nonce: 12 bytes (96 bits), random per encryption
Tag:   16 bytes (128 bits), authentication

Encrypt("John Doe") → {
  ciphertext: "aBcD1234FgHi..."  (base64)
  nonce:      "xYzW6789..."      (base64)
  tag:        "pQrS..."          (base64)
}

Decrypt(ciphertext, nonce, tag, key) → "John Doe"
```

### FF3-1 FPE — For Numeric PII

```
Key:   16 bytes (128 bits)
Tweak: 7 bytes
Radix: 10 (digits only)

Encrypt("4532111111111111") → "7293048156823741"
                                 ↑ Same length, same charset

Decrypt("7293048156823741") → "4532111111111111"
```

---

## 11. Threat Scoring & Risk Assessment

See [Section 4.7](#47-threat-intelligence-threat_intelpy) for the full threat intelligence engine details.

Summary:
- Each detected entity contributes `weight × confidence` to the total risk score
- The score maps to a threat level (LOW / MEDIUM / HIGH / CRITICAL)
- The report includes per-type breakdowns, top detections, and recommended actions
- Actions escalate from "standard handling" (LOW) to "urgent quarantine with breach assessment" (CRITICAL)

---

## 12. Audit Trail & Tamper Detection

See [Section 4.8](#48-audit-logger-audit_loggerpy) for the full audit logger details.

Summary:
- SHA-256 hash chain — each entry depends on all previous entries
- Actions tracked: `UPLOAD` → `EXTRACT` → `ANALYZE` → `ENCRYPT` → `REPORT`
- Modifying any entry breaks the chain (detected by `verify_chain()`)
- Persisted to `audit_log.json`
- Compliant with SOX, GDPR, PCI-DSS, India DPDP Act

---

## 13. Database Schema

### Firestore Collections (Frontend)

```
users/{userId}
  ├── name: string
  ├── email: string
  ├── role: "admin" | "user"
  ├── status: "active" | "inactive"
  └── createdAt: timestamp

files/{docId}
  ├── fileName: string
  ├── fileData: string (base64 data-URI — original)
  ├── sanitizedFileData: string (base64 data-URI — sanitised)
  ├── fileSize: number
  ├── uploadedBy: string
  ├── uploadTime: timestamp
  ├── status: "uploaded" | "processing" | "completed" | "error"
  ├── scanResults: {
  │     threat_level: string
  │     risk_score: number
  │     entity_count: number
  │     entity_breakdown: map
  │     entities: array (max 50)
  │     masked_text: string (max 5000 chars)
  │     recommended_actions: array
  │     scannedAt: string
  │   }
  └── scanError: string (only on error)
```

### SQLite Tables (Backend)

```sql
CREATE TABLE documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT NOT NULL,
    file_type   TEXT,
    file_size   INTEGER,
    file_hash   TEXT,
    status      TEXT DEFAULT 'processing',
    threat_level TEXT,
    risk_score  REAL,
    pii_count   INTEGER DEFAULT 0,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Full Schema (in `db_schema.sql`)

Additional tables defined for production use:

| Table | Purpose |
|---|---|
| `users` | RBAC with roles: admin, analyst, viewer |
| `documents` | File metadata, threat assessment |
| `pii_records` | Encrypted entities with AES/FPE data |
| `threat_reports` | Full JSON threat reports |
| `audit_logs` | Hash-chain entries |

RBAC views:
- `admin_pii_view` — full encrypted + masked data
- `analyst_pii_view` — masked data only (no decryption keys)
- `viewer_document_view` — metadata only (no PII)

---

## 14. Security Model & Compliance

### Authentication & Authorisation

| Layer | Technology | Details |
|---|---|---|
| Authentication | Firebase Auth | Email/password with bcrypt hashing |
| Role storage | Firestore | `users/{uid}.role` = `"admin"` or `"user"` |
| Route protection | Frontend JS | Each page checks `firebaseAuth.currentUser` on load |
| RBAC | SQL views | Admin / Analyst / Viewer access levels |

### Data Protection

| State | Protection |
|---|---|
| **At rest** | AES-256-GCM encryption for stored PII; FPE for numeric data |
| **In transit** | HTTPS (Firebase) + CORS-restricted API |
| **At process** | Dual-state design — masked view visible, encrypted raw isolated |
| **Audit** | SHA-256 hash chain — tamper detection for all operations |

### Threat Model Mitigations

| Attack | Mitigation |
|---|---|
| Database exfiltration | AES-256-GCM double-encrypts all PII at rest |
| Audit log tampering | SHA-256 hash chain — modifying any entry breaks all downstream hashes |
| SQL injection in dumps | SQL handler validates syntax, escapes quotes, processes string values only |
| OCR evasion | Tesseract LSTM + image preprocessing (bilateral filter, adaptive threshold) |
| False negatives (missed PII) | Custom Indian recognizers + IndianNameRecognizer fallback |
| Credential theft | Firebase Auth with bcrypt; no raw passwords stored |

---

## 15. Deployment & Configuration

### Prerequisites

- Python 3.13+
- Node.js (for `package.json` if needed, though frontend is CDN-based)
- Tesseract OCR (optional, for image processing)

### Backend Setup

```bash
cd logic
python -m venv .venv
.venv\Scripts\activate              # Windows
pip install -r requirements.txt
python app.py                        # Starts Flask on http://localhost:5000
```

### Frontend Setup

Open any HTML file in a browser, or serve via a local HTTP server. Firebase configuration is in `firebaseConfig.js` — update project credentials if needed.

### Environment Notes

- Encryption keys (`AES_KEY`, `FPE_KEY`, `FPE_TWEAK`) are randomly generated each run — for production, persist these securely
- `TESSERACT_CMD` in `config.py` can be set to override the Tesseract binary path
- SQLite (`pii_shield.db`) is auto-created on first run
- The `sanitized_files/` directory is auto-created to store output files

### Project Structure

```
Hackamined/
├── README.md
├── doc.md                          ← This file
├── FRONTEND/
│   ├── firebaseConfig.js           Firebase project configuration
│   ├── Login.html                  Authentication page
│   ├── Signup.html                 Registration page
│   ├── Dashboard.html              Admin dashboard
│   ├── UserDashboard.html          User dashboard
│   ├── Upload.html                 File upload + scanning
│   ├── ViewFiles.html              Admin file viewer
│   ├── SanitizedFilesViewer.html   User sanitised file viewer
│   ├── DownloadSanitized.html      Download sanitised files
│   ├── DownloadPII.html            Download encrypted PII (admin)
│   ├── SearchSanitized.html        Search files
│   ├── StatisticalAnalysis.html    Admin analytics
│   ├── UserStatisticalAnalysis.html  User analytics
│   ├── ManageUsers.html            User management (admin)
│   ├── AuditLogs.html              Audit trail viewer
│   ├── updateSanitizedFile.js      File update utility
│   └── package.json                Frontend package metadata
│
└── logic/
    ├── app.py                      Flask API server
    ├── pipeline.py                 PIIShieldPipeline orchestrator
    ├── ingestion.py                Multi-format text extraction
    ├── analyzer_engine.py          Presidio configuration
    ├── recognizers.py              Custom Indian PII recognizers
    ├── dual_state.py               Masked + encrypted dual views
    ├── encryption.py               AES-256-GCM + FF3-1 FPE
    ├── threat_intel.py             Threat scoring engine
    ├── audit_logger.py             SHA-256 hash-chain audit log
    ├── table_processor.py          ASCII table cell-by-cell processing
    ├── sql_handler.py              SQL dump sanitisation
    ├── ocr_pipeline.py             Tesseract OCR pipeline
    ├── file_handlers.py            Format-specific file sanitisation
    ├── config.py                   Centralised configuration
    ├── db_schema.sql               Full database schema
    ├── requirements.txt            Python dependencies
    ├── test_pipeline.py            Unit tests
    ├── audit_log.json              Persistent audit chain
    ├── templates/
    │   └── index.html              Flask template
    └── sample_data/
        ├── sample.sql              Test SQL dump
        ├── sample_sanitized.sql    Sanitised SQL output
        └── sample_text.txt         Test text file
```
