# PII Shield — Hackamined

**AI-powered document scanning platform that detects, sanitizes, and encrypts Personally Identifiable Information across 11+ file formats.**

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-black?logo=flask)
![Firebase](https://img.shields.io/badge/Firebase-Auth%20%7C%20Firestore%20%7C%20Storage-orange?logo=firebase)
![Presidio](https://img.shields.io/badge/Microsoft%20Presidio-NLP%20PII%20Engine-0078D4?logo=microsoft)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

PII Shield scans uploaded documents for personally identifiable information — emails, phone numbers, Aadhaar, PAN, credit cards, SSNs, and more — then produces sanitized copies in the original file format with PII masked or redacted. It is built for compliance teams, data analysts, and organizations that handle sensitive personal data and need to share or archive documents safely.

- **Multi-format scanning** — `.txt`, `.csv`, `.pdf`, `.docx`, `.xlsx`, `.sql`, `.png`, `.jpg`, `.jpeg`, `.mp3`, `.wav`
- **Dual-state encryption** — every detected entity gets a masked view (for analysts) and an AES-256-GCM or FF3-1 FPE encrypted view (for admins)
- **Threat scoring** — documents rated LOW / MEDIUM / HIGH / CRITICAL based on entity types and confidence
- **Tamper-evident audit trail** — SHA-256 hash-chained log entries for SOX, GDPR, PCI-DSS compliance
- **Role-based access control** — Admin sees full results; User sees only sanitized outputs
- **Custom Indian PII recognizers** — Aadhaar (Verhoeff checksum), PAN, and Indian name detection

*For full technical documentation, see [doc.md](doc.md)*

---

## Project Structure

```
Hackamined/
├── README.md                           Project overview and setup guide
├── doc.md                              Full technical documentation
├── FRONTEND/
│   ├── firebaseConfig.js               Firebase project configuration (API keys, project ID)
│   ├── Login.html                      Email/password authentication page
│   ├── Signup.html                     User registration with role selection (User / Admin)
│   ├── Dashboard.html                  Admin overview — total files, PII entities, threat distribution
│   ├── UserDashboard.html              User overview — own sanitised files, security status
│   ├── Upload.html                     Drag-drop file upload → automatic scan → results modal
│   ├── ViewFiles.html                  Admin file browser — view original, sanitised text, entities
│   ├── SanitizedFilesViewer.html       User sanitised file viewer (masked text preview)
│   ├── DownloadSanitized.html          Download sanitised files in original format
│   ├── DownloadPII.html                Download encrypted PII data (admin only)
│   ├── SearchSanitized.html            Search files by name, date, entity type
│   ├── StatisticalAnalysis.html        Admin analytics charts — entity distribution, threat trends
│   ├── UserStatisticalAnalysis.html    User's own PII statistics
│   ├── ManageUsers.html                User administration — roles, status, credentials (admin)
│   ├── AuditLogs.html                  Tamper-evident audit trail viewer (admin)
│   ├── updateSanitizedFile.js          File update utility
│   └── package.json                    Frontend package metadata
│
└── logic/
    ├── app.py                          Flask API server — routes, background processing, Firestore sync
    ├── pipeline.py                     PIIShieldPipeline orchestrator — ties all modules together
    ├── ingestion.py                    Multi-format text extraction (PDF, DOCX, XLSX, images, etc.)
    ├── analyzer_engine.py              Presidio analyzer + anonymizer configuration
    ├── recognizers.py                  Custom Indian PII recognizers (Aadhaar, PAN, Indian names)
    ├── dual_state.py                   Masked + encrypted dual-view record generation
    ├── encryption.py                   AES-256-GCM (text PII) + FF3-1 FPE (numeric PII)
    ├── threat_intel.py                 Weighted risk scoring engine (LOW → CRITICAL)
    ├── audit_logger.py                 SHA-256 hash-chain tamper-evident audit log
    ├── table_processor.py              ASCII pipe-delimited table cell-by-cell PII processing
    ├── sql_handler.py                  SQL dump sanitisation (INSERT values only, DDL preserved)
    ├── ocr_pipeline.py                 Tesseract/EasyOCR text extraction + image PII redaction
    ├── audio_handler.py                Whisper transcription + 1 kHz beep overlay on PII segments
    ├── file_handlers.py                Format-specific sanitised file generation (PDF, DOCX, XLSX, TXT)
    ├── context_rules.py                Context-aware post-processing to reduce false positives
    ├── config.py                       Centralised configuration (keys, thresholds, entity types)
    ├── db_schema.sql                   Full database schema (users, documents, pii_records, etc.)
    ├── requirements.txt                Python dependencies
    ├── serviceAccountKey.json          Firebase service account credentials (not committed)
    ├── test_pipeline.py                Unit tests
    ├── _test_quarterly.py              Quarterly test suite
    ├── audit_log.json                  Persistent hash-chain audit entries (auto-created)
    ├── templates/
    │   └── index.html                  Flask template for root route
    └── sample_data/
        ├── sample.sql                  Test SQL dump
        ├── sample_sanitized.sql        Sanitised SQL output example
        └── sample_text.txt             Test text file
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Python** | 3.13 or higher |
| **Tesseract OCR** | Required for image scanning (`.png`, `.jpg`, `.jpeg`). **Windows:** download from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki). **Linux:** `sudo apt install tesseract-ocr`. If not installed, image OCR falls back to EasyOCR (slower, no system binary needed). |
| **Firebase project** | A Firebase project with **Firestore**, **Storage**, and **Authentication** (email/password) enabled |
| **Firebase service account key** | A JSON key file for server-side Firestore access |

Node.js is **not** required — the frontend uses React and Tailwind via CDN with in-browser Babel transpilation.

---

## Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd Hackamined
   ```

2. **Navigate to the backend directory**

   ```bash
   cd logic
   ```

3. **Create and activate a virtual environment**

   Windows:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

   macOS / Linux:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. **Install Python dependencies**

   ```bash
   pip install -r requirements.txt
   ```

5. **Tesseract setup**

   If Tesseract is installed in a non-default location, open `logic/config.py` and set the `TESSERACT_CMD` variable to the full path of the Tesseract binary:

   Windows:
   ```python
   TESSERACT_CMD = "C:/Program Files/Tesseract-OCR/tesseract.exe"
   ```

   Linux:
   ```python
   TESSERACT_CMD = "/usr/bin/tesseract"
   ```

   If Tesseract is on your system PATH, no configuration is needed — the default will work automatically.

6. **Firebase service account setup**

   - Go to the [Firebase Console](https://console.firebase.google.com/)
   - Open your project → **Project Settings** → **Service Accounts**
   - Click **Generate new private key** → download the JSON file
   - Rename it to `serviceAccountKey.json` and place it inside the `logic/` directory

7. **Firebase frontend configuration**

   Open `FRONTEND/firebaseConfig.js` and replace the placeholder values with your own Firebase project credentials (API key, auth domain, project ID, storage bucket, messaging sender ID, app ID).

---

## Running the Project

**Start the backend:**

```bash
cd logic
python app.py
```

The Flask server starts on `http://localhost:5000`.

**Open the frontend:**

Open any HTML file from the `FRONTEND/` directory directly in a browser (e.g. `Upload.html`), or serve the directory with a local HTTP server:

```bash
cd FRONTEND
python -m http.server 8080
```

Then open `http://localhost:8080/Upload.html` in your browser.

**When both are running correctly**, you should be able to log in (or sign up), upload a file on the Upload page, and see it move through `uploaded → processing → completed` with a threat level badge and entity breakdown.

---

## Supported File Types

| File Type | What It Does |
|---|---|
| `.txt` | Reads plain text, replaces PII with masked placeholders, writes sanitized `.txt` |
| `.csv` | Treated as plain text — scans all cell values for PII, outputs sanitized `.txt` |
| `.pdf` | Extracts text per page, draws black redaction rectangles over PII locations using PyMuPDF |
| `.docx` | Iterates paragraphs and table cells, sanitizes each text run, preserves bold/italic formatting |
| `.xlsx` | Loads with pandas, applies cell-by-cell PII replacement, exports to new `.xlsx` |
| `.sql` | Parses INSERT statements, sanitizes string values inside `VALUES(...)`, leaves DDL untouched |
| `.png` `.jpg` `.jpeg` | Runs OCR (Tesseract or EasyOCR), draws black bounding boxes over PII words in the image |
| `.mp3` `.wav` | Transcribes with Whisper, overlays a 1 kHz beep on each PII word segment in the audio |

---

## Environment Notes

- **Encryption keys** (`AES_KEY`, `FPE_KEY`, `FPE_TWEAK`) are randomly generated each run. For production, persist these in a KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS) or HSM.
- **Tesseract path** can be overridden via `TESSERACT_CMD` in `config.py`. If unset, the system PATH is used.
- **SQLite database** (`pii_shield.db`) is auto-created on first run inside `logic/`.
- **`sanitized_files/` directory** is auto-created inside `logic/` to store all sanitized output files.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| **Stuck on "Scanning"** | Check the Flask terminal for errors. Confirm `serviceAccountKey.json` is valid and located in `logic/`. If credentials have expired, regenerate from **Firebase Console → Project Settings → Service Accounts → Generate new private key**. |
| **"Sanitized file not found"** | Confirm the Flask backend is running and the `sanitized_files/` directory exists inside `logic/`. |
| **Tesseract not found** | Set `TESSERACT_CMD` in `config.py` to the full path of the Tesseract binary (e.g. `C:/Program Files/Tesseract-OCR/tesseract.exe`). |
| **Firebase permission denied** | Check that Firestore security rules allow read/write for authenticated users, and that the service account JSON has the **Editor** role on the Firebase project. |

---

## License

MIT License