"""
=============================================================================
PII Shield — Web Frontend + API Server
=============================================================================
Flask server providing:
  - API endpoints for the React frontend (CORS-enabled)
  - File scanning via the PII Shield pipeline
  - Text analysis and table processing

Run with: python app.py
Then open: http://localhost:5000
=============================================================================
"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import traceback

import requests as http_requests
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

from pipeline import PIIShieldPipeline
from ingestion import ingest_file
from table_processor import process_ascii_table, create_table_processor
from file_handlers import process_file, HANDLERS
from config import DATABASE_PATH

# Firebase Admin SDK — needed to write scan results back to Firestore
try:
    import firebase_admin
    from firebase_admin import credentials, firestore as admin_firestore
    _FIREBASE_AVAILABLE = True
except ImportError:
    _FIREBASE_AVAILABLE = False
    print("WARNING: firebase-admin not installed. Run: pip install firebase-admin")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB upload limit
CORS(app, origins="*")  # Allow all origins during development
pipeline = None  # Lazy initialization
table_processor = None  # Lazy initialization

SANITIZED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sanitized_files")
os.makedirs(SANITIZED_DIR, exist_ok=True)

TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
os.makedirs(TEMP_DIR, exist_ok=True)

# ---- In-memory scan results cache (fallback when Firestore writes fail) ----
_scan_results_lock = threading.Lock()
_scan_results = {}  # doc_id → {"status": "completed"|"error", ...}

# ---- Firebase Admin SDK Setup ----
_firestore_client = None


def init_firebase():
    """Initialize Firebase Admin SDK for server-side Firestore writes."""
    global _firestore_client
    if not _FIREBASE_AVAILABLE:
        print("  firebase-admin not installed — using polling fallback only.")
        return
    service_account_path = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json"),
    )
    if os.path.exists(service_account_path):
        try:
            cred = credentials.Certificate(service_account_path)
            firebase_admin.initialize_app(cred)
            _firestore_client = admin_firestore.client()
            print("Firebase Admin SDK initialized (Firestore writes will be attempted).")
        except Exception as e:
            print(f"WARNING: Firebase Admin SDK init failed: {e}")
            _firestore_client = None
    else:
        print(f"WARNING: Service account key not found at: {service_account_path}")
        print("  Place serviceAccountKey.json in logic/ or set FIREBASE_SERVICE_ACCOUNT env var.")
        print("  Firestore writes from Flask DISABLED (frontend fallback will be used).")


def _update_firestore_completed(doc_id, response):
    """Fire-and-forget: try to write scan results to Firestore in a background thread."""
    if not _firestore_client or not doc_id:
        return
    def _write():
        try:
            update_payload = {
                "status": "completed",
                "threatLevel": response.get("threat_level", "LOW"),
                "scanResults": {
                    "threat_level": response.get("threat_level", "LOW"),
                    "risk_score": response.get("risk_score", 0),
                    "entity_count": response.get("entity_count", 0),
                    "entity_breakdown": response.get("entity_breakdown", {}),
                    "entities": (response.get("entities") or [])[:50],
                    "masked_text": (response.get("masked_text") or "")[:500000],
                    "recommended_actions": response.get("recommended_actions", []),
                    "scannedAt": admin_firestore.SERVER_TIMESTAMP,
                },
            }
            san_data = response.get("sanitizedFileData", "")
            if san_data:
                update_payload["sanitizedFileData"] = san_data[:900000]
            orig_data = response.get("original_text", "")
            if orig_data:
                update_payload["fileData"] = orig_data[:500000]
            san_path = response.get("sanitizedFilePath", "")
            if san_path:
                update_payload["sanitizedFilePath"] = os.path.basename(san_path)
            _firestore_client.collection("files").document(doc_id).update(update_payload)
            print(f"[SCAN] Firestore updated for {doc_id}")
        except Exception as fs_err:
            print(f"[SCAN] Firestore update failed (non-blocking): {fs_err}")
    threading.Thread(target=_write, daemon=True).start()


def _update_firestore_error(doc_id, error_msg):
    """Fire-and-forget: mark the Firestore document as errored."""
    if not _firestore_client or not doc_id:
        return
    def _write():
        try:
            _firestore_client.collection("files").document(doc_id).update({
                "status": "error",
                "scanError": str(error_msg),
            })
        except Exception:
            pass
    threading.Thread(target=_write, daemon=True).start()


# ---- Database Setup ----
def get_db():
    """Get a connection to the SQLite database."""
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    """Create the documents table if it doesn't exist."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            doc_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename            VARCHAR(255) NOT NULL,
            file_type           VARCHAR(20)  NOT NULL,
            file_size_bytes     INTEGER,
            file_hash_sha256    VARCHAR(64)  NOT NULL,
            uploaded_by         VARCHAR(255) NOT NULL DEFAULT 'web_user',
            uploaded_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            scan_status         VARCHAR(20)  NOT NULL DEFAULT 'processing'
                                CHECK (scan_status IN ('processing', 'Success', 'Failed')),
            sanitized_file_path TEXT,
            pii_count           INTEGER      DEFAULT 0,
            threat_level        VARCHAR(20),
            risk_score          REAL,
            error_message       TEXT
        )
    """)
    db.commit()
    db.close()


# CORS is handled by flask-cors (see CORS(app) above)


def is_ascii_table(text: str) -> bool:
    """Detect if input text is an ASCII pipe-delimited table."""
    lines = text.strip().split("\n")
    pipe_lines = [l for l in lines if "|" in l]
    # At least 3 pipe-delimited lines (header + divider/data + data)
    if len(pipe_lines) < 3:
        return False
    # Check that pipe lines have consistent pipe counts
    pipe_counts = [l.count("|") for l in pipe_lines]
    return len(set(pipe_counts)) <= 2  # Allow minor variation


def get_pipeline():
    """Lazy-initialize the pipeline (Presidio takes time to load)."""
    global pipeline
    if pipeline is None:
        print("Initializing PII Shield Pipeline (this may take a few seconds)...")
        pipeline = PIIShieldPipeline()
        print("Pipeline ready!")
    return pipeline


def get_table_processor():
    """Lazy-initialize the table processor."""
    global table_processor
    if table_processor is None:
        print("Initializing Table Processor...")
        table_processor = create_table_processor(
            twelve_digit_mode="mask_last_4",
            name_mode="redact",
            min_score=0.3,
        )
        print("Table Processor ready!")
    return table_processor


@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyze text for PII.
    
    Expects JSON: {"text": "...", "user": "..."}
    Returns JSON with masked text, entities, and threat report.
    """
    data = request.get_json()
    text = data.get("text", "")
    user = data.get("user", "web_user")

    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    try:
        # Auto-detect ASCII tables and route to table processor
        if is_ascii_table(text):
            sanitized = process_ascii_table(
                text,
                twelve_digit_mode="ignore",  # Default: don't redact standalone numbers
                name_mode="redact",
                min_score=0.3,
            )
            response = {
                "success": True,
                "original_length": len(text),
                "masked_text": sanitized,
                "entities": [],
                "entity_count": 0,
                "threat_level": "TABLE",
                "risk_score": 0,
                "entity_breakdown": {},
                "recommended_actions": [
                    "Table processed cell-by-cell (alignment preserved)",
                    "Quasi-identifier column detection applied",
                ],
                "audit_valid": True,
            }
            return jsonify(response)

        p = get_pipeline()
        result = p.process_text(text, "web_input.txt", user)

        # Format response for frontend
        response = {
            "success": True,
            "original_length": len(text),
            "masked_text": result["masked_text"],
            "entities": result["entities"],
            "entity_count": len(result["entities"]),
            "threat_level": result["threat_report"]["threat_assessment"]["threat_level"],
            "risk_score": result["threat_report"]["threat_assessment"]["risk_score"],
            "entity_breakdown": result["threat_report"]["entity_breakdown"],
            "recommended_actions": result["threat_report"]["recommended_actions"],
            "audit_valid": result["audit_chain_valid"],
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "pipeline_loaded": pipeline is not None})


@app.route("/analyze_table", methods=["POST"])
def analyze_table():
    """
    Process an ASCII table with cell-by-cell PII detection.
    
    Fixes:
      - Bug 1: Missed Indian names (lower threshold + fallback recognizer)
      - Bug 2: Inconsistent 12-digit handling (unified operators)
      - Bug 3: Table alignment breaking (cell-by-cell processing)
    
    Expects JSON: {
        "text": "...",
        "twelve_digit_mode": "mask_last_4" | "full_mask" | "redact" | "ignore",
        "name_mode": "redact" | "mask_first" | "hash"
    }
    """
    data = request.get_json()
    text = data.get("text", "")
    twelve_digit_mode = data.get("twelve_digit_mode", "mask_last_4")
    name_mode = data.get("name_mode", "redact")

    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    try:
        # Process table with specified modes
        sanitized = process_ascii_table(
            text,
            twelve_digit_mode=twelve_digit_mode,
            name_mode=name_mode,
            min_score=0.3,  # Lower threshold to catch more names
        )

        response = {
            "success": True,
            "original_text": text,
            "sanitized_text": sanitized,
            "twelve_digit_mode": twelve_digit_mode,
            "name_mode": name_mode,
        }
        return jsonify(response)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def api_scan():
    """
    Queue a file for PII scanning — used by the React frontend.

    Accepts either:
      - FormData with a 'file' field (direct upload)
      - JSON with {"fileUrl", "fileName", "docId", "fileType"}

    Returns HTTP 202 with {"status": "queued"} immediately.
    Processing happens in a background thread that updates Firestore directly.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    uploaded_file = request.files.get("file")

    if uploaded_file:
        # ---- Direct file upload path (FormData) ----
        file_name = request.form.get("fileName", uploaded_file.filename or "unknown.txt")
        doc_id = request.form.get("docId", "")
        file_type = request.form.get("fileType", "")
        ext = file_type if file_type.startswith(".") else f".{file_type}" if file_type else os.path.splitext(file_name)[1].lower()
        ext = ext.lower()

        supported_extensions = {".txt", ".csv", ".pdf", ".docx", ".xlsx", ".sql", ".png", ".jpg", ".jpeg", ".mp3", ".wav"}
        if ext not in supported_extensions:
            _update_firestore_error(doc_id, f"Unsupported file type: {ext}")
            return jsonify({"error": f"Unsupported file type: {ext}", "status": "error"}), 400

        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in file_name)
        tmp_path = os.path.join(TEMP_DIR, f"{doc_id}_{safe_name}")
        uploaded_file.save(tmp_path)
        print(f"[SCAN] Received direct upload: {file_name} ({os.path.getsize(tmp_path)} bytes)")

        thread = threading.Thread(
            target=_background_scan,
            args=(None, file_name, doc_id, ext),
            kwargs={"local_path": tmp_path},
            daemon=True,
        )
        thread.start()
        return jsonify({"status": "queued"}), 202

    # ---- JSON / fileUrl path (existing behaviour) ----
    data = request.get_json() or {}
    file_url = data.get("fileUrl", "")
    file_name = data.get("fileName", "unknown.txt")
    doc_id = data.get("docId", "")
    file_type = data.get("fileType", "")

    if not file_url:
        _update_firestore_error(doc_id, "No file URL provided")
        return jsonify({"error": "No file URL provided", "status": "error"}), 400

    # Normalise extension
    ext = file_type if file_type.startswith(".") else f".{file_type}" if file_type else os.path.splitext(file_name)[1].lower()
    ext = ext.lower()

    supported_extensions = {".txt", ".csv", ".pdf", ".docx", ".xlsx", ".sql", ".png", ".jpg", ".jpeg", ".mp3", ".wav"}
    if ext not in supported_extensions:
        _update_firestore_error(doc_id, f"Unsupported file type: {ext}")
        return jsonify({"error": f"Unsupported file type: {ext}", "status": "error"}), 400

    # Spawn background thread so the HTTP response returns immediately
    thread = threading.Thread(
        target=_background_scan,
        args=(file_url, file_name, doc_id, ext),
        daemon=True,
    )
    thread.start()

    return jsonify({"status": "queued"}), 202


@app.route("/api/scan-status/<doc_id>", methods=["GET"])
def scan_status(doc_id):
    """Poll endpoint — returns cached scan results for the given docId."""
    with _scan_results_lock:
        entry = _scan_results.get(doc_id)
    if entry is None:
        return jsonify({"status": "processing"}), 200
    return jsonify(entry), 200


@app.route("/api/download-sanitized/<doc_id>", methods=["GET"])
def download_sanitized_file(doc_id):
    """
    Download the sanitized file in its original format (PDF, DOCX, etc.).
    Looks up the sanitizedFilePath from Firestore or the in-memory cache,
    then serves the file from sanitized_files/.
    """
    # Try in-memory cache first
    san_filename = None
    with _scan_results_lock:
        entry = _scan_results.get(doc_id)
        if entry:
            sp = entry.get("sanitizedFilePath", "")
            if sp:
                san_filename = os.path.basename(sp)

    # Try Firestore if not in cache
    if not san_filename and _firestore_client:
        try:
            doc_ref = _firestore_client.collection("files").document(doc_id).get()
            if doc_ref.exists:
                san_filename = doc_ref.to_dict().get("sanitizedFilePath", "")
        except Exception:
            pass

    if not san_filename:
        return jsonify({"error": "Sanitized file not found"}), 404

    san_path = os.path.join(SANITIZED_DIR, san_filename)
    if not os.path.exists(san_path):
        return jsonify({"error": "Sanitized file missing from server"}), 404

    # Determine a user-friendly download name from the original filename
    original_name = san_filename
    # Try to get original name from Firestore
    if _firestore_client:
        try:
            doc_ref = _firestore_client.collection("files").document(doc_id).get()
            if doc_ref.exists:
                original_name = doc_ref.to_dict().get("fileName", san_filename)
        except Exception:
            pass

    name, orig_ext = os.path.splitext(original_name)
    san_ext = os.path.splitext(san_filename)[1]
    download_name = f"{name}_sanitized{san_ext or orig_ext}"

    return send_file(
        san_path,
        as_attachment=True,
        download_name=download_name,
    )


def _background_scan(file_url, file_name, doc_id, ext, local_path=None):
    """Background thread: scan a file for PII. File is either already on disk (local_path) or downloaded from file_url."""
    import time as _time

    SCAN_TIMEOUT = 300  # seconds — hard limit (audio/Whisper needs more time)

    tmp_path = local_path
    start_ts = _time.monotonic()

    def _check_timeout(stage=""):
        elapsed = _time.monotonic() - start_ts
        if elapsed > SCAN_TIMEOUT:
            raise TimeoutError(f"Scan timed out after {SCAN_TIMEOUT}s during {stage}")

    try:
        # ---- Get file on disk ----
        if not tmp_path:
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in file_name)
            tmp_path = os.path.join(TEMP_DIR, f"{doc_id}_{safe_name}")
            resp = http_requests.get(file_url, timeout=120)
            resp.raise_for_status()
            with open(tmp_path, "wb") as f:
                f.write(resp.content)
            print(f"[SCAN] Downloaded {file_name} ({len(resp.content)} bytes) → {tmp_path}")
        _check_timeout("download")

        # Read raw bytes for text decoding
        with open(tmp_path, "rb") as f:
            file_bytes = f.read()

        p = get_pipeline()
        sanitized_file_data = ""  # will hold the masked text as a string
        original_text = ""  # will hold the original text for storage

        # ---- Audio file handling (.mp3, .wav) ----
        if ext in (".mp3", ".wav"):
            from audio_handler import process_audio_file
            audio_result = process_audio_file(
                tmp_path, process_text_with_presidio, SANITIZED_DIR, doc_id
            )
            _check_timeout("audio")
            if audio_result["status"] == "error":
                raise RuntimeError(audio_result.get("error", "Audio processing failed"))
            response = {
                "masked_text": audio_result["masked_text"],
                "sanitizedFileData": audio_result["masked_text"],
                "original_text": audio_result["transcript"],
                "sanitizedFilePath": os.path.basename(audio_result.get("sanitized_path", "")),
                "entities": audio_result["entities"],
                "entity_count": audio_result["entity_count"],
                "threat_level": audio_result["threat_level"],
                "risk_score": audio_result["risk_score"],
                "entity_breakdown": audio_result["entity_breakdown"],
                "recommended_actions": audio_result["recommended_actions"],
            }
            _update_firestore_completed(doc_id, response)
            with _scan_results_lock:
                _scan_results[doc_id] = {"status": "completed", **response}
            print(f"[SCAN] Completed (audio): {file_name}, threat={response['threat_level']}")
            return

        # ---- Text-based ASCII-table fast path ----
        text_extensions = {".txt", ".csv", ".sql"}
        if ext in text_extensions:
            try:
                text_content = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text_content = file_bytes.decode("latin-1")
            original_text = text_content

            if is_ascii_table(text_content):
                sanitized = process_ascii_table(
                    text_content, twelve_digit_mode="ignore",
                    name_mode="redact", min_score=0.3,
                )
                # Save sanitized text file to disk
                table_san_path = os.path.join(SANITIZED_DIR, f"{doc_id}_sanitized{ext}")
                with open(table_san_path, "w", encoding="utf-8") as sf:
                    sf.write(sanitized)
                response = {
                    "masked_text": sanitized,
                    "sanitizedFileData": sanitized,
                    "original_text": original_text,
                    "sanitizedFilePath": table_san_path,
                    "entities": [],
                    "entity_count": 0,
                    "threat_level": "LOW",
                    "risk_score": 0,
                    "entity_breakdown": {},
                    "recommended_actions": ["Table processed cell-by-cell"],
                }
                _update_firestore_completed(doc_id, response)
                with _scan_results_lock:
                    _scan_results[doc_id] = {"status": "completed", **response}
                print(f"[SCAN] Completed (table): {file_name}")
                return

        # ---- SQL file handling (INSERT-aware sanitization) ----
        if ext == ".sql":
            _check_timeout("pre-sql")
            p = get_pipeline()
            result = p.process_document(tmp_path, user="admin")
            _check_timeout("sql-analysis")

            # Read full sanitized SQL content from the file produced by _process_sql
            sql_san_src = result.get("sanitized_sql_path", "")
            full_sanitized_sql = ""
            sql_dest = ""
            if sql_san_src and os.path.exists(sql_san_src):
                with open(sql_san_src, "r", encoding="utf-8") as sf:
                    full_sanitized_sql = sf.read()
                # Copy to sanitized_files/ with doc_id naming
                import shutil
                sql_dest = os.path.join(SANITIZED_DIR, f"{doc_id}_sanitized.sql")
                shutil.copy2(sql_san_src, sql_dest)

            response = {
                "masked_text": full_sanitized_sql,
                "sanitizedFileData": full_sanitized_sql,
                "original_text": original_text,
                "sanitizedFilePath": sql_dest,
                "entities": result.get("entities", []),
                "entity_count": len(result.get("entities", [])),
                "threat_level": result.get("threat_report", {})
                    .get("threat_assessment", {})
                    .get("threat_level", "LOW"),
                "risk_score": result.get("threat_report", {})
                    .get("threat_assessment", {})
                    .get("risk_score", 0),
                "entity_breakdown": result.get("threat_report", {})
                    .get("entity_breakdown", {}),
                "recommended_actions": result.get("threat_report", {})
                    .get("recommended_actions", []),
            }
            _update_firestore_completed(doc_id, response)
            with _scan_results_lock:
                _scan_results[doc_id] = {"status": "completed", **response}
            print(f"[SCAN] Completed (SQL): {file_name}, threat={response['threat_level']}")
            return

        # ---- XLSX file handling (cell-level sanitization) ----
        if ext == ".xlsx":
            _check_timeout("pre-xlsx")
            handler_result = process_file(tmp_path, SANITIZED_DIR, process_text_with_presidio)
            _check_timeout("xlsx-sanitize")
            sanitized_path = handler_result["output_path"]
            # Rename to include doc_id for uniqueness
            if sanitized_path and os.path.exists(sanitized_path):
                final_name = f"{doc_id}_sanitized.xlsx"
                final_path = os.path.join(SANITIZED_DIR, final_name)
                try:
                    os.replace(sanitized_path, final_path)
                    sanitized_path = final_path
                except OSError:
                    pass

            # Text previews from the handler (capped at 3000 chars for Firestore)
            orig_text = handler_result.get("original_text", "")
            san_text = handler_result.get("sanitized_text", "")

            # Lightweight analysis on original text for entities/threat
            from analyzer_engine import analyze_text as _xlsx_analyze
            from context_rules import apply_context_rules as _xlsx_ctx
            from threat_intel import generate_threat_report as _xlsx_threat
            analysis_text = orig_text[:50000]
            results = _xlsx_analyze(p.analyzer, analysis_text)
            results = _xlsx_ctx(analysis_text, results)
            threat_report = _xlsx_threat(file_name, results, len(orig_text))
            _check_timeout("xlsx-analysis")

            response = {
                "masked_text": san_text[:3000],
                "sanitizedFileData": san_text[:3000],
                "original_text": orig_text,
                "sanitizedFilePath": sanitized_path or "",
                "entities": [
                    {"type": r.entity_type, "confidence": r.score,
                     "position": f"{r.start}-{r.end}"}
                    for r in results
                ][:50],
                "entity_count": len(results),
                "threat_level": threat_report.get("threat_assessment", {})
                    .get("threat_level", "LOW"),
                "risk_score": threat_report.get("threat_assessment", {})
                    .get("risk_score", 0),
                "entity_breakdown": threat_report.get("entity_breakdown", {}),
                "recommended_actions": threat_report.get("recommended_actions", []),
            }
            _update_firestore_completed(doc_id, response)
            with _scan_results_lock:
                _scan_results[doc_id] = {"status": "completed", **response}
            print(f"[SCAN] Completed (XLSX): {file_name}, threat={response['threat_level']}")
            return

        # ---- PDF file handling (redacted PDF + text preview) ----
        if ext == '.pdf':
            _check_timeout("pre-pdf")
            handler_result = process_file(tmp_path, SANITIZED_DIR, process_text_with_presidio)
            _check_timeout("pdf-sanitize")
            sanitized_path = handler_result["output_path"]
            if sanitized_path and os.path.exists(sanitized_path):
                final_name = f"{doc_id}_sanitized.pdf"
                final_path = os.path.join(SANITIZED_DIR, final_name)
                try:
                    os.replace(sanitized_path, final_path)
                    sanitized_path = final_path
                except OSError:
                    pass

            orig_text = handler_result.get("original_text", "")
            san_text = handler_result.get("sanitized_text", "")

            from analyzer_engine import analyze_text as _pdf_analyze
            from context_rules import apply_context_rules as _pdf_ctx
            from threat_intel import generate_threat_report as _pdf_threat
            analysis_text = orig_text[:50000]
            results = _pdf_analyze(p.analyzer, analysis_text)
            results = _pdf_ctx(analysis_text, results)
            threat_report = _pdf_threat(file_name, results, len(orig_text))
            _check_timeout("pdf-analysis")

            response = {
                "masked_text": san_text[:3000],
                "sanitizedFileData": san_text[:3000],
                "original_text": orig_text,
                "sanitizedFilePath": sanitized_path or "",
                "entities": [
                    {"type": r.entity_type, "confidence": r.score,
                     "position": f"{r.start}-{r.end}"}
                    for r in results
                ][:50],
                "entity_count": len(results),
                "threat_level": threat_report.get("threat_assessment", {})
                    .get("threat_level", "LOW"),
                "risk_score": threat_report.get("threat_assessment", {})
                    .get("risk_score", 0),
                "entity_breakdown": threat_report.get("entity_breakdown", {}),
                "recommended_actions": threat_report.get("recommended_actions", []),
            }
            _update_firestore_completed(doc_id, response)
            with _scan_results_lock:
                _scan_results[doc_id] = {"status": "completed", **response}
            print(f"[SCAN] Completed (PDF): {file_name}, threat={response['threat_level']}")
            return

        # ---- Image file handling (visual redaction + fast analysis) ----
        if ext in (".png", ".jpg", ".jpeg"):
            _check_timeout("pre-image")

            # Resize large images for faster processing
            try:
                from PIL import Image as PILImage
                pil_img = PILImage.open(tmp_path)
                max_dim = 2000
                if max(pil_img.size) > max_dim:
                    ratio = max_dim / max(pil_img.size)
                    new_size = (int(pil_img.size[0] * ratio), int(pil_img.size[1] * ratio))
                    pil_img = pil_img.resize(new_size, PILImage.LANCZOS)
                    pil_img.save(tmp_path)
                    print(f"[SCAN] Image resized to {new_size} for faster processing")
                else:
                    pil_img.close()
            except Exception as resize_err:
                print(f"[SCAN] Image resize skipped: {resize_err}")

            # Visual redaction with presidio-image-redactor
            sanitized_path = None
            try:
                from PIL import Image as PILImage
                from presidio_image_redactor import ImageRedactorEngine
                img_engine = ImageRedactorEngine()
                pil_img = PILImage.open(tmp_path)
                redacted_img = img_engine.redact(pil_img, fill=(0, 0, 0))
                img_out_name = f"{doc_id}_sanitized{ext}"
                sanitized_path = os.path.join(SANITIZED_DIR, img_out_name)
                redacted_img.save(sanitized_path)
                print(f"[SCAN] Image redacted: {sanitized_path}")
            except ImportError:
                print("[SCAN] presidio-image-redactor not installed — skipping image redaction")
            except Exception as img_err:
                print(f"[SCAN] Image redaction error: {img_err}")
            _check_timeout("image-redact")

            # OCR text extraction (once only)
            original_text = ""
            try:
                original_text = ingest_file(tmp_path)
            except Exception:
                pass

            # Lightweight Presidio analysis on OCR text
            sanitized_text = process_text_with_presidio(original_text) if original_text.strip() else ""
            from analyzer_engine import analyze_text as _img_analyze
            from context_rules import apply_context_rules as _img_ctx
            from threat_intel import generate_threat_report as _img_threat
            analysis_text = original_text[:50000]
            results = _img_analyze(p.analyzer, analysis_text) if analysis_text.strip() else []
            results = _img_ctx(analysis_text, results) if analysis_text.strip() else []
            threat_report = _img_threat(file_name, results, len(original_text))
            _check_timeout("image-analysis")

            response = {
                "masked_text": sanitized_text[:3000],
                "sanitizedFileData": sanitized_text[:3000],
                "original_text": original_text,
                "sanitizedFilePath": sanitized_path or "",
                "entities": [
                    {"type": r.entity_type, "confidence": r.score,
                     "position": f"{r.start}-{r.end}"}
                    for r in results
                ][:50],
                "entity_count": len(results),
                "threat_level": threat_report.get("threat_assessment", {})
                    .get("threat_level", "LOW"),
                "risk_score": threat_report.get("threat_assessment", {})
                    .get("risk_score", 0),
                "entity_breakdown": threat_report.get("entity_breakdown", {}),
                "recommended_actions": threat_report.get("recommended_actions", []),
            }
            _update_firestore_completed(doc_id, response)
            with _scan_results_lock:
                _scan_results[doc_id] = {"status": "completed", **response}
            print(f"[SCAN] Completed (Image): {file_name}, threat={response['threat_level']}")
            return

        # ---- Produce sanitized file via file_handlers (DOCX, TXT, CSV) ----
        sanitized_path = None
        try:
            if ext in HANDLERS:
                handler_result = process_file(tmp_path, SANITIZED_DIR, process_text_with_presidio)
                sanitized_path = handler_result["output_path"]
                # Rename to include doc_id for uniqueness
                if sanitized_path and os.path.exists(sanitized_path):
                    final_name = f"{doc_id}_sanitized{ext}"
                    final_path = os.path.join(SANITIZED_DIR, final_name)
                    try:
                        os.replace(sanitized_path, final_path)
                        sanitized_path = final_path
                    except OSError:
                        pass
                print(f"[SCAN] Sanitized file written: {sanitized_path}")
        except Exception as handler_err:
            print(f"[SCAN] file_handlers error for {file_name}: {handler_err}")
            traceback.print_exc()

        _check_timeout("pre-analysis")

        # Extract original text for non-text files (DOCX, etc.)
        if not original_text:
            try:
                original_text = ingest_file(tmp_path)
            except Exception:
                pass

        # ---- Full pipeline analysis ----
        result = p.process_document(tmp_path, user="admin")
        _check_timeout("analysis")

        # Build sanitizedFileData (plain masked text string)
        sanitized_file_data = result.get("masked_text", "")

        # Capture original text for storage
        if not original_text:
            original_text = result.get("original_text", "") or result.get("raw_text", "")

        response = {
            "masked_text": result.get("masked_text", ""),
            "sanitizedFileData": sanitized_file_data,
            "original_text": original_text,
            "sanitizedFilePath": sanitized_path or "",
            "entities": result.get("entities", []),
            "entity_count": len(result.get("entities", [])),
            "threat_level": result.get("threat_report", {})
                .get("threat_assessment", {})
                .get("threat_level", "LOW"),
            "risk_score": result.get("threat_report", {})
                .get("threat_assessment", {})
                .get("risk_score", 0),
            "entity_breakdown": result.get("threat_report", {})
                .get("entity_breakdown", {}),
            "recommended_actions": result.get("threat_report", {})
                .get("recommended_actions", []),
        }
        _update_firestore_completed(doc_id, response)
        with _scan_results_lock:
            _scan_results[doc_id] = {"status": "completed", **response}
        print(f"[SCAN] Completed: {file_name}, threat={response['threat_level']}")

    except Exception as e:
        print(f"[SCAN] Error processing {file_name}: {e}")
        traceback.print_exc()
        _update_firestore_error(doc_id, str(e))
        with _scan_results_lock:
            _scan_results[doc_id] = {"status": "error", "scanError": str(e)}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---- Upload & Download Routes ----

def process_text_with_presidio(raw_text: str) -> str:
    """
    Lightweight wrapper for file_handlers: analyze + anonymize only.
    Skips dual-state encryption, audit logging, and threat reports
    to keep cell-by-cell processing fast.
    """
    from analyzer_engine import analyze_text, anonymize_text
    from context_rules import apply_context_rules
    p = get_pipeline()
    results = analyze_text(p.analyzer, raw_text)
    results = apply_context_rules(raw_text, results)
    if not results:
        return raw_text
    return anonymize_text(p.anonymizer, raw_text, results)


@app.route("/upload", methods=["POST", "OPTIONS"])
def upload_file():
    """
    Receive a file, route it to the correct handler, save the
    sanitized output, and update the database.

    Accepts:
      - multipart/form-data with field "file"
      - optional field "user" (email string)

    Returns JSON with doc_id, scan_status, pii_count, and download URL.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    if "file" not in request.files:
        return jsonify({"error": "No file provided", "success": False}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename", "success": False}), 400

    user = request.form.get("user", "web_user")
    filename = uploaded.filename
    ext = os.path.splitext(filename)[1].lower()

    allowed_extensions = set(HANDLERS.keys()) | {".sql", ".png", ".jpg", ".jpeg"}
    if ext not in allowed_extensions:
        return jsonify({"error": f"Unsupported file type: {ext}", "success": False}), 400

    # Save uploaded file to a temp location
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix="upload_") as tmp:
        uploaded.save(tmp)
        tmp_path = tmp.name

    # Compute file hash for integrity
    with open(tmp_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    file_size = os.path.getsize(tmp_path)

    # Insert initial DB record
    db = get_db()
    cursor = db.execute(
        "INSERT INTO documents (filename, file_type, file_size_bytes, "
        "file_hash_sha256, uploaded_by, scan_status) VALUES (?, ?, ?, ?, ?, ?)",
        (filename, ext.lstrip("."), file_size, file_hash, user, "processing"),
    )
    doc_id = cursor.lastrowid
    db.commit()

    try:
        if ext == ".sql":
            # SQL files use the existing pipeline's SQL handler
            p = get_pipeline()
            result = p.process_document(tmp_path, user)
            sanitized_path = result.get("sanitized_sql_path", "")
            pii_count = len(result.get("entities", []))
            threat_level = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("threat_level", "LOW")
            risk_score = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("risk_score", 0)

            # Copy sanitized SQL into sanitized_files directory
            if sanitized_path and os.path.exists(sanitized_path):
                dest = os.path.join(SANITIZED_DIR, f"{doc_id}_sanitized.sql")
                import shutil
                shutil.copy2(sanitized_path, dest)
                sanitized_path = dest

        elif ext in (".png", ".jpg", ".jpeg"):
            # Image files go through OCR → text pipeline, result is text-only
            p = get_pipeline()
            result = p.process_document(tmp_path, user)
            pii_count = len(result.get("entities", []))
            threat_level = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("threat_level", "LOW")
            risk_score = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("risk_score", 0)

            # Save masked text as a .txt file
            sanitized_path = os.path.join(SANITIZED_DIR, f"{doc_id}_sanitized.txt")
            with open(sanitized_path, "w", encoding="utf-8") as f:
                f.write(result.get("masked_text", ""))

        else:
            # Route through file_handlers factory (.txt, .csv, .docx, .pdf, .xlsx)
            handler_result = process_file(tmp_path, SANITIZED_DIR, process_text_with_presidio)

            pii_count = handler_result["pii_count"]
            sanitized_path = handler_result["output_path"]

            # Rename to include doc_id for uniqueness
            base_ext = os.path.splitext(sanitized_path)[1]
            final_path = os.path.join(SANITIZED_DIR, f"{doc_id}_sanitized{base_ext}")
            os.replace(sanitized_path, final_path)
            sanitized_path = final_path

            # Get threat info from a quick pipeline scan
            p = get_pipeline()
            result = p.process_document(tmp_path, user)
            threat_level = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("threat_level", "LOW")
            risk_score = result.get("threat_report", {}).get(
                "threat_assessment", {}
            ).get("risk_score", 0)

        # Update DB — Success
        db.execute(
            "UPDATE documents SET scan_status = ?, sanitized_file_path = ?, "
            "pii_count = ?, threat_level = ?, risk_score = ? WHERE doc_id = ?",
            ("Success", sanitized_path, pii_count, threat_level, risk_score, doc_id),
        )
        db.commit()

        response = {
            "success": True,
            "doc_id": doc_id,
            "filename": filename,
            "scan_status": "Success",
            "pii_count": pii_count,
            "threat_level": threat_level,
            "risk_score": risk_score,
            "download_url": f"/download/{doc_id}",
        }
        return jsonify(response)

    except Exception as e:
        traceback.print_exc()
        # Update DB — Failed
        db.execute(
            "UPDATE documents SET scan_status = ?, error_message = ? WHERE doc_id = ?",
            ("Failed", str(e), doc_id),
        )
        db.commit()
        return jsonify({
            "success": False,
            "doc_id": doc_id,
            "scan_status": "Failed",
            "error": str(e),
        }), 500

    finally:
        db.close()
        # Clean up temp upload
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@app.route("/download/<int:file_id>")
def download_file(file_id):
    """
    Fetch the sanitized file path from the database and return
    it as a downloadable attachment.
    """
    db = get_db()
    try:
        row = db.execute(
            "SELECT filename, sanitized_file_path, scan_status "
            "FROM documents WHERE doc_id = ?",
            (file_id,),
        ).fetchone()

        if row is None:
            return jsonify({"error": "File not found", "success": False}), 404

        if row["scan_status"] != "Success":
            return jsonify({
                "error": f"File scan status is '{row['scan_status']}' — not available for download",
                "success": False,
            }), 400

        sanitized_path = row["sanitized_file_path"]
        if not sanitized_path or not os.path.exists(sanitized_path):
            return jsonify({"error": "Sanitized file missing from server", "success": False}), 404

        # Build a user-friendly download name
        original_name = row["filename"]
        name, ext = os.path.splitext(original_name)
        download_name = f"{name}_sanitized{ext}"

        return send_file(
            sanitized_path,
            as_attachment=True,
            download_name=download_name,
        )
    finally:
        db.close()


if __name__ == "__main__":
    # Initialize Firebase Admin SDK (for Firestore writes)
    init_firebase()
    # Initialize database tables on startup
    init_db()

    print("\n" + "=" * 60)
    print("  PII SHIELD — Web Testing Interface")
    print("  Open http://localhost:5000 in your browser")
    print("  API available at http://localhost:5000/api/scan")
    print("  Upload:   POST /upload  (multipart/form-data)")
    print("  Download: GET  /download/<file_id>")
    print("=" * 60 + "\n")
    
    # Pre-load the pipeline on startup
    get_pipeline()
    
    app.run(debug=False, host="0.0.0.0", port=5000)
