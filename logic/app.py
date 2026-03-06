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
import traceback

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

from pipeline import PIIShieldPipeline
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
CORS(app)  # Allow all origins during development
pipeline = None  # Lazy initialization
table_processor = None  # Lazy initialization

SANITIZED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sanitized_files")
os.makedirs(SANITIZED_DIR, exist_ok=True)

# ---- Firebase Admin SDK Setup ----
_firestore_client = None


def init_firebase():
    """Initialize Firebase Admin SDK for server-side Firestore writes."""
    global _firestore_client
    if not _FIREBASE_AVAILABLE:
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
            print("Firebase Admin SDK initialized — Firestore writes enabled.")
        except Exception as e:
            print(f"WARNING: Firebase Admin SDK init failed: {e}")
    else:
        print(f"WARNING: Service account key not found at: {service_account_path}")
        print("  Place serviceAccountKey.json in logic/ or set FIREBASE_SERVICE_ACCOUNT env var.")
        print("  Firestore writes from Flask DISABLED (frontend fallback will be used).")


def _update_firestore_completed(doc_id, response):
    """Write scan results to the Firestore document. Returns True on success."""
    if not _firestore_client or not doc_id:
        return False
    try:
        update_payload = {
            "status": "completed",
            "scanResults": {
                "threat_level": response.get("threat_level", "LOW"),
                "risk_score": response.get("risk_score", 0),
                "entity_count": response.get("entity_count", 0),
                "entity_breakdown": response.get("entity_breakdown", {}),
                "entities": (response.get("entities") or [])[:50],
                "masked_text": (response.get("masked_text") or "")[:5000],
                "recommended_actions": response.get("recommended_actions", []),
                "scannedAt": admin_firestore.SERVER_TIMESTAMP,
            },
        }
        if response.get("sanitizedFileData"):
            update_payload["sanitizedFileData"] = response["sanitizedFileData"]
        _firestore_client.collection("files").document(doc_id).update(update_payload)
        return True
    except Exception as fs_err:
        print(f"[SCAN] Firestore update failed: {fs_err}")
        return False


def _update_firestore_error(doc_id, error_msg):
    """Mark the Firestore document as errored."""
    if not _firestore_client or not doc_id:
        return
    try:
        _firestore_client.collection("files").document(doc_id).update({
            "status": "error",
            "scanError": str(error_msg),
        })
    except Exception:
        pass


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
    Scan file content for PII — used by the React frontend.

    Expects JSON: {
        "fileData": "data:<mime>;base64,...",   // base64-encoded file
        "fileName": "report.sql",
        "user": "admin@example.com",
        "docId": "<Firestore document ID>"      // so Flask can update Firestore
    }
    Returns JSON with threat_level, risk_score, entities, masked_text, etc.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json()
    file_data = data.get("fileData", "")
    file_name = data.get("fileName", "unknown.txt")
    user = data.get("user", "web_user")
    doc_id = data.get("docId", "")

    if not file_data:
        return jsonify({"error": "No file data provided", "success": False}), 400

    # Validate file extension upfront so unsupported types fail fast
    ext_check = os.path.splitext(file_name)[1].lower()
    supported_extensions = {".txt", ".csv", ".pdf", ".docx", ".xlsx", ".sql", ".json", ".png", ".jpg", ".jpeg"}
    if ext_check not in supported_extensions:
        return jsonify({"error": f"Unsupported file type: {ext_check}", "success": False}), 400

    try:
        # Decode base64 data
        if "," in file_data:
            mime_header = file_data.split(",", 1)[0]
            file_data = file_data.split(",", 1)[1]
        else:
            mime_header = ""
        raw_bytes = base64.b64decode(file_data)

        ext = os.path.splitext(file_name)[1].lower()

        # Write to a temp file for pipeline processing
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=ext, prefix="pii_scan_"
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        p = get_pipeline()
        sanitized_file_data = ""  # base64 data-URI of the sanitized file

        # For text-based files, also try the text-based route
        text_extensions = {".txt", ".csv", ".json", ".sql"}
        if ext in text_extensions:
            try:
                text_content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text_content = raw_bytes.decode("latin-1")

            # Check if it's a table
            if is_ascii_table(text_content):
                sanitized = process_ascii_table(
                    text_content,
                    twelve_digit_mode="ignore",
                    name_mode="redact",
                    min_score=0.3,
                )
                san_b64 = base64.b64encode(sanitized.encode("utf-8")).decode("ascii")
                sanitized_file_data = (mime_header + "," + san_b64) if mime_header else ("data:text/plain;base64," + san_b64)
                response = {
                    "success": True,
                    "fileName": file_name,
                    "original_length": len(text_content),
                    "masked_text": sanitized,
                    "sanitizedFileData": sanitized_file_data,
                    "entities": [],
                    "entity_count": 0,
                    "threat_level": "LOW",
                    "risk_score": 0,
                    "entity_breakdown": {},
                    "recommended_actions": [
                        "Table processed cell-by-cell (alignment preserved)",
                        "Quasi-identifier column detection applied",
                    ],
                }
                response["firestoreUpdated"] = _update_firestore_completed(doc_id, response)
                return jsonify(response)

        # ---- Produce the sanitized file via file_handlers ----
        sanitized_path = None
        try:
            if ext in HANDLERS:
                handler_result = process_file(tmp_path, SANITIZED_DIR, process_text_with_presidio)
                sanitized_path = handler_result["output_path"]
                print(f"[SCAN] Sanitized file written: {sanitized_path}")

            # Build a base64 data-URI from the sanitized file for the frontend
            if sanitized_path and os.path.exists(sanitized_path):
                with open(sanitized_path, "rb") as sf:
                    san_bytes = sf.read()
                san_b64 = base64.b64encode(san_bytes).decode("ascii")
                mime_map = {
                    ".txt": "text/plain", ".csv": "text/csv",
                    ".pdf": "application/pdf",
                    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                }
                mime_type = mime_map.get(ext, "application/octet-stream")
                sanitized_file_data = f"data:{mime_type};base64,{san_b64}"
        except Exception as handler_err:
            print(f"[SCAN] file_handlers error for {file_name}: {handler_err}")
            traceback.print_exc()
            # Non-fatal — we still return analysis results even if sanitized file fails

        # Process through the full pipeline for analysis/threat results
        result = p.process_document(tmp_path, user)

        # For text-based files without a handler, build sanitized data-URI from masked_text
        if not sanitized_file_data and result.get("masked_text"):
            masked = result["masked_text"]
            san_b64 = base64.b64encode(masked.encode("utf-8")).decode("ascii")
            sanitized_file_data = f"data:text/plain;base64,{san_b64}"

        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        response = {
            "success": True,
            "fileName": file_name,
            "original_length": result.get("original_length", 0),
            "masked_text": result.get("masked_text", ""),
            "sanitizedFileData": sanitized_file_data,
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
        response["firestoreUpdated"] = _update_firestore_completed(doc_id, response)
        return jsonify(response)

    except Exception as e:
        traceback.print_exc()
        _update_firestore_error(doc_id, e)
        return jsonify({"error": str(e), "success": False}), 500


# ---- Upload & Download Routes ----

def process_text_with_presidio(raw_text: str) -> str:
    """
    Wrapper around the existing pipeline for use by file_handlers.
    Accepts raw text, returns sanitized text with PII masked.
    """
    p = get_pipeline()
    result = p.process_text(raw_text, "handler_input", "system")
    return result["masked_text"]


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
    
    app.run(debug=True, host="0.0.0.0", port=5000)
