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
import json
import os
import tempfile
from flask import Flask, render_template, request, jsonify

from pipeline import PIIShieldPipeline
from table_processor import process_ascii_table, create_table_processor

app = Flask(__name__)
pipeline = None  # Lazy initialization
table_processor = None  # Lazy initialization


# ---- CORS Support ----
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    # Allow requests from the frontend served via file:// or localhost
    allowed_origins = ["null"]  # file:// sends Origin: null
    if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        allowed_origins.append(origin)
    if origin in allowed_origins or origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        response.headers["Access-Control-Allow-Origin"] = origin if origin != "" else "null"
    else:
        response.headers["Access-Control-Allow-Origin"] = "null"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


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
        "user": "admin@example.com"
    }
    Returns JSON with threat_level, risk_score, entities, masked_text, etc.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json()
    file_data = data.get("fileData", "")
    file_name = data.get("fileName", "unknown.txt")
    user = data.get("user", "web_user")

    if not file_data:
        return jsonify({"error": "No file data provided", "success": False}), 400

    try:
        # Decode base64 data
        if "," in file_data:
            file_data = file_data.split(",", 1)[1]
        raw_bytes = base64.b64decode(file_data)

        ext = os.path.splitext(file_name)[1].lower()

        # Write to a temp file for pipeline processing
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=ext, prefix="pii_scan_"
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        p = get_pipeline()

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
                response = {
                    "success": True,
                    "fileName": file_name,
                    "original_length": len(text_content),
                    "masked_text": sanitized,
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
                return jsonify(response)

        # Process through the full pipeline
        result = p.process_document(tmp_path, user)

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
        return jsonify(response)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "success": False}), 500


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  PII SHIELD — Web Testing Interface")
    print("  Open http://localhost:5000 in your browser")
    print("  API available at http://localhost:5000/api/scan")
    print("=" * 60 + "\n")
    
    # Pre-load the pipeline on startup
    get_pipeline()
    
    app.run(debug=True, host="0.0.0.0", port=5000)
