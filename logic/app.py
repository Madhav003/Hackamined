"""
=============================================================================
PII Shield — Web Frontend for Testing
=============================================================================
A simple Flask web interface to test the PII Shield pipeline.

Run with: python app.py
Then open: http://localhost:5000
=============================================================================
"""

import json
import os
from flask import Flask, render_template, request, jsonify

from pipeline import PIIShieldPipeline
from table_processor import process_ascii_table, create_table_processor

app = Flask(__name__)
pipeline = None  # Lazy initialization
table_processor = None  # Lazy initialization


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


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  PII SHIELD — Web Testing Interface")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 60 + "\n")
    
    # Pre-load the pipeline on startup
    get_pipeline()
    
    app.run(debug=True, host="0.0.0.0", port=5000)
