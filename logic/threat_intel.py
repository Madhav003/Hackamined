"""
=============================================================================
PII Shield — Threat Intelligence Module
=============================================================================
Calculates a Document Threat Level based on:
  • Quantity of PII entities detected
  • Type of each entity (weighted by sensitivity)
  • Presidio confidence score for each detection

Threat Levels:
  LOW      — Score < 10  (e.g., a few names/dates)
  MEDIUM   — 10 ≤ Score < 30  (emails, phone numbers)
  HIGH     — 30 ≤ Score < 60  (financial data, government IDs)
  CRITICAL — Score ≥ 60  (multiple high-sensitivity records)

The scoring algorithm is designed to flag documents that pose
the highest risk for identity theft, financial fraud, or
regulatory violations (GDPR, PCI-DSS, India DPDP Act).
=============================================================================
"""

import logging
from datetime import datetime, timezone
from typing import List

from presidio_analyzer import RecognizerResult

from config import ENTITY_RISK_WEIGHTS, THREAT_THRESHOLDS

logger = logging.getLogger(__name__)


def calculate_threat_score(results: List[RecognizerResult]) -> float:
    """
    Calculate a cumulative risk score for a set of PII detections.
    
    Formula per entity:
        entity_score = WEIGHT[entity_type] × confidence_score
    
    Total score = sum of all entity_scores
    
    This design means:
      • A high-confidence Aadhaar detection adds 10 × 0.95 = 9.5
      • A low-confidence name detection adds 2 × 0.3 = 0.6
      • Multiple entities compound the score, reflecting increased risk
    """
    total_score = 0.0

    for result in results:
        weight = ENTITY_RISK_WEIGHTS.get(result.entity_type, 1)
        entity_score = weight * result.score
        total_score += entity_score

    return round(total_score, 2)


def determine_threat_level(score: float) -> str:
    """Map a numeric risk score to a threat level string."""
    if score < THREAT_THRESHOLDS["LOW"]:
        return "LOW"
    elif score < THREAT_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    elif score < THREAT_THRESHOLDS["HIGH"]:
        return "HIGH"
    else:
        return "CRITICAL"


def generate_threat_report(
    filename: str,
    results: List[RecognizerResult],
    text_length: int = 0,
) -> dict:
    """
    Generate a comprehensive Threat Intelligence Report.
    
    Returns a structured dict suitable for JSON serialization,
    database storage, or Admin dashboard display.
    
    Report Contents:
      • Document metadata (filename, scan time, text length)
      • Overall threat level and numeric score
      • Per-entity-type breakdown (count, avg confidence, max confidence)
      • Top high-confidence detections
      • Recommended actions based on threat level
    """
    score = calculate_threat_score(results)
    threat_level = determine_threat_level(score)

    # ---- Entity breakdown by type ----
    entity_breakdown = {}
    for result in results:
        etype = result.entity_type
        if etype not in entity_breakdown:
            entity_breakdown[etype] = {
                "count": 0,
                "total_confidence": 0.0,
                "max_confidence": 0.0,
                "risk_weight": ENTITY_RISK_WEIGHTS.get(etype, 1),
            }
        entity_breakdown[etype]["count"] += 1
        entity_breakdown[etype]["total_confidence"] += result.score
        entity_breakdown[etype]["max_confidence"] = max(
            entity_breakdown[etype]["max_confidence"], result.score
        )

    # Calculate average confidence per type
    for etype, info in entity_breakdown.items():
        info["avg_confidence"] = round(info["total_confidence"] / info["count"], 3)
        del info["total_confidence"]  # Clean up intermediate field

    # ---- Top detections (highest individual risk) ----
    top_detections = sorted(
        [
            {
                "entity_type": r.entity_type,
                "confidence": r.score,
                "risk_contribution": round(
                    ENTITY_RISK_WEIGHTS.get(r.entity_type, 1) * r.score, 2
                ),
                "position": f"chars {r.start}-{r.end}",
            }
            for r in results
        ],
        key=lambda x: x["risk_contribution"],
        reverse=True,
    )[:10]  # Top 10

    # ---- Recommended actions ----
    actions = _get_recommended_actions(threat_level)

    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner_version": "PII Shield v1.0",
            "filename": filename,
            "text_length": text_length,
        },
        "threat_assessment": {
            "threat_level": threat_level,
            "risk_score": score,
            "total_entities_detected": len(results),
            "unique_entity_types": len(entity_breakdown),
        },
        "entity_breakdown": entity_breakdown,
        "top_detections": top_detections,
        "recommended_actions": actions,
    }

    logger.info("Threat report for '%s': %s (score=%.2f, entities=%d)",
                filename, threat_level, score, len(results))
    return report


def _get_recommended_actions(threat_level: str) -> list:
    """Return recommended remediation actions based on threat level."""
    actions = {
        "LOW": [
            "Standard data handling procedures apply",
            "Log access for audit compliance",
            "No immediate escalation required",
        ],
        "MEDIUM": [
            "Apply data masking before sharing with non-privileged users",
            "Encrypt data at rest using AES-256",
            "Review access logs within 24 hours",
            "Notify data protection officer if data leaves the organization",
        ],
        "HIGH": [
            "IMMEDIATE: Restrict access to authorized personnel only",
            "Apply full encryption (AES-256 + FPE for numeric fields)",
            "Notify Data Protection Officer within 4 hours",
            "Enable enhanced audit logging for all access",
            "Consider data minimization — remove unnecessary PII fields",
        ],
        "CRITICAL": [
            "URGENT: Quarantine document — restrict all access immediately",
            "Escalate to CISO / Data Protection Officer within 1 hour",
            "Apply maximum encryption and access controls",
            "Initiate incident response procedure if data may have been exposed",
            "Prepare breach notification if applicable (GDPR 72-hour rule)",
            "Conduct forensic analysis of document origin and access history",
        ],
    }
    return actions.get(threat_level, actions["LOW"])


def format_threat_report_text(report: dict) -> str:
    """Format a threat report as a human-readable text string."""
    lines = [
        "=" * 70,
        "             PII SHIELD — THREAT INTELLIGENCE REPORT",
        "=" * 70,
        "",
        f"  Document:      {report['report_metadata']['filename']}",
        f"  Scanned:       {report['report_metadata']['generated_at']}",
        f"  Text Length:   {report['report_metadata']['text_length']} characters",
        "",
        "-" * 70,
        f"  THREAT LEVEL:  *** {report['threat_assessment']['threat_level']} ***",
        f"  Risk Score:    {report['threat_assessment']['risk_score']}",
        f"  Total PII:     {report['threat_assessment']['total_entities_detected']} entities",
        f"  Entity Types:  {report['threat_assessment']['unique_entity_types']}",
        "-" * 70,
        "",
        "  ENTITY BREAKDOWN:",
    ]

    for etype, info in report["entity_breakdown"].items():
        lines.append(
            f"    • {etype:<20s}  Count: {info['count']:<4d}  "
            f"Avg Conf: {info['avg_confidence']:.3f}  "
            f"Weight: {info['risk_weight']}"
        )

    lines.extend([
        "",
        "  RECOMMENDED ACTIONS:",
    ])
    for i, action in enumerate(report["recommended_actions"], 1):
        lines.append(f"    {i}. {action}")

    lines.extend(["", "=" * 70])
    return "\n".join(lines)
