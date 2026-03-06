-- =============================================================================
-- PII Shield — Database Schema with Role-Based Access Control (RBAC)
-- =============================================================================
-- This schema demonstrates how to securely store PII data with:
--   • Encrypted raw data (AES-256-GCM ciphertext + nonce + auth tag)
--   • Masked views for non-privileged access
--   • Role-based access control via SQL views and GRANT statements
--   • Audit trail storage for tamper-evident logging
--
-- DESIGN PRINCIPLES:
--   1. Separation of Concerns: Raw PII is NEVER stored in plaintext
--   2. Defense in Depth: Even if DB is compromised, data is encrypted
--   3. Least Privilege: Users see only what their role permits
--   4. Auditability: Every action is logged with hash-chain integrity
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. USERS & ROLES TABLE
-- ---------------------------------------------------------------------------
-- Tracks all users with their assigned access roles.
-- Roles: 'admin', 'analyst', 'viewer'

CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username        VARCHAR(100) NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,         -- bcrypt/argon2 hash
    role            VARCHAR(20)  NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login      TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- 2. DOCUMENTS TABLE
-- ---------------------------------------------------------------------------
-- Metadata for uploaded files. Does NOT contain any PII directly.

CREATE TABLE IF NOT EXISTS documents (
    doc_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename        VARCHAR(255) NOT NULL,
    file_type       VARCHAR(20)  NOT NULL,          -- pdf, docx, sql, png, txt
    file_size_bytes INTEGER,
    file_hash_sha256 VARCHAR(64) NOT NULL,          -- Integrity verification
    uploaded_by     INTEGER      NOT NULL REFERENCES users(user_id),
    uploaded_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    threat_level    VARCHAR(20),                     -- LOW, MEDIUM, HIGH, CRITICAL
    risk_score      REAL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'processing'
                    CHECK (status IN ('processing', 'completed', 'failed', 'quarantined'))
);

-- ---------------------------------------------------------------------------
-- 3. PII RECORDS TABLE
-- ---------------------------------------------------------------------------
-- Stores detected PII entities with BOTH encrypted raw data and masked view.
--
-- SECURITY MODEL:
--   • encrypted_value:  AES-256-GCM ciphertext (base64)
--   • encryption_nonce: Required for AES-GCM decryption (base64)
--   • encryption_tag:   Authentication tag — detects any tampering (base64)
--   • masked_value:     Human-readable redaction (e.g., "j***@email.com")
--   • fpe_value:        Format-Preserving Encrypted value (same format as original)
--
-- Only admins can access encrypted_value/nonce/tag.
-- Analysts see only masked_value.
-- Viewers see only document metadata (no PII access).

CREATE TABLE IF NOT EXISTS pii_records (
    record_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id          INTEGER      NOT NULL REFERENCES documents(doc_id),
    entity_type     VARCHAR(50)  NOT NULL,          -- e.g., IN_AADHAAR, CREDIT_CARD
    char_start      INTEGER      NOT NULL,          -- Position in original text
    char_end        INTEGER      NOT NULL,
    confidence      REAL         NOT NULL,           -- Presidio confidence score

    -- Encrypted raw PII (AES-256-GCM) — Admin access only
    encrypted_value VARCHAR(500),
    encryption_nonce VARCHAR(50),
    encryption_tag  VARCHAR(50),

    -- Format-Preserving Encrypted value — same format as original
    -- Used for numeric fields (credit cards, phones, Aadhaar)
    fpe_value       VARCHAR(100),
    encryption_method VARCHAR(20) NOT NULL           -- 'AES-256-GCM' or 'FF3-1-FPE'
                    CHECK (encryption_method IN ('AES-256-GCM', 'FF3-1-FPE')),

    -- Masked value — Analyst access
    masked_value    VARCHAR(500) NOT NULL,

    detected_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- 4. THREAT REPORTS TABLE
-- ---------------------------------------------------------------------------
-- Stores the full threat intelligence report as JSON for each document.

CREATE TABLE IF NOT EXISTS threat_reports (
    report_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id          INTEGER      NOT NULL REFERENCES documents(doc_id),
    report_json     TEXT         NOT NULL,           -- Full JSON report
    threat_level    VARCHAR(20)  NOT NULL,
    risk_score      REAL         NOT NULL,
    total_entities  INTEGER      NOT NULL,
    generated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- 5. AUDIT LOGS TABLE
-- ---------------------------------------------------------------------------
-- Stores the tamper-evident hash-chain audit trail.
-- Each entry's hash depends on the previous entry's hash (blockchain-like).

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       VARCHAR(50)  NOT NULL,
    user_identity   VARCHAR(255) NOT NULL,
    action          VARCHAR(50)  NOT NULL,
    details         TEXT,
    prev_hash       VARCHAR(64)  NOT NULL,           -- SHA-256 of previous entry
    entry_hash      VARCHAR(64)  NOT NULL UNIQUE      -- SHA-256 of this entry
);

-- ---------------------------------------------------------------------------
-- 6. RBAC VIEWS — Enforcing Least Privilege Access
-- ---------------------------------------------------------------------------

-- ADMIN VIEW: Full access to encrypted data + masked data + metadata
-- Only admins with decryption keys can recover original PII
CREATE VIEW IF NOT EXISTS admin_pii_view AS
SELECT
    d.doc_id,
    d.filename,
    d.threat_level,
    p.entity_type,
    p.confidence,
    p.masked_value,
    p.encrypted_value,
    p.encryption_nonce,
    p.encryption_tag,
    p.fpe_value,
    p.encryption_method,
    p.char_start,
    p.char_end
FROM documents d
JOIN pii_records p ON d.doc_id = p.doc_id;

-- ANALYST VIEW: Masked data only — no access to encrypted values
-- Analysts can see WHAT was detected but not the raw PII
CREATE VIEW IF NOT EXISTS analyst_pii_view AS
SELECT
    d.doc_id,
    d.filename,
    d.threat_level,
    p.entity_type,
    p.confidence,
    p.masked_value,
    p.char_start,
    p.char_end
FROM documents d
JOIN pii_records p ON d.doc_id = p.doc_id;

-- VIEWER VIEW: Document metadata only — zero PII access
-- Viewers can see that a document was scanned and its threat level
CREATE VIEW IF NOT EXISTS viewer_document_view AS
SELECT
    doc_id,
    filename,
    file_type,
    uploaded_at,
    threat_level,
    risk_score,
    status
FROM documents;

-- ---------------------------------------------------------------------------
-- 7. INDEXES for Performance
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_pii_doc_id ON pii_records(doc_id);
CREATE INDEX IF NOT EXISTS idx_pii_entity_type ON pii_records(entity_type);
CREATE INDEX IF NOT EXISTS idx_docs_uploaded_by ON documents(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_docs_threat_level ON documents(threat_level);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_identity);

-- ---------------------------------------------------------------------------
-- 8. GRANT STATEMENTS (PostgreSQL syntax — conceptual for SQLite demo)
-- ---------------------------------------------------------------------------
-- In a production PostgreSQL database, these grants enforce RBAC:
--
-- GRANT SELECT ON admin_pii_view TO admin_role;
-- GRANT SELECT ON analyst_pii_view TO analyst_role;
-- GRANT SELECT ON viewer_document_view TO viewer_role;
--
-- REVOKE ALL ON pii_records FROM analyst_role, viewer_role;
-- REVOKE ALL ON audit_logs FROM viewer_role;
--
-- Admin role: Full CRUD on all tables
-- Analyst role: SELECT on analyst_pii_view + threat_reports only
-- Viewer role: SELECT on viewer_document_view only
