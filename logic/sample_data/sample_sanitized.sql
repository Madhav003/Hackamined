-- =============================================================================
-- Sample SQL Dump for PII Shield Testing
-- =============================================================================
-- Contains CREATE TABLE + INSERT statements with PII in the data payloads.
-- The system should sanitize PII in INSERT values while preserving DDL.
-- =============================================================================

CREATE TABLE employees (
    emp_id      INTEGER PRIMARY KEY,
    first_name  VARCHAR(100) NOT NULL,
    last_name   VARCHAR(100) NOT NULL,
    email       VARCHAR(255),
    phone       VARCHAR(20),
    aadhaar     VARCHAR(14),
    pan         VARCHAR(10),
    address     TEXT,
    hire_date   DATE
);

CREATE INDEX idx_emp_email ON employees(email);

INSERT INTO employees (emp_id, first_name, last_name, email, phone, aadhaar, pan, address, hire_date) VALUES
(1, '[REDACTED_NAME]', '[REDACTED_NAME]', '******.kumar@techcorp.in', 'XXXXXX76543210', 'XXXXXXXX8 9018', '[REDACTED_PAN]', '42 MG Road, [REDACTED_LOCATION], [REDACTED_LOCATION]', '[REDACTED_DATE]'),
(2, '[REDACTED_NAME]', '[REDACTED_NAME]', '******sharma@gmail.com', 'XXXXXX65432109', 'XXXXXXXX9 0126', '[REDACTED_PAN]', '15 [REDACTED_NAME], [REDACTED_LOCATION], [REDACTED_LOCATION]', '[REDACTED_DATE]'),
(3, '[REDACTED_NAME]', '[REDACTED_NAME]', '******atel@enterprise.com', 'XXXXXX54321098', 'XXXXXXXX0 1233', '[REDACTED_PAN]', '78 [REDACTED_LOCATION], [REDACTED_LOCATION], [REDACTED_LOCATION]', '[REDACTED_DATE]');

CREATE TABLE customers (
    cust_id     INTEGER PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    email       VARCHAR(255),
    credit_card VARCHAR(20),
    phone       VARCHAR(20)
);

INSERT INTO customers (cust_id, name, email, credit_card, phone) VALUES
(101, '[REDACTED_NAME]', '******gupta@email.com', 'XXXXXXXXXXXX1111', 'XXXXXX88776655'),
(102, '[REDACTED_NAME]', '******.singh@corporate.in', 'XXXXXXXXXXXX0004', 'XXXXXX77665544');

ALTER TABLE employees ADD COLUMN department VARCHAR(50);
