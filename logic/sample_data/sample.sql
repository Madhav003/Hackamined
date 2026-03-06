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
(1, 'Rajesh', 'Kumar', 'rajesh.kumar@techcorp.in', '+91 9876543210', '2234 5678 9018', 'ABCPK1234F', '42 MG Road, Bengaluru, Karnataka', '2023-01-15'),
(2, 'Priya', 'Sharma', 'priya.sharma@gmail.com', '+91 8765432109', '3345 6789 0126', 'XYZPL5678G', '15 Anna Salai, Chennai, Tamil Nadu', '2022-06-20'),
(3, 'Amit', 'Patel', 'amit.patel@enterprise.com', '+91 7654321098', '4456 7890 1233', 'DEFPM9012H', '78 Park Street, Kolkata, West Bengal', '2023-03-10');

CREATE TABLE customers (
    cust_id     INTEGER PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    email       VARCHAR(255),
    credit_card VARCHAR(20),
    phone       VARCHAR(20)
);

INSERT INTO customers (cust_id, name, email, credit_card, phone) VALUES
(101, 'Sneha Gupta', 'sneha.gupta@email.com', '4111111111111111', '+91 9988776655'),
(102, 'Vikram Singh', 'vikram.singh@corporate.in', '5500000000000004', '+91 8877665544');

ALTER TABLE employees ADD COLUMN department VARCHAR(50);
