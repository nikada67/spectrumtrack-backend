-- SpectrumTrack — MySQL Schema
-- Run this once on your Railway MySQL instance
-- Usage: mysql -h HOST -u USER -pPASSWORD spectrumtrack < scripts/schema.sql

CREATE DATABASE IF NOT EXISTS spectrumtrack;
USE spectrumtrack;

-- ─── Organizations (schools / districts) ─────────────────────────────────────
CREATE TABLE organizations (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(255) NOT NULL,
  tier          ENUM('classroom','school','district') DEFAULT 'school',
  settings      JSON,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ─── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE users (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  organization_id INT NOT NULL,
  name            VARCHAR(255) NOT NULL,
  email           VARCHAR(255) UNIQUE NOT NULL,
  password_hash   VARCHAR(255) NOT NULL,
  role            ENUM('admin','bcba','teacher','aide','parent') NOT NULL,
  preferences     JSON,
  last_login      TIMESTAMP,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- ─── Students ─────────────────────────────────────────────────────────────────
CREATE TABLE students (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  organization_id INT NOT NULL,
  first_name      VARCHAR(100) NOT NULL,
  last_name       VARCHAR(100) NOT NULL,
  date_of_birth   DATE,
  iep_goals       JSON,
  behavior_plan   JSON,
  sensory_profile JSON,
  reinforcers     JSON,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- ─── Student ↔ User assignments (many-to-many) ───────────────────────────────
CREATE TABLE student_assignments (
  student_id INT NOT NULL,
  user_id    INT NOT NULL,
  PRIMARY KEY (student_id, user_id),
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE
);

-- ─── Behavior logs (ABC data) ─────────────────────────────────────────────────
CREATE TABLE behavior_logs (
  id                      INT AUTO_INCREMENT PRIMARY KEY,
  student_id              INT NOT NULL,
  recorded_by             INT NOT NULL,
  behavior_type           VARCHAR(100) NOT NULL,
  intensity               TINYINT CHECK (intensity BETWEEN 1 AND 5),
  start_time              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  end_time                TIMESTAMP NULL,
  antecedent              VARCHAR(255),
  consequence             VARCHAR(255),
  location                VARCHAR(100),
  activity                VARCHAR(100),
  intervention_used       VARCHAR(255),
  intervention_successful BOOLEAN,
  notes                   TEXT,
  synced_from_offline     BOOLEAN DEFAULT FALSE,
  created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id)  REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (recorded_by) REFERENCES users(id)
);

CREATE INDEX idx_logs_student_time ON behavior_logs (student_id, start_time DESC);
CREATE INDEX idx_logs_type         ON behavior_logs (behavior_type);
CREATE INDEX idx_logs_location     ON behavior_logs (location, activity);

-- ─── Intervention strategies library ─────────────────────────────────────────
CREATE TABLE interventions (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  organization_id INT NOT NULL,
  name            VARCHAR(255) NOT NULL,
  category        VARCHAR(100),
  description     TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- ─── Alert rules ──────────────────────────────────────────────────────────────
CREATE TABLE alert_rules (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  student_id     INT NOT NULL,
  created_by     INT NOT NULL,
  rule_condition JSON NOT NULL,
  rule_action    JSON NOT NULL,
  active         BOOLEAN DEFAULT TRUE,
  last_triggered TIMESTAMP NULL,
  FOREIGN KEY (student_id)  REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by)  REFERENCES users(id)
);

-- ─── Audit log (FERPA compliance) ────────────────────────────────────────────
CREATE TABLE audit_logs (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT,
  action      VARCHAR(100) NOT NULL,
  table_name  VARCHAR(100) NOT NULL,
  record_id   INT,
  ip_address  VARCHAR(45),
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ─── Refresh tokens (for JWT rotation) ───────────────────────────────────────
CREATE TABLE refresh_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  token_hash  VARCHAR(255) NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  revoked     BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ─── Seed: default org ────────────────────────────────────────────────────────
INSERT INTO organizations (name, tier) VALUES ('Demo School', 'school');

-- ─── Seed: admin user ─────────────────────────────────────────────────────────
-- IMPORTANT: Before running this file, generate a real bcrypt hash with:
--   node -e "const b=require('bcryptjs'); b.hash('Admin1234!',12).then(console.log)"
-- Then replace the placeholder below with the output.
--
-- The placeholder hash below will NOT work for login — bcrypt.compare() will
-- always return false against it. You MUST replace it before running the seed.

INSERT INTO users (organization_id, name, email, password_hash, role)
VALUES (
  1,
  'Admin User',
  'admin@demo.com',
  'REPLACE_THIS_WITH_REAL_BCRYPT_HASH',
  'admin'
);