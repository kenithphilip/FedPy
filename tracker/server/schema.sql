-- FedRAMP 20x Tracker schema
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- FRMR source metadata (single row, key/value)
CREATE TABLE IF NOT EXISTS frmr_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Processes: FRR processes (ADS, CCM, ...) and a synthetic 'KSI' kind for the catalog
CREATE TABLE IF NOT EXISTS processes (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('FRR','KSI')),
  short_name  TEXT,
  name        TEXT,
  web_name    TEXT,
  info_json   TEXT
);

-- KSI domains (IAM, CMT, ...) — separate from FRR processes for clarity
CREATE TABLE IF NOT EXISTS ksi_domains (
  id          TEXT PRIMARY KEY,
  short_name  TEXT,
  name        TEXT,
  web_name    TEXT,
  theme       TEXT
);

-- FRD (definitions / glossary)
CREATE TABLE IF NOT EXISTS definitions (
  id          TEXT PRIMARY KEY,           -- e.g. FRD-ACV
  term        TEXT NOT NULL,
  definition  TEXT NOT NULL,
  alts_json   TEXT,                       -- JSON array of strings
  fka         TEXT
);

-- One row per "label" within a process (e.g. CSO -> General Provider Responsibilities)
CREATE TABLE IF NOT EXISTS process_labels (
  process_id  TEXT NOT NULL REFERENCES processes(id),
  label_key   TEXT NOT NULL,              -- e.g. CSO
  label_name  TEXT,                       -- human-readable
  PRIMARY KEY (process_id, label_key)
);

-- FRR requirements (flattened across applicability + label)
CREATE TABLE IF NOT EXISTS requirements (
  id                     TEXT PRIMARY KEY,   -- e.g. ADS-CSO-PUB
  process_id             TEXT NOT NULL REFERENCES processes(id),
  applicability          TEXT NOT NULL CHECK (applicability IN ('20x','rev5','both')),
  actor_label            TEXT NOT NULL,     -- e.g. CSO
  name                   TEXT,
  statement              TEXT NOT NULL,
  primary_key_word       TEXT,              -- MUST/SHOULD/MAY/...
  terms_json             TEXT,              -- JSON array of FRD term names referenced
  affects_json           TEXT,
  following_info_json    TEXT,
  examples_json          TEXT,
  note                   TEXT,
  fka                    TEXT,
  timeframe_type         TEXT,
  timeframe_num          INTEGER,
  raw_json               TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_req_process ON requirements(process_id);
CREATE INDEX IF NOT EXISTS idx_req_applic  ON requirements(applicability);
CREATE INDEX IF NOT EXISTS idx_req_actor   ON requirements(actor_label);

-- KSI indicators
CREATE TABLE IF NOT EXISTS indicators (
  id          TEXT PRIMARY KEY,           -- e.g. KSI-IAM-AAM
  domain_id   TEXT NOT NULL REFERENCES ksi_domains(id),
  name        TEXT,
  statement   TEXT NOT NULL,
  fka         TEXT,
  raw_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ind_domain ON indicators(domain_id);

-- NIST 800-53 controls referenced by indicators
CREATE TABLE IF NOT EXISTS controls (
  id      TEXT PRIMARY KEY,               -- e.g. ac-2.2 (kept lowercase as in FRMR)
  family  TEXT NOT NULL                   -- e.g. ac
);
CREATE INDEX IF NOT EXISTS idx_ctrl_family ON controls(family);

CREATE TABLE IF NOT EXISTS indicator_controls (
  indicator_id  TEXT NOT NULL REFERENCES indicators(id),
  control_id    TEXT NOT NULL REFERENCES controls(id),
  PRIMARY KEY (indicator_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_ic_ctrl ON indicator_controls(control_id);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,           -- scrypt: salt$N$r$p$hash
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
-- 2FA columns are added via db.ts migrate() at startup (idempotent).

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sess_user ON sessions(user_id);

-- User-entered state per FRMR item. Survives FRMR re-ingest via stable IDs.
CREATE TABLE IF NOT EXISTS item_state (
  item_id        TEXT NOT NULL,
  item_type      TEXT NOT NULL CHECK (item_type IN ('requirement','indicator')),
  status         TEXT NOT NULL DEFAULT 'not_started'
                   CHECK (status IN ('not_started','in_progress','met','not_applicable','blocked')),
  owner_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  owner_text     TEXT,                  -- free-text fallback (e.g. team name)
  notes          TEXT,
  evidence_url   TEXT,
  last_reviewed  TEXT,                  -- ISO date
  updated_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (item_id, item_type)
);
CREATE INDEX IF NOT EXISTS idx_state_status ON item_state(status);
CREATE INDEX IF NOT EXISTS idx_state_owner  ON item_state(owner_user_id);

-- API tokens for headless integrations (e.g. cloud-evidence collector tracker-push).
-- Tokens are SHA-256 hashed at rest; the raw token is shown to the admin only at creation.
CREATE TABLE IF NOT EXISTS api_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash  TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,                  -- human label, e.g. "cloud-evidence collector"
  scope       TEXT NOT NULL DEFAULT 'patch:indicators'
                CHECK (scope IN ('patch:indicators', 'patch:all', 'read:all')),
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_used   TEXT,
  expires_at  TEXT,
  revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_apitok_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_apitok_revoked ON api_tokens(revoked_at);

-- Collector-run telemetry pushed by cloud-evidence after each PVA run.
-- Surfaces last-run state to the tracker dashboard without coupling the tracker
-- to cloud-evidence's filesystem layout.
CREATE TABLE IF NOT EXISTS collector_runs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id          TEXT NOT NULL UNIQUE,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  frmr_version    TEXT,
  total_ksis      INTEGER NOT NULL DEFAULT 0,
  passed_ksis     INTEGER NOT NULL DEFAULT 0,
  failed_ksis     INTEGER NOT NULL DEFAULT 0,
  drift_events    INTEGER NOT NULL DEFAULT 0,
  negative_drift  INTEGER NOT NULL DEFAULT 0,
  pushed_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  source_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL,
  summary_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_collector_runs_started ON collector_runs(started_at DESC);

-- Rate limit buckets: one row per (key, window-start-second).
-- "key" is a composite of the rate-limit policy name + the subject (IP or user ID).
-- Hit counts auto-prune on read; we don't need an explicit cleanup cron.
CREATE TABLE IF NOT EXISTS rate_limits (
  key         TEXT NOT NULL,
  window_sec  INTEGER NOT NULL,   -- unix-seconds of the bucket start
  hits        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window_sec)
);
CREATE INDEX IF NOT EXISTS idx_rl_window ON rate_limits(window_sec);

-- Audit log for compliance / change tracking
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  item_id    TEXT NOT NULL,
  item_type  TEXT NOT NULL,
  field      TEXT NOT NULL,
  old_value  TEXT,
  new_value  TEXT,
  changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_item ON audit_log(item_id, item_type);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

-- ─── LOOP-B.B3: Risk acceptance workflow ──────────────────────────────────────
-- Resident Ed25519 signing key registry. The private key is stored PEM-encoded
-- so the tracker can re-sign / re-verify without external key material; a
-- production deployment would front this with a KMS/HSM (tracked as a follow-up
-- risk B.B3-EXT-1). Every risk-acceptance record + approval is signed with the
-- active key; the cloud-evidence reader verifies each record against
-- public_key_pem returned alongside the GET /api/risk-acceptances response.
CREATE TABLE IF NOT EXISTS signing_keys (
  key_id           TEXT PRIMARY KEY,            -- SHA-256(SPKI PEM)[0:16]
  private_key_pem  TEXT NOT NULL,               -- PKCS8 Ed25519 PEM
  public_key_pem   TEXT NOT NULL,               -- SPKI Ed25519 PEM
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Signed, audited risk-acceptance decisions (NIST CA-5 / RA-7 / FedRAMP
-- Deviation Request + Risk Adjustment Request). The signature over the
-- canonical-JSON payload IS the non-repudiable audit record; the cloud-evidence
-- POA&M emitter flips matching risks to risk.status="deviation-approved" only
-- for rows that are status='approved' AND expiration_date > now().
CREATE TABLE IF NOT EXISTS risk_acceptances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,                       -- v4 uuid; written to OSCAL acceptance-uuid prop
  finding_uuid TEXT NOT NULL,                      -- matches oscal finding.uuid
  poam_item_uuid TEXT NOT NULL,                    -- matches oscal poam-item.uuid
  ksi_id TEXT NOT NULL,                            -- e.g. KSI-IAM-MFA
  rule TEXT NOT NULL,                              -- e.g. iam-mfa-aws-root
  provider TEXT NOT NULL,                          -- aws | gcp | azure
  accepted_by_user_id INTEGER NOT NULL REFERENCES users(id),
  accepted_at TEXT NOT NULL,                       -- ISO datetime
  expiration_date TEXT NOT NULL,                   -- ISO datetime; >= now+7d AND <= now+365d
  business_justification TEXT NOT NULL,            -- min 100 chars (server-enforced)
  acceptance_type TEXT NOT NULL CHECK (acceptance_type IN ('deviation-request','risk-adjustment','false-positive','operational-requirement')),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','expired','revoked')),
  approved_by_user_id INTEGER REFERENCES users(id),
  approved_at TEXT,
  signature TEXT NOT NULL,                         -- base64 Ed25519 signature of canonical-JSON payload
  signing_key_id TEXT NOT NULL,                    -- maps to signing_keys.key_id
  approval_signature TEXT,                         -- second signature over (uuid, approved_by_user_id, approved_at)
  approval_signing_key_id TEXT,
  revoked_at TEXT,
  revoked_by_user_id INTEGER REFERENCES users(id),
  revocation_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_ra_finding ON risk_acceptances(finding_uuid);
CREATE INDEX IF NOT EXISTS idx_ra_poam_item ON risk_acceptances(poam_item_uuid);
CREATE INDEX IF NOT EXISTS idx_ra_status ON risk_acceptances(status);
CREATE INDEX IF NOT EXISTS idx_ra_expiration ON risk_acceptances(expiration_date);
CREATE INDEX IF NOT EXISTS idx_ra_ksi ON risk_acceptances(ksi_id);

CREATE TABLE IF NOT EXISTS risk_acceptance_compensating_links (
  acceptance_id INTEGER NOT NULL REFERENCES risk_acceptances(id) ON DELETE CASCADE,
  compensating_control_uuid TEXT NOT NULL,         -- foreign UUID to B.B4 registry
  PRIMARY KEY (acceptance_id, compensating_control_uuid)
);
CREATE INDEX IF NOT EXISTS idx_ra_cc_acceptance ON risk_acceptance_compensating_links(acceptance_id);

-- ─── LOOP-B.B4: Compensating-controls registry ────────────────────────────────
-- Structured, AO-signed compensating-control records (NIST 800-53A §2.4 / CA-5
-- / CA-2(1) / PL-2). Replaces free-text UUID references from B.B3 acceptances
-- with immutable, signed rows the cloud-evidence POA&M emitter consumes to fill
-- risk.remediations[] (lifecycle='completed'). Each record is signed with the
-- same resident Ed25519 key as risk_acceptances (signing_keys table); activation
-- writes a second signature so AO sign-off is non-repudiable. draft → active
-- requires an ao/admin sign-off; active rows are immutable (retire + recreate).
CREATE TABLE IF NOT EXISTS compensating_controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,                       -- v4 uuid; canonical id referenced by acceptances + OSCAL props
  title TEXT NOT NULL,                             -- 5-200 chars
  description TEXT NOT NULL,                       -- >= 200 chars
  nist_control_ids TEXT NOT NULL,                  -- JSON array of NIST 800-53 r5 control ids; validated against catalog
  implemented_by_user_id INTEGER NOT NULL REFERENCES users(id),
  implemented_at TEXT NOT NULL,
  signed_off_by_user_id INTEGER REFERENCES users(id),   -- AO id (null until activated)
  signed_off_at TEXT,                              -- ISO datetime (null until activated)
  expiration_date TEXT,                            -- ISO datetime; null = no expiration
  evidence_url TEXT,                               -- e.g. runbook URL
  evidence_sha256 TEXT,                            -- sha256 of evidence attachment if uploaded via H.4
  status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  signature TEXT NOT NULL,                         -- base64 Ed25519 signature over the canonical payload
  signing_key_id TEXT NOT NULL,
  activation_signature TEXT,                       -- second signature over the activation event
  activation_signing_key_id TEXT,
  retired_at TEXT,
  retired_by_user_id INTEGER REFERENCES users(id),
  retirement_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cc_status ON compensating_controls(status);
CREATE INDEX IF NOT EXISTS idx_cc_expiration ON compensating_controls(expiration_date);
CREATE INDEX IF NOT EXISTS idx_cc_uuid ON compensating_controls(uuid);
