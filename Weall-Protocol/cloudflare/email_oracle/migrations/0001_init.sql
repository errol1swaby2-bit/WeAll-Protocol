CREATE TABLE IF NOT EXISTS email_challenges (
  challenge_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  operator_account_id TEXT,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  verified_at_ms INTEGER,
  resend_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_challenges_email
ON email_challenges(email);

CREATE INDEX IF NOT EXISTS idx_email_challenges_status
ON email_challenges(status);

CREATE INDEX IF NOT EXISTS idx_email_challenges_expires_at
ON email_challenges(expires_at_ms);
