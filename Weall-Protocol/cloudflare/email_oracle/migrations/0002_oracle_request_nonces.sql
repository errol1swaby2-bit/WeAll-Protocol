CREATE TABLE IF NOT EXISTS oracle_request_nonces (
  nonce_key TEXT PRIMARY KEY,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oracle_request_nonces_expires_at
ON oracle_request_nonces(expires_at_ms);
