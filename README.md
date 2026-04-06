# WeAll Protocol

WeAll is a custom Layer 1 blockchain focused on deterministic social, identity, and governance systems.

The protocol is designed to eliminate trust assumptions wherever possible by enforcing:
- deterministic execution
- on-chain verifiability
- reproducible state transitions
- user-controlled identity and participation

---

# 🚀 Current Status

✅ Full test suite passing  
✅ Fresh clone reproducible  
✅ Full-stack golden path (account → PoH → media → post → feed) validated  
✅ IPFS-backed media pipeline working  

---

# 🧱 System Overview

WeAll consists of:

- Backend (Python / FastAPI / Gunicorn)
- Frontend (Vite / TypeScript)
- IPFS (Kubo via Docker)
- Custom L1 runtime (execution + consensus + state)

---

# ⚙️ Requirements

### System Dependencies

You must have:

- Python 3.12+
- Node.js 18+
- npm
- Git
- Docker Desktop (with WSL2 integration enabled)

---

## ⚠️ WSL2 USERS (IMPORTANT)

If you're on Windows:

1. Install Docker Desktop
2. Go to:
   - Settings → Resources → WSL Integration
3. Enable your Ubuntu distro

Verify inside WSL:

docker version
docker compose version

If these fail, the golden path will NOT work.

---

# 📦 Fresh Clone Setup

cd ~
git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
cd WeAll-Protocol/Weall-Protocol

---

## 🐍 Python Setup

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.lock

---

## 🌐 Frontend Setup

cd web
npm install
cd ..

---

# 🧪 Validate Full System (GOLDEN PATH)

This is the canonical validation command:

cd ~/WeAll-Protocol
./scripts/golden_path_e2e_gate.sh

---

## ✅ What This Does

The golden path verifies:

1. Starts IPFS (Kubo via Docker)
2. Starts backend API
3. Starts block producer
4. Waits for readiness
5. Runs frontend contract checks
6. Executes full user flow:

- account registration
- PoH bootstrap
- session issuance
- media upload (IPFS)
- content declaration
- post creation
- feed verification

---

## ✅ Expected Result

✅ FULL STACK GOLDEN PATH PASSED  
✅ golden path e2e gate complete  

---

# 📡 IPFS (Kubo)

Media uploads depend on IPFS.

The golden path automatically starts it via Docker:

docker compose -f Weall-Protocol/docker-compose.ipfs.yml up -d

Manual check:

curl -X POST http://127.0.0.1:5001/api/v0/version

---

# 🧪 Run Tests

pytest -q

---

# 🧠 Dev vs Production Behavior

### Dev / E2E Mode

- Open PoH bootstrap enabled
- Self-registration allowed
- No validator gating

### Production Mode (Target)

- Validator-controlled PoH issuance
- Strict identity verification
- Governance-controlled permissions

---

# 📁 Key Scripts

- scripts/golden_path_e2e_gate.sh → Full system validation
- scripts/golden_path_full_stack.py → End-to-end flow
- scripts/run_node.sh → Start backend
- scripts/start_full_stack.sh → Full stack boot

---

# 🔐 Determinism Goals

WeAll is built around:

- deterministic transaction execution
- explicit read/write sets
- replay-safe execution
- verifiable state transitions
- consensus-safe recovery

---

# 🧩 Architecture Principles

- No hidden state
- No implicit trust
- All critical flows auditable
- Economic layer isolated from social layer during genesis phase

---

# 📊 Genesis Phase

WeAll launches with:

- economics disabled
- no fees
- no rewards
- governance locked for economic parameters

---

# 🧭 Roadmap Focus

- validator network hardening
- consensus safety under adversarial conditions
- PoH strengthening
- DAO governance activation
- economic layer unlock

---

# 🧪 What Makes This Different

Most projects validate:
- builds
- unit tests

WeAll validates:
- full user lifecycle
- full runtime execution
- cross-system integration
- reproducibility from fresh clone

---

# 🤝 Contributing

We are actively looking for:

- backend engineers (Python / distributed systems)
- frontend engineers (TypeScript / Vite)
- protocol researchers
- systems engineers

---

# 📜 License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.

See the `LICENSE` file for the full text.

---

# 🧠 Final Note

If the golden path passes from a fresh clone, the system works.

That is the standard.
