# WeAll Protocol

![CI](https://img.shields.io/badge/tests-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MPL%202.0-purple)

**From prototype → infrastructure**

WeAll is a decentralized protocol for social coordination, identity, and governance — designed to operate under adversarial conditions with deterministic execution and verifiable state.

---

## ⚡ Current State

- Deterministic state execution  
- Consensus safety under adversarial conditions  
- Crash recovery and replay correctness  
- Network-layer resilience  
- Full CI test suite passing  

> Transition complete: *“it runs” → “it holds under pressure”*

---

## 🧠 Core Principles

- Determinism first  
- Verifiability over trust  
- Replayability  
- Adversarial resilience  
- No shortcuts  

---

## 🚀 Execution Roadmap

WeAll is moving toward deterministic parallel execution:

- conflict-safe execution lanes  
- helper validator proofs  
- deterministic merge  
- serial fallback guarantees  

---

## 🧩 Architecture Overview

- BFT-style consensus  
- deterministic execution engine  
- SQLite ledger (current)  
- P2P networking  
- Proof-of-Humanity  
- governance + treasury  
- API + runtime  

---

## 🧪 Running Tests

```bash
pytest
```

---

# 🚀 Boot Instructions (Corrected)

## 🧪 Tester Quickstart (Recommended)

From repo root:

```bash
git clone https://github.com/errol1swaby2-bit/WeAll-Protocol
cd WeAll-Protocol
./scripts/quickstart_tester.sh
```

This:
- boots backend via Docker
- initializes local state
- prepares test environment

---

## 🌐 Frontend (Optional)

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

---

## 🎬 Demo Bootstrap Flow

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

---

## 🧰 Backend Node Launcher (Production-Oriented)

```bash
cd Weall-Protocol
./scripts/run_node.sh
```

### What this does:
- loads node identity keys  
- validates environment configuration  
- enforces safety checks  
- launches node via gunicorn (port 8000)  

⚠️ Note:
This is a **lower-level node launcher**, not a full one-command public onboarding flow yet.

---

## 🔍 Health Checks

- API: http://127.0.0.1:8000/v1/readyz  
- Docs: http://127.0.0.1:8000/docs  
- Frontend: http://127.0.0.1:5173  

---

## 📈 Expected Impact

- 3–5x throughput increase (target)  
- preserved determinism  
- full replayability  
- no consensus weakening  

---

## 🧠 What We're Building

> A foundational protocol for decentralized social and governance systems

---

## 🤝 Contributing

Looking for contributors in:
- distributed systems  
- consensus  
- cryptography  
- backend infrastructure  
- protocol design  

---

## 🧭 Roadmap

- execution lanes  
- helper validator proofs  
- state partitioning  
- execution certificates  
- throughput scaling  

---

## 📜 License

Mozilla Public License 2.0

---

## 🔗 Repository

https://github.com/errol1swaby2-bit/WeAll-Protocol
