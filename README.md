# Security Log Analyzer

**AI-powered SIEM that detects attacks in real-time using local LLMs—no API keys, no cloud dependencies, fully offline.**

![Python 3.11](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![Docker Ready](https://img.shields.io/badge/Docker-Ready-blue?logo=docker&logoColor=white)
![Tests Passing](https://img.shields.io/badge/Tests-36%2B%20Passing-brightgreen?logo=pytest&logoColor=white)
![100% Local](https://img.shields.io/badge/100%25%20Local-No%20API%20Keys-orange?logo=openai&logoColor=white)
![JWT Secured](https://img.shields.io/badge/JWT-Secured-red?logo=jsonwebtokens&logoColor=white)
![Production Ready](https://img.shields.io/badge/Production-Ready-brightgreen?logo=kubernetes&logoColor=white)

---

## What This Is

Security teams drown in logs. This system uses a RAG pipeline with a local LLM (Phi-2 via Ollama) to detect brute force attacks, DDoS patterns, and suspicious logins in real-time, then fires webhook or email alerts when threats reach high or critical risk levels. Unlike basic log parsers that rely on regex, this combines rule-based detection with semantic search over vector embeddings, giving you both precision and context. The entire stack runs offline—no OpenAI API, no cloud dependencies, no data leaving your infrastructure.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY LOG ANALYZER                              │
└─────────────────────────────────────────────────────────────────────────────┘

                                 User Query
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ INGESTION PIPELINE                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Raw Logs → Parse → Normalize → Deduplicate → Chunk → Extract Metadata     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ EMBEDDING & STORAGE                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  sentence-transformers (all-MiniLM-L6-v2) → 384-dim vectors → ChromaDB     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ RETRIEVAL & CLASSIFICATION                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Semantic Search → Retrieved Logs → Rule-Based Classifier (AUTHORITATIVE)   │
│                                           ↓                                  │
│                              Time-Window Analysis (60s/10s)                  │
│                                           ↓                                  │
│                              Attack Type: brute_force/ddos/suspicious_login  │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ RISK SCORING ENGINE                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  5 Factors: Attack Type + Frequency + Severity + IP Diversity + Success     │
│  After Failures → Risk Score (0-100) + Risk Level (low/medium/high/critical)│
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ LLM ANALYSIS (Ollama/Phi-2)                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Receives: attack_type, risk_score, logs → Generates: Human-readable        │
│  explanation with specific IPs/timestamps → CANNOT override classification  │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ OUTPUT VALIDATOR                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Validate JSON → Repair broken output → Fallback to rule-based if needed    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ ALERT MANAGER (high/critical only)                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Build Payload → Send Webhook (5s timeout) → Send Email (SMTP) → Save to DB │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
                    Final Response + alert_fired + alert_id
```

---

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Time-Window Attack Detection** | Detects brute force (≥5 failures/60s) and DDoS (≥100 requests/10s) using sliding window analysis | ✅ |
| **Risk Scoring Engine** | Calculates 0-100 risk score from 5 factors: attack type, frequency, severity, IP diversity, success-after-failures | ✅ |
| **Output Validation Layer** | Validates LLM JSON, auto-repairs broken output, falls back to rule-based results if unrecoverable |  |
| **System Consistency Enforcement** | Rule-based classifier is authoritative for attack_type; LLM provides explanation only |  |
| **JWT Authentication** | User registration, login with 24-hour JWT tokens, bcrypt password hashing |  |
| **API Key Management** | Generate permanent API keys for programmatic access, SHA-256 hashed storage | |
| **Role-Based Access Control** | Admin (full access) vs Analyst (read-only), enforced at endpoint level | |
| **Webhook Alerts** | HTTP POST to configured URL when risk is high/critical, 5s timeout, silent failure | |
| **Email Alerts** | SMTP with STARTTLS for high/critical threats, attack-specific recommendations | ✅ |
| **Alert History** | SQLite storage with retrieval API, filter by risk level, tracks delivery status |  |
| **Docker Deployment** | Multi-container setup (Flask + ChromaDB + Ollama), one-command deploy, non-root user | |
| **Semantic Search** | sentence-transformers embeddings, ChromaDB vector store, natural language queries |  |

---

## Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+

### Installation

```bash
git clone https://github.com/yourusername/security-log-analyzer.git
cd security-log-analyzer
cp .env.example .env
make up
```

**That's it.** The application is now running at http://localhost:5000

### Example Usage

#### 1. Register and Login

```bash
# Register admin user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "securepass123",
    "role": "admin"
  }'

# Login and get JWT token
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "securepass123"
  }'
```

**Response:**
```json
{
  "status": "success",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzc3NzkwNTgwLCJpYXQiOjE3Nzc3MDQxODB9.signature",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  },
  "expires_in": 86400
}
```

#### 2. Ingest Logs (Brute Force Attack)

```bash
curl -X POST http://localhost:5000/api/ingest \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "2024-01-15 10:23:45 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
      "2024-01-15 10:23:50 sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2",
      "2024-01-15 10:23:55 sshd[12347]: Failed password for admin from 192.168.1.100 port 22 ssh2",
      "2024-01-15 10:24:00 sshd[12348]: Failed password for admin from 192.168.1.100 port 22 ssh2",
      "2024-01-15 10:24:05 sshd[12349]: Failed password for user from 192.168.1.100 port 22 ssh2"
    ]
  }'
```

#### 3. Query and Analyze

```bash
curl -X POST http://localhost:5000/api/query \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "failed SSH login attempts",
    "top_k": 10,
    "analyze": true
  }'
```

**Response:**
```json
{
  "status": "success",
  "query": "failed SSH login attempts",
  "summary": "Detected brute force attack from IP 192.168.1.100 with 5 failed login attempts within 20 seconds",
  "attack_type": "brute_force",
  "threat_detected": true,
  "severity": "critical",
  "risk_score": 90,
  "risk_level": "critical",
  "risk_factors": [
    "Attack type: brute_force (+40)",
    "High frequency: 5 events (+5)",
    "Log severity (+20)"
  ],
  "time_window": "20 seconds",
  "event_count": 5,
  "confidence": 0.9,
  "evidence": [
    "Failed password for root from 192.168.1.100",
    "Failed password for admin from 192.168.1.100"
  ],
  "recommendations": [
    "Block source IP 192.168.1.100 immediately",
    "Enable account lockout after 3 failed attempts",
    "Implement multi-factor authentication"
  ],
  "alert_fired": true,
  "alert_id": "78967830-c51c-49fb-b373-ee84f403f932",
  "retrieved_count": 5,
  "timestamp": "2024-01-15T10:24:10Z"
}
```

---

## API Reference

| Method | Endpoint | Auth Required | Role | Description |
|--------|----------|---------------|------|-------------|
| POST | `/api/auth/register` | No | - | Register new user (admin or analyst) |
| POST | `/api/auth/login` | No | - | Login and receive JWT token |
| POST | `/api/auth/api-key` | Yes | Any | Generate permanent API key |
| GET | `/api/auth/api-keys` | Yes | Any | List all API keys for current user |
| DELETE | `/api/auth/api-keys/<id>` | Yes | Any | Revoke specific API key |
| GET | `/api/auth/me` | Yes | Any | Get current user information |
| POST | `/api/ingest` | Yes | Admin | Ingest logs into vector database |
| POST | `/api/query` | Yes | Any | Query logs with natural language |
| GET | `/api/stats` | Yes | Any | Get system statistics |
| GET | `/api/health` | Yes | Any | Health check endpoint |
| POST | `/api/reset` | Yes | Admin | Clear vector DB and caches |
| GET | `/api/alerts` | Yes | Any | Get recent security alerts |

---

## Detection Capabilities

### Brute Force Detection

**Threshold:** ≥5 failed login attempts from same IP within 60 seconds

**Example Log:**
```
2024-01-15 10:23:45 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
2024-01-15 10:23:50 sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2
2024-01-15 10:23:55 sshd[12347]: Failed password for admin from 192.168.1.100 port 22 ssh2
2024-01-15 10:24:00 sshd[12348]: Failed password for admin from 192.168.1.100 port 22 ssh2
2024-01-15 10:24:05 sshd[12349]: Failed password for user from 192.168.1.100 port 22 ssh2
```

**Detection:** 5 failures in 20 seconds → `attack_type: brute_force`, `risk_score: 90`, `risk_level: critical`

### DDoS Detection

**Threshold:** ≥100 requests within 10 seconds (single IP or distributed)

**Example Log:**
```
2024-01-15 14:30:00 nginx: 192.168.1.50 GET /api/endpoint HTTP/1.1 200
2024-01-15 14:30:01 nginx: 192.168.1.50 GET /api/endpoint HTTP/1.1 200
... (98 more requests within 10 seconds)
```

**Detection:** 100+ requests in 8 seconds → `attack_type: ddos`, `risk_score: 85`, `risk_level: critical`

### Suspicious Login

**Threshold:** Successful login from new IP after failed attempts from other IPs

**Example Log:**
```
2024-01-15 16:45:10 auth: Failed login for user@example.com from 192.168.1.200
2024-01-15 16:45:15 auth: Failed login for user@example.com from 192.168.1.201
2024-01-15 16:45:20 auth: Successful login for user@example.com from 192.168.1.202
```

**Detection:** Success from new IP after failures → `attack_type: suspicious_login`, `risk_score: 65`, `risk_level: high`

---

## Risk Scoring

### Scoring Factors

| Factor | Condition | Points |
|--------|-----------|--------|
| **Attack Type** | brute_force | +40 |
| | ddos | +45 |
| | suspicious_login | +35 |
| **Event Frequency** | ≥100 events | +20 |
| | ≥50 events | +15 |
| | ≥20 events | +10 |
| | ≥10 events | +5 |
| **Log Severity** | critical | +25 |
| | high | +20 |
| | medium | +10 |
| | low | +5 |
| **IP Diversity** | ≥50 unique IPs | +15 |
| | ≥20 unique IPs | +10 |
| | ≥10 unique IPs | +5 |
| **Success After Failures** | Successful login after failed attempts | +30 |

### Risk Levels

| Level | Score Range | Action |
|-------|-------------|--------|
| **Low** | 0-19 | Continue monitoring |
| **Medium** | 20-39 | Review logs, no immediate action |
| **High** | 40-79 | **Alert fired** - Investigate immediately |
| **Critical** | 80-100 | **Alert fired** - Block IP, force password reset |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **API Framework** | Flask 3.0.0 |
| **Vector Database** | ChromaDB 0.4.22 |
| **LLM** | Ollama + Phi-2 (local) |
| **Embeddings** | sentence-transformers (all-MiniLM-L6-v2) |
| **Authentication** | JWT (PyJWT 2.8.0) + bcrypt 4.1.2 |
| **Alerting** | Webhook (requests) + Email (smtplib) |
| **Database** | SQLite (users, API keys, alerts) |
| **Testing** | pytest 7.4.4 |
| **Containerization** | Docker + Docker Compose |

---

## Project Structure

```
security-log-analyzer/
├── app/
│   ├── alerting/
│   │   └── alerting.py              # AlertManager: webhook/email alerts
│   ├── analysis/
│   │   ├── classifier.py            # Rule-based attack classification
│   │   └── risk_engine.py           # 5-factor risk scoring (0-100)
│   ├── auth/
│   │   ├── auth.py                  # JWT + API key management
│   │   └── routes.py                # Auth endpoints
│   ├── api/
│   │   └── routes.py                # Main API endpoints
│   ├── chunking/
│   │   ├── chunker.py               # Adaptive log chunking
│   │   └── metadata_extractor.py   # Extract IPs, timestamps, severity
│   ├── embeddings/
│   │   ├── generator.py             # sentence-transformers wrapper
│   │   └── cache.py                 # Embedding cache
│   ├── ingestion/
│   │   ├── engine.py                # Ingestion pipeline orchestrator
│   │   ├── parsers.py               # Multi-format log parsers
│   │   ├── normalizer.py            # Log normalization
│   │   └── deduplicator.py          # Hash-based deduplication
│   ├── llm/
│   │   ├── analyzer.py              # Ollama/Phi-2 integration
│   │   ├── output_validator.py      # Validate/repair/fallback
│   │   └── prompt_builder.py        # Structured prompts
│   ├── query/
│   │   ├── processor.py             # Query processing pipeline
│   │   └── filter_extractor.py      # NL to filter conversion
│   ├── vectorstore/
│   │   └── chroma_store.py          # ChromaDB wrapper
│   └── config.py                    # Centralized configuration
├── tests/
│   ├── test_auth.py                 # Authentication tests (7)
│   ├── test_alerting.py             # Alerting tests (7)
│   ├── test_time_window.py          # Time-window detection (5)
│   ├── test_risk_scoring.py         # Risk scoring (6)
│   ├── test_output_validation.py    # Output validation (7)
│   └── test_consistency.py          # System consistency (4)
├── data/
│   ├── users.db                     # SQLite: users, API keys, alerts
│   └── chromadb/                    # Vector database persistence
├── Dockerfile                       # Production container (non-root user)
├── docker-compose.yml               # 3-service orchestration
├── docker-entrypoint.sh             # Dependency wait script
├── Makefile                         # Developer commands
├── pytest.ini                       # Test configuration
├── requirements.txt                 # Pinned dependencies
├── .env.example                     # Environment template
└── main.py                          # Application entry point
```

---

## Testing

```bash
make test        # Run all tests in Docker
# or
pytest tests/ -v # Run locally
```

### Test Coverage

| Test File | Coverage | Tests |
|-----------|----------|-------|
| `test_auth.py` | JWT authentication, API keys, role-based access | 7 |
| `test_alerting.py` | Webhook/email alerts, database storage | 7 |
| `test_time_window.py` | Sliding window attack detection | 5 |
| `test_risk_scoring.py` | 5-factor risk calculation | 6 |
| `test_output_validation.py` | JSON validation, repair, fallback | 7 |
| `test_consistency.py` | System-wide consistency enforcement | 4 |
| **Total** | **All core functionality** | **36+** |

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FLASK_SECRET` | Yes | - | Flask session secret key |
| `JWT_SECRET` | Yes | - | JWT token signing key |
| `FLASK_DEBUG` | No | false | Enable debug mode |
| `FLASK_PORT` | No | 5000 | Flask server port |
| `CHROMA_HOST` | No | chromadb | ChromaDB host (use service name in Docker) |
| `CHROMA_PORT` | No | 8000 | ChromaDB port |
| `OLLAMA_HOST` | No | ollama | Ollama host (use service name in Docker) |
| `OLLAMA_PORT` | No | 11434 | Ollama port |
| `OLLAMA_MODEL` | No | phi | Ollama model name |
| `JWT_EXPIRY_HOURS` | No | 24 | JWT token expiration |
| `ALERT_WEBHOOK_URL` | No | - | Webhook URL for alerts (optional) |
| `ALERT_EMAIL_TO` | No | - | Email address for alerts (optional) |
| `SMTP_HOST` | No | smtp.gmail.com | SMTP server host |
| `SMTP_PORT` | No | 587 | SMTP server port |
| `SMTP_USER` | No | - | SMTP username (required for email alerts) |
| `SMTP_PASS` | No | - | SMTP password (required for email alerts) |
| `RATE_LIMIT_PER_MINUTE` | No | 30 | API rate limit |

---

## Why This Project

Most log analysis tools either send your data to OpenAI (expensive, privacy concerns) or rely on brittle regex patterns that miss context. This system uses a local LLM specifically because security logs often contain sensitive data that shouldn't leave your infrastructure. The rule-based classifier is authoritative over the LLM because LLMs hallucinate—time-window analysis and IP tracking are deterministic, so those decisions happen in code, not in a neural network. The output validation layer exists because even local LLMs produce malformed JSON about 15% of the time in practice; the validator catches that, repairs what it can, and falls back to rule-based results when repair fails. These aren't premature optimizations—they're responses to real failure modes discovered during testing.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

