# 🛡️ SentinelPrompt WAF — Self-Learning Prompt Injection Firewall

> An enterprise-grade **Web Application Firewall (WAF)** for defending LLM-based applications against prompt injection, jailbreaks, document tampering, credential harvesting, and unauthorized data access — powered by multi-layer AI security with adaptive threat learning.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [System Requirements](#-system-requirements)
- [Project Structure](#-project-structure)
- [Quick Start — Step by Step](#-quick-start--step-by-step)
  - [Step 1: Install Ollama](#step-1-install-ollama)
  - [Step 2: Setup Backend](#step-2-setup-backend)
  - [Step 3: Setup Frontend](#step-3-setup-frontend)
  - [Step 4: Run the Project](#step-4-run-the-project)
- [How It Works](#-how-it-works)
- [Security Layers](#-security-layers)
- [Screenshots](#-screenshots)
- [Troubleshooting](#-troubleshooting)

---

## 🔍 Project Overview

**SentinelPrompt WAF** sits between the user and an LLM (TinyLlama via Ollama). Every prompt is evaluated across **6 detection layers** before reaching the AI model. Malicious or unauthorized prompts are **BLOCKED** before any LLM call is made.

### Key Features
- ✅ Real-time prompt injection detection
- ✅ SR-ACT (Subject-Resource-Action-Authorization) enterprise policy engine
- ✅ FAISS semantic similarity search with adaptive threat memory
- ✅ Self-learning: automatically learns new threat patterns
- ✅ Knowledge-base grounded responses (no hallucination of internal data)
- ✅ Admin security dashboard with live threat analytics
- ✅ Full audit logging with threat scores per detection layer

---

## 💻 System Requirements

| Requirement | Minimum |
|:---|:---|
| **OS** | Windows 10/11, macOS, Ubuntu 20.04+ |
| **Python** | 3.10 or higher |
| **Node.js** | 18.x or higher |
| **RAM** | 8 GB (16 GB recommended for ML models) |
| **Disk Space** | ~5 GB (for Ollama model + Python packages) |
| **Ollama** | Latest version (free, local LLM runner) |

---

## 📁 Project Structure

```
sentinel-prompt-waf/
├── backend/                        # FastAPI Python backend
│   ├── app/
│   │   ├── main.py                 # FastAPI app entry point
│   │   ├── api/
│   │   │   └── endpoints/
│   │   │       ├── scan.py         # /scan and /chat security gateway endpoints
│   │   │       ├── auth.py         # Authentication endpoints
│   │   │       └── dashboard.py    # Admin dashboard endpoints
│   │   ├── services/
│   │   │   ├── decision_engine.py  # Master security orchestrator
│   │   │   ├── input_normalizer.py # Layer 0: Unicode/obfuscation stripping
│   │   │   ├── regex_detector.py   # Layer 1: Pattern & regex detection
│   │   │   ├── keyword_detector.py # Layer 2: Keyword threat detection
│   │   │   ├── rule_detector.py    # Layer 3: Rule-based heuristics
│   │   │   ├── ml_detector.py      # Layer 4: DistilBERT ML classifier
│   │   │   ├── semantic_detector.py# Layer 5: FAISS semantic similarity
│   │   │   ├── policy_engine.py    # SR-ACT enterprise policy engine
│   │   │   ├── threat_intel.py     # Threat intelligence & IP tracking
│   │   │   ├── learning_module.py  # Adaptive self-learning manager
│   │   │   ├── knowledge_base.py   # SentinelCorp RAG knowledge base
│   │   │   └── llm_adapters.py     # Ollama / OpenAI LLM adapters
│   │   ├── core/
│   │   │   └── config.py           # App configuration & settings
│   │   └── db/                     # Database models & repositories
│   ├── models/                     # FAISS index & ML model files (auto-generated)
│   ├── requirements.txt            # Python dependencies
│   └── .env                        # Environment variables (create from .env.example)
│
├── frontend/                       # Next.js React frontend
│   ├── pages/
│   │   ├── index.js                # Employee chat interface
│   │   └── admin.js                # Security admin dashboard
│   ├── styles/                     # CSS styles
│   └── package.json                # Node.js dependencies
│
├── company_policy.yaml             # Enterprise security policy rules
└── README.md                       # This file
```

---

## 🚀 Quick Start — Step by Step

### Step 1: Install Ollama

Ollama runs the TinyLlama AI model locally on your machine.

1. Go to **[https://ollama.com](https://ollama.com)** and download for your OS
2. Install and open Ollama
3. Open a terminal and pull the TinyLlama model:

```bash
ollama pull tinyllama
```

4. Verify Ollama is running:
```bash
ollama list
# Should show: tinyllama
```

> ⚠️ Keep Ollama running in the background while using SentinelPrompt.

---

### Step 2: Setup Backend

Open a terminal and navigate to the `backend` folder:

```bash
cd sentinel-prompt-waf/backend
```

#### 2a. Create a Python virtual environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 2b. Install Python dependencies

```bash
pip install -r requirements.txt
```

> ⏳ This may take 5–10 minutes — it installs FastAPI, sentence-transformers, FAISS, and other packages.

#### 2c. Create the environment file

Create a file named `.env` inside the `backend/` folder with this content:

```env
# Application
PROJECT_NAME=SentinelPrompt WAF
SECRET_KEY=your-secret-key-change-this-in-production
CORS_ORIGINS=["http://localhost:3000"]

# Ollama Settings
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=tinyllama

# Security Thresholds
OVERALL_BLOCK_THRESHOLD=0.65

# Database (optional — uses SQLite by default)
DATABASE_URL=sqlite+aiosqlite:///./sentinelprompt.db
```

#### 2d. Start the backend server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

✅ Backend is running at: **http://localhost:8000**  
📖 API Docs available at: **http://localhost:8000/docs**

---

### Step 3: Setup Frontend

Open a **new** terminal and navigate to the `frontend` folder:

```bash
cd sentinel-prompt-waf/frontend
```

#### 3a. Install Node.js dependencies

```bash
npm install
```

#### 3b. Start the frontend

```bash
npm run dev
```

✅ Frontend is running at: **http://localhost:3000**

---

### Step 4: Run the Project

Once all three services are running, open your browser:

| Service | URL |
|:---|:---|
| 🌐 **Employee Chat Interface** | http://localhost:3000 |
| 🔒 **Security Admin Dashboard** | http://localhost:3000/admin |
| 📖 **Backend API Docs** | http://localhost:8000/docs |
| 🤖 **Ollama** | http://localhost:11434 |

> **Admin Login:** Username: `admin` / Password: `sentinel123`

---

## ⚙️ How It Works

```
User Prompt
    │
    ▼
┌─────────────────────────────────┐
│   SentinelPrompt Security WAF   │
│                                 │
│  L0: Input Normalization        │ ← Strips unicode tricks, zero-width chars
│  L1: Regex Pattern Detection    │ ← Jailbreaks, delimiters, tampering patterns
│  L2: Keyword Detection          │ ← Threat keyword matching
│  L3: Rule-Based Heuristics      │ ← Structural attack patterns
│  L4: ML Classifier (DistilBERT) │ ← Trained binary threat classifier
│  L5: Semantic FAISS Search      │ ← Vector similarity to known threat bank
│  SR-ACT Policy Engine           │ ← Enterprise authorization policy
│  Threat Intelligence            │ ← IP reputation & attack frequency
│                                 │
│  ┌─────────┐    ┌────────────┐  │
│  │ BLOCKED │    │ FORWARDED  │  │
│  │ ─────── │    │ ─────────  │  │
│  │ No RAG  │    │ KB Lookup  │  │
│  │ No LLM  │    │ → Ollama   │  │
│  └─────────┘    └────────────┘  │
└─────────────────────────────────┘
```

### Decision Rules
- **BLOCKED** → Returns security violation notice. Ollama is **never called**.
- **FORWARDED + General Knowledge** → Ollama answers directly.
- **FORWARDED + Company Specific** → Ollama answers using verified KB context.
- **FORWARDED + Unknown Company Fact** → Returns grounded refusal (no Ollama).

---

## 🔐 Security Layers

| Layer | Name | What it Detects |
|:---|:---|:---|
| **L0** | Input Normalizer | Zero-width chars, homoglyphs, unicode obfuscation |
| **L1** | Regex Detector | Prompt delimiters, jailbreak signatures, document tampering, credential harvesting |
| **L2** | Keyword Detector | 200+ threat keywords across attack categories |
| **L3** | Rule Heuristics | Structural injection patterns, role-play attacks |
| **L4** | ML Classifier | DistilBERT fine-tuned binary threat classifier |
| **L5** | Semantic FAISS | Cosine similarity search against 384-dim threat vector bank |
| **Policy** | SR-ACT Engine | Enterprise authorization matrix (Subject-Resource-Action) |
| **Intel** | Threat Intel | IP reputation, attack frequency, rate limiting |

---

## 🔧 Troubleshooting

### ❌ `Cannot find module 'next'`
```bash
cd frontend
npm install
```

### ❌ `Ollama connection refused`
- Make sure Ollama is running: open the Ollama app or run `ollama serve`
- Verify: `curl http://localhost:11434/api/tags`

### ❌ `ModuleNotFoundError` in Python
```bash
cd backend
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

### ❌ `CORS error` in browser
- Make sure the backend `.env` has `CORS_ORIGINS=["http://localhost:3000"]`
- Restart the backend after editing `.env`

### ❌ Backend shows `Database error`
- This is non-fatal. The app works without a database (logs are skipped).
- To enable: ensure `DATABASE_URL` is set correctly in `.env`

---

## 📞 Support

This project was built as part of a final year academic project demonstrating AI-powered enterprise security for LLM systems.

**Tech Stack:** Python · FastAPI · Next.js · React · Ollama · TinyLlama · FAISS · SentenceTransformers · DistilBERT · SQLite · SQLAlchemy
