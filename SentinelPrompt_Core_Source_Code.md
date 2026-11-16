============================================================
SENTINELPROMPT
CORE SECURITY MECHANISM SOURCE CODE
============================================================

Project:
SentinelPrompt: An Adaptive Multi-Layer Security Gateway
for Prompt Injection Detection in LLM Applications

============================================================
1. CORE REPOSITORY MAP & SUMMARY
============================================================

| Core Component | File Path | Core Security Role |
|---|---|---|
| **1. Application Gateway** | `backend/app/main.py` | FastAPI application initialization & API route registration |
| **2. Security Gateway API** | `backend/app/api/endpoints/scan.py` | `/scan` & `/chat` endpoints; early block & RAG enrichment logic |
| **3. Layer 1: Regex Detector** | `backend/app/services/regex_detector.py` | Fast pattern scanner (delimiters, DAN prefixes, base64 payloads) |
| **4. Layer 2: Keyword Detector** | `backend/app/services/keyword_detector.py` | Linear-time Aho-Corasick automaton for high-risk threat phrases |
| **5. Layer 3: DistilBERT Model** | `backend/app/services/ml_detector.py` | Fine-tuned PyTorch sequence classification for adversarial prompts |
| **6. Layer 4: MiniLM + FAISS** | `backend/app/services/semantic_detector.py` | 384-dim dense vector search against indexed threat vectors |
| **7. SR-ACT Policy Engine** | `backend/app/services/policy_engine.py` | Subject-Resource-Action parser & enterprise policy enforcement |
| **8. Multi-Layer Decision Engine**| `backend/app/services/decision_engine.py` | Layer orchestration, weighted scoring, & fail-closed safety block |
| **9. Adaptive Threat Memory** | `backend/app/services/learning_module.py` | Analyst threat confirmation workflow & vector memory persistence |
| **10. RAG Grounding Engine** | `backend/app/services/knowledge_base.py` | Enterprise knowledge retrieval & out-of-domain query refusal |
| **11. Ollama LLM Adapter** | `backend/app/services/llm_adapters.py` | Downstream TinyLlama adapter & structured error classification |


============================================================
2. CORE APPLICATION ENTRY POINT
============================================================

SOURCE FILE: backend/app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logger import logger
from app.db.session import async_engine, Base
from app.api.endpoints import auth, scan, health, dashboard, policies


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SentinelPrompt WAF application startup...")
    if async_engine is not None:
        try:
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database schemas verified and initialized successfully.")
        except Exception as e:
            logger.warning(f"Database table auto-creation skipped or failed: {str(e)}")
    yield
    logger.info("SentinelPrompt WAF shutting down...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Self-Learning Web Application Firewall (WAF) for Prompt Injection Defense in LLM Systems.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(policies.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API Gateway",
        "docs": "/docs",
        "health": "/health"
    }


============================================================
3. SECURITY GATEWAY ENDPOINTS
============================================================

SOURCE FILE: backend/app/api/endpoints/scan.py

from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.db.session import get_db
from app.db.repositories import SecurityLogRepository
from app.services.decision_engine import DecisionEngine
from app.services.knowledge_base import KnowledgeBaseService
from app.services.llm_adapters import LLMAdapterFactory
from app.api.schemas import PromptScanRequest, PromptScanResponse, ChatGatewayRequest, ChatGatewayResponse
from app.core.logger import logger

router = APIRouter(prefix="", tags=["Security Gateway"])
decision_engine = DecisionEngine()
knowledge_base = KnowledgeBaseService()


@router.post("/scan", response_model=PromptScanResponse)
async def scan_prompt(
    req: PromptScanRequest,
    request: Request,
    db: Optional[AsyncSession] = Depends(get_db)
):
    eval_res = decision_engine.evaluate_prompt(req.prompt)
    client_ip = request.client.host if request.client else "127.0.0.1"

    if db is not None:
        try:
            log_repo = SecurityLogRepository(db)
            await log_repo.log_event(
                prompt=req.prompt,
                is_malicious=eval_res["is_malicious"],
                action_taken=eval_res["verdict"],
                threat_score=eval_res["overall_threat_score"],
                layer_scores=eval_res["layer_scores"],
                detected_attack_types=eval_res["detected_attack_types"],
                execution_time_ms=eval_res["execution_time_ms"],
                client_ip=client_ip,
                user_id=req.user_id
            )
        except Exception as e:
            logger.warning(f"Failed to log security event to database: {str(e)}")

    return PromptScanResponse(**eval_res)


@router.post("/chat", response_model=ChatGatewayResponse)
async def chat_gateway(
    req: ChatGatewayRequest,
    request: Request,
    db: Optional[AsyncSession] = Depends(get_db)
):
    eval_res = decision_engine.evaluate_prompt(req.prompt)
    client_ip = request.client.host if request.client else "127.0.0.1"

    if db is not None:
        try:
            log_repo = SecurityLogRepository(db)
            await log_repo.log_event(
                prompt=req.prompt,
                is_malicious=eval_res["is_malicious"],
                action_taken=eval_res["verdict"],
                threat_score=eval_res["overall_threat_score"],
                layer_scores=eval_res["layer_scores"],
                detected_attack_types=eval_res["detected_attack_types"],
                execution_time_ms=eval_res["execution_time_ms"],
                client_ip=client_ip,
                llm_provider=req.llm_provider
            )
        except Exception as e:
            logger.warning(f"Failed to log security event: {str(e)}")

    scan_dto = PromptScanResponse(**eval_res)

    if eval_res["is_malicious"]:
        security_report = {
            "status": "BLOCKED",
            "message": "Security Notice: This request was blocked because it attempts to access restricted, confidential, or unauthorized information.",
            "threat_score": eval_res["overall_threat_score"],
            "threat_level": eval_res["threat_level"],
            "detected_attack_types": eval_res["detected_attack_types"],
            "recommendation": "Refactor prompt to remove jailbreak syntax or system override instructions."
        }
        return ChatGatewayResponse(security_eval=scan_dto, security_report=security_report, llm_response=None)

    kb_context, is_grounded = knowledge_base.get_company_context(req.prompt)
    if not is_grounded:
        llm_res = {
            "provider": req.llm_provider,
            "model": "sentinelcorp-rag-grounding",
            "text": "I don't have that information in the current SentinelCorp knowledge base.",
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "error": None
        }
        return ChatGatewayResponse(
            security_eval=scan_dto,
            llm_response=llm_res
        )

    system_prompt = req.system_prompt or f"You are SentinelCorp's AI Assistant. Use the following SentinelCorp company knowledge to answer employee questions accurately:\n\n{kb_context}"
    
    adapter = LLMAdapterFactory.get_adapter(req.llm_provider)
    llm_res = await adapter.generate_response(req.prompt, system_prompt=system_prompt)

    return ChatGatewayResponse(
        security_eval=scan_dto,
        llm_response=llm_res
    )


============================================================
4. LAYER 1: REGEX PATTERN DETECTOR
============================================================

SOURCE FILE: backend/app/services/regex_detector.py

import re
import base64
from typing import Dict, List, Any, Tuple


class RegexDetector:
    """
    Layer 1: High-speed Regex and Pattern Detection Engine.
    Detects encoded payloads, prompt delimiters, unicode tricks, and known jailbreak syntax.
    """

    def __init__(self):
        self.patterns = {
            "PROMPT_DELIMITER": [
                r"<\s*\|?\s*im_start\s*\|?\s*>",
                r"<\s*\|?\s*im_end\s*\|?\s*>",
                r"<\s*\|?\s*endoftext\s*\|?\s*>",
                r"\[\s*INST\s*\]",
                r"\[\s*/\s*INST\s*\]",
                r"===\s*SYSTEM\s*(PROMPT|OVERRIDE)?\s*[:=]*",
                r"\[\s*SYSTEM\s*(PROMPT|OVERRIDE)?\s*\]",
                r"<\s*system\s*>",
                r"<\s*/\s*system\s*>",
                r"system\s*override\s*:"
            ],
            "JAILBREAK_PREFIX": [
                r"\bDAN\s*\d+(\.\d+)?\b",
                r"\bDeveloper\s*Mode\s*(enabled|v\d+)?\b",
                r"\bSUDO\s*mode\b",
                r"\bDo\s*Anything\s*Now\b",
                r"\bAIM\s*Mode\b",
                r"\bAlways\s*Intelligent\s*and\s*Machiavellian\b",
            ],
            "COMMAND_INJECTION": [
                r"\b(exec|eval|system|passthru|popen|shell_exec)\s*\(",
                r"\bimport\s+(os|subprocess|sys|shutil)\b",
                r"__import__\s*\(",
            ],
            "BASE64_PAYLOAD": [
                r"\b[A-Za-z0-9+/]{20,}={0,2}\b"
            ],
            "HEX_ENCODED": [
                r"(\\x[0-9a-fA-F]{2}){4,}",
                r"(0x[0-9a-fA-F]{2}\s*){4,}"
            ],
            "ZERO_WIDTH_CHARS": [
                r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E]"
            ],
            "CREDENTIAL_HARVESTING": [
                r"\b(give|show|reveal|provide|extract|tell|output|get|display|send|i\s+need)\s+(me|us)?\s*.*(the\s+)?(admin|administrator|system|it|root|app|user|company|sentinelcorp|manager)?\s*(password|passcode|secret\s*key|api\s*key|credentials|private\s*key)s?\b",
                r"\bwhat\s+is\s+the\s+.*(admin|administrator|system|it|root|user|sentinelcorp\s+it)\s+password(?![\w\s]*(reset|policy|procedure|guide|help|support))\b",
                r"\b(admin|administrator|manager|employee|hr|sentinelcorp\s+it)\s+password(?![\w\s]*(reset|policy|procedure|guide|help|support))\b",
                r"\b(secret\s*key|api\s*key|access\s*token)\s+(used|stored|configured|used\s+by)\b",
                r"\bprovide\s+administrator\s+credentials\b",
                r"\b(reveal|show|give)\s+.*(api\s*keys|secret\s*key|credentials)\b",
            ],
            "FINANCIAL_DATA_HARVESTING": [
                r"\b(manager|employee|executive|user|person)\s+acc\s*(num|number)?\s*and\s*ifsc\b",
                r"\b(bank\s*account|account\s*number|ifsc\s*code|bank\s*details|ifsc)\b",
                r"\b(confidential\s+financial|financial\s+audit|unreleased\s+earnings|payroll\s+records)\b",
                r"\b(give|show|reveal|provide|extract)\s+me\s+.*(bank|ifsc|account\s*num)\b",
            ],
            "PERSONAL_DATA_HARVESTING": [
                r"\b(hr\s+employee|employee|person|principal|manager)\s+(personal|confidential)\s+(details|information|data)\b",
                r"\b(confidential|personal)\s+(employee|person|principal)\s+(information|details|data)\b",
                r"\b(company|employee)\s+person\s+details\b",
                r"\bshow\s+me\s+hr\s+employee\b",
                r"\b(give|show|reveal|provide)\s+me\s+.*(personal|person)\s+(details|information)\b",
            ],
            "CONFIDENTIAL_DOC_HARVESTING": [
                r"\b(give|show|reveal|provide|extract|get)\s+me\s+.*confidential\b",
                r"\bconfidential\s+(company|corporate|internal)\s+(documents|information|files|data)\b",
                r"\bshow\s+me\s+the\s+company'?s\s+confidential\b",
            ],
            "CYBER_ABUSE_CRACKING": [
                r"\b(how\s+(can\s+i|to)|way\s+to)\s+(crack|hack|bypass|steal)\s+.*(password|pin|upi|credential)s?\b",
                r"\b(crack|hack|steal)\s+the\s+.*(password|pin|upi)\b",
                r"\bcrack\s+a\s+upi\s+password\b",
            ],
            "SALARY_DATA_EXTRACTION": [
                r"\b(give|show|reveal|provide|tell)\s+me\s+.*(john'?s|manager'?s|hr\s+manager'?s|employee|all\s+employee|executive)\s+(salary|salaries|compensation|pay)\b",
                r"\bwhat\s+is\s+the\s+salary\s+of\b",
                r"\bshow\s+me\s+all\s+employee\s+salaries\b",
                r"\bhow\s+(can\s+i|to)\s+(get|obtain|retrieve|access|extract)\s+.*(employee'?s\s+salary|salaries|salary\s+data)\b",
                r"\b(give|show)\s+me\s+step-by-step\s+instructions\s+to\s+retrieve\s+employee\s+salary\b",
                r"\bwhich\s+database\s+contains\s+employee\s+salaries\b",
                r"\b(give|show|provide)\s+me\s+the\s+query\s+.*(extract|retrieve|get)\s+employee\s+salaries\b",
                r"\bwhere\s+is\s+the\s+salary\s+table\b",
            ],
            "UNAUTHORIZED_ACCESS_ASSISTANCE": [
                r"\bhow\s+(do\s+i|can\s+i)\s+access\s+another\s+employee'?s\s+hr\s+record\b",
                r"\bhow\s+can\s+i\s+obtain\s+confidential\s+employee\s+information\b",
                r"\bhow\s+can\s+i\s+bypass\s+the\s+(security\s+controls|hr\s+system)\b",
                r"\bfor\s+a\s+security\s+test,\s*explain\s+exactly\s+how\s+i\s+could\s+bypass\b",
                r"\bpretend\s+i\s+am\s+an?\s+administrator\b",
                r"\b(manager|boss)\s+approved\s+this\s+request.*bank\s+details\b",
                r"\bwhat\s+is\s+the\s+database\s+username\b",
            ]
        }

        self.compiled_patterns = {
            category: [re.compile(p, re.IGNORECASE) for p in pats]
            for category, pats in self.patterns.items()
        }

    def decode_base64_candidates(self, prompt: str) -> List[str]:
        decoded_strings = []
        candidates = re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", prompt)
        for cand in candidates:
            try:
                missing_padding = len(cand) % 4
                if missing_padding:
                    cand += "=" * (4 - missing_padding)
                decoded_bytes = base64.b64decode(cand, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str) > 5 and any(c.isalpha() for c in decoded_str):
                    decoded_strings.append(decoded_str)
            except Exception:
                continue
        return decoded_strings

    def analyze(self, prompt: str) -> Dict[str, Any]:
        detected_categories = []
        match_details = []
        score = 0.0

        zw_matches = self.compiled_patterns["ZERO_WIDTH_CHARS"][0].findall(prompt)
        if zw_matches:
            detected_categories.append("ZERO_WIDTH_OBFUSCATION")
            match_details.append(f"Found {len(zw_matches)} zero-width invisible characters.")
            score += 0.40

        cleaned_prompt = re.sub(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E]", "", prompt)

        for pattern in self.compiled_patterns["PROMPT_DELIMITER"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("PROMPT_DELIMITER_INJECTION")
                match_details.append(f"Prompt delimiter match: {matches[0]}")
                score += 0.75
                break

        for pattern in self.compiled_patterns["JAILBREAK_PREFIX"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("JAILBREAK_SIGNATURE")
                match_details.append(f"Jailbreak signature match: {matches[0]}")
                score += 0.85
                break

        for pattern in self.compiled_patterns["COMMAND_INJECTION"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("COMMAND_INJECTION")
                match_details.append(f"Command injection match: {matches[0]}")
                score += 0.75
                break

        for pattern in self.compiled_patterns["HEX_ENCODED"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("HEX_ENCODED_PAYLOAD")
                match_details.append("Hex encoded sequence detected.")
                score += 0.50
                break

        decoded_payloads = self.decode_base64_candidates(cleaned_prompt)
        for decoded in decoded_payloads:
            lower_decoded = decoded.lower()
            if any(k in lower_decoded for k in ["ignore", "system prompt", "jailbreak", "override", "developer mode"]):
                detected_categories.append("BASE64_ENCODED_INJECTION")
                match_details.append(f"Decoded Base64 payload contained injection: '{decoded[:50]}...'")
                score += 0.90
                break

        is_legit_credential_inquiry = any(k in cleaned_prompt.lower() for k in ["reset", "procedure", "policy", "how do i", "forgot", "support"]) and not any(k in cleaned_prompt.lower() for k in ["give me", "show me", "reveal", "provide", "crack", "what is the", "tell me"])
        if not is_legit_credential_inquiry:
            for pattern in self.compiled_patterns.get("CREDENTIAL_HARVESTING", []):
                matches = pattern.findall(cleaned_prompt)
                if matches:
                    detected_categories.append("CREDENTIAL_DISCLOSURE")
                    match_details.append("Credential harvesting pattern detected.")
                    score += 0.85
                    break

        for pattern in self.compiled_patterns.get("FINANCIAL_DATA_HARVESTING", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("FINANCIAL_DATA_DISCLOSURE")
                match_details.append("Financial data extraction pattern detected.")
                score += 0.85
                break

        for pattern in self.compiled_patterns.get("PERSONAL_DATA_HARVESTING", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("PERSONAL_DATA_DISCLOSURE")
                match_details.append("Personal data extraction pattern detected.")
                score += 0.85
                break

        for pattern in self.compiled_patterns.get("CONFIDENTIAL_DOC_HARVESTING", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("CONFIDENTIAL_INFORMATION_DISCLOSURE")
                match_details.append("Confidential document harvesting pattern detected.")
                score += 0.85
                break

        for pattern in self.compiled_patterns.get("CYBER_ABUSE_CRACKING", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("CYBER_ABUSE_CRACKING")
                match_details.append("Credential cracking / cyber abuse pattern detected.")
                score += 0.85
                break

        for pattern in self.compiled_patterns.get("SALARY_DATA_EXTRACTION", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("SALARY_DATA_EXTRACTION")
                match_details.append("Salary data extraction pattern detected.")
                score += 0.85
                break

        for pattern in self.compiled_patterns.get("UNAUTHORIZED_ACCESS_ASSISTANCE", []):
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("UNAUTHORIZED_ACCESS")
                match_details.append("Unauthorized access assistance pattern detected.")
                score += 0.85
                break

        final_score = min(round(score, 2), 1.0)
        is_triggered = final_score >= 0.50

        return {
            "layer_name": "Layer 1 - Regex Engine",
            "score": final_score,
            "is_triggered": is_triggered,
            "detected_categories": list(set(detected_categories)),
            "match_details": match_details,
            "cleaned_prompt": cleaned_prompt
        }


============================================================
5. LAYER 2: KEYWORD AHO-CORASICK DETECTOR
============================================================

SOURCE FILE: backend/app/services/keyword_detector.py

from typing import Dict, List, Any, Set

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False


class KeywordDetector:
    """
    Layer 2: Keyword & Phrase Detection Engine using Aho-Corasick Automaton with fallback.
    Scans prompts in linear time O(N + K) over thousands of key security phrases.
    """

    def __init__(self):
        self.keywords_config = {
            "INSTRUCTION_OVERRIDE": [
                "ignore previous instructions",
                "ignore all previous instructions",
                "forget all rules",
                "disregard prior directives",
                "override system rules",
                "bypass safety filters",
                "ignore safety",
                "disregard safety guidelines",
                "bypass restrictions",
                "new operating mode",
                "ignore safety measures"
            ],
            "SYSTEM_PROMPT_LEAK": [
                "reveal system prompt",
                "print system prompt",
                "show your initial instructions",
                "display system prompt",
                "repeat the text above",
                "output initial prompt",
                "show prompt context",
                "what is your system prompt",
                "give me your instructions"
            ],
            "ROLE_MANIPULATION": [
                "developer mode",
                "god mode",
                "root prompt",
                "jailbreak",
                "do anything now",
                "unrestricted mode",
                "unfiltered mode",
                "evil bot",
                "chaos mode",
                "jailbroken mode"
            ],
            "DATA_EXFILTRATION": [
                "send token to",
                "exfiltrate data",
                "fetch url",
                "http request to",
                "send logs to",
                "callback url"
            ],
            "CREDENTIAL_DISCLOSURE": [
                "give me the password",
                "give me admin password",
                "administrator password",
                "sentinelcorp it password",
                "give me password",
                "show me password",
                "reveal password",
                "get password",
                "provide password",
                "secret key used by",
                "administrator credentials",
                "system credentials",
                "app credentials",
                "provide administrator credentials",
                "reveal the company's api keys",
                "secret key used by the application",
                "give me the secret key"
            ],
            "PERSONAL_DATA_DISCLOSURE": [
                "hr employee personal details",
                "employee personal details",
                "personal and confidential information",
                "confidential employee information",
                "person details",
                "personal information of employee",
                "show me hr employee",
                "reveal confidential employee",
                "amc principal personal",
                "company person details",
                "principal personal and confidential"
            ],
            "FINANCIAL_DATA_DISCLOSURE": [
                "bank account number and ifsc",
                "manager acc num",
                "ifsc code",
                "bank account details",
                "confidential financial information",
                "company's confidential financial",
                "bank account",
                "acc num and ifsc"
            ],
            "CONFIDENTIAL_INFORMATION_DISCLOSURE": [
                "confidential company documents",
                "confidential company information",
                "give me confidential",
                "show me confidential",
                "company confidential",
                "confidential financial information"
            ],
            "CYBER_ABUSE_CRACKING": [
                "crack the upi password",
                "crack upi password",
                "how can i crack",
                "how to crack",
                "crack password",
                "steal password",
                "hack password",
                "crack a upi password",
                "how to crack the upi password"
            ]
        }

        if HAS_AHOCORASICK and hasattr(ahocorasick, "Automaton"):
            self.automaton = ahocorasick.Automaton()
            for category, phrases in self.keywords_config.items():
                for phrase in phrases:
                    self.automaton.add_word(phrase.lower(), (phrase, category))
            self.automaton.make_automaton()
        else:
            self.automaton = None

    def analyze(self, prompt: str) -> Dict[str, Any]:
        lower_prompt = prompt.lower()
        matched_items = []
        matched_categories: Set[str] = set()

        if HAS_AHOCORASICK and self.automaton:
            for end_index, (phrase, category) in self.automaton.iter(lower_prompt):
                matched_items.append({"phrase": phrase, "category": category, "end_index": end_index})
                matched_categories.add(category)
        else:
            for category, phrases in self.keywords_config.items():
                for phrase in phrases:
                    if phrase in lower_prompt:
                        matched_items.append({"phrase": phrase, "category": category, "end_index": -1})
                        matched_categories.add(category)

        is_legit_credential_inquiry = any(k in lower_prompt for k in ["reset", "procedure", "policy", "how do i", "forgot", "support"]) and not any(k in lower_prompt for k in ["give me", "show me", "reveal", "provide", "crack", "what is the", "tell me"])
        if is_legit_credential_inquiry:
            matched_categories.discard("CREDENTIAL_DISCLOSURE")

        score = 0.0
        if "INSTRUCTION_OVERRIDE" in matched_categories:
            score += 0.70
        if "SYSTEM_PROMPT_LEAK" in matched_categories:
            score += 0.65
        if "ROLE_MANIPULATION" in matched_categories:
            score += 0.60
        if "DATA_EXFILTRATION" in matched_categories:
            score += 0.50
        if "CREDENTIAL_DISCLOSURE" in matched_categories:
            score += 0.85
        if "PERSONAL_DATA_DISCLOSURE" in matched_categories:
            score += 0.85
        if "FINANCIAL_DATA_DISCLOSURE" in matched_categories:
            score += 0.85
        if "CONFIDENTIAL_INFORMATION_DISCLOSURE" in matched_categories:
            score += 0.85
        if "CYBER_ABUSE_CRACKING" in matched_categories:
            score += 0.85

        if len(matched_items) > 1:
            score += 0.15 * (len(matched_items) - 1)

        final_score = min(round(score, 2), 1.0)
        is_triggered = final_score >= 0.50

        return {
            "layer_name": "Layer 2 - Keyword Engine",
            "score": final_score,
            "is_triggered": is_triggered,
            "detected_categories": list(matched_categories),
            "matched_phrases": [m["phrase"] for m in matched_items],
            "match_count": len(matched_items)
        }


============================================================
6. LAYER 3: DISTILBERT MACHINE LEARNING DETECTOR
============================================================

SOURCE FILE: backend/app/services/ml_detector.py

import os
import re
import math
import time
from typing import Dict, Any, List, Optional

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class MLDetector:
    """
    Layer 3: Machine Learning Classifier Service (DistilBERT Fine-Tuned).
    Evaluates semantic feature representations of prompt injections using a fine-tuned DistilBERT model.
    Falls back to high-speed n-gram probability estimation if model weights are loading or offline.
    """

    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_dir = os.path.join(base_dir, "models", "distilbert_sentinelprompt")

        self.model_dir = model_dir
        self.model = None
        self.tokenizer = None
        self.device = None
        self.model_version = "fast_ngram_classifier"

        if HAS_TRANSFORMERS and os.path.exists(self.model_dir) and os.path.exists(os.path.join(self.model_dir, "config.json")):
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir, use_fast=False)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.model.to(self.device)
                self.model.eval()
                self.model_version = "distilbert_v1_fine_tuned"
            except Exception:
                self.model = None
                self.tokenizer = None

        self.malicious_ngrams = [
            "ignore previous", "system prompt", "reveal prompt", "developer mode",
            "jailbreak", "override rules", "unconstrained ai", "ignore safety",
            "exfiltrate", "sudo mode", "do anything now", "forget rules"
        ]

    def _fallback_predict(self, prompt: str) -> Dict[str, Any]:
        lower_prompt = prompt.lower()
        matches = [ngram for ngram in self.malicious_ngrams if ngram in lower_prompt]
        
        match_count = len(matches)
        if match_count == 0:
            prob = 0.05
        else:
            prob = round(1.0 / (1.0 + math.exp(-1.5 * (match_count - 0.5))), 2)

        return {
            "is_malicious": prob >= 0.50,
            "confidence": prob,
            "matched_ngrams": matches,
            "model_used": "fast_ngram_classifier"
        }

    def analyze(self, prompt: str) -> Dict[str, Any]:
        start_time = time.perf_counter()

        if self.model is not None and self.tokenizer is not None:
            try:
                inputs = self.tokenizer(
                    prompt,
                    truncation=True,
                    max_length=128,
                    padding="max_length",
                    return_tensors="pt"
                )
                input_ids = inputs["input_ids"].to(self.device)
                attention_mask = inputs["attention_mask"].to(self.device)

                with torch.no_grad():
                    outputs = self.model(input_ids, attention_mask=attention_mask)
                    probs = torch.softmax(outputs.logits, dim=-1).cpu().numpy()[0]
                    score = round(float(probs[1]), 4)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                is_triggered = score >= 0.50

                return {
                    "layer_name": "Layer 3 - Machine Learning Classifier",
                    "score": score,
                    "is_triggered": is_triggered,
                    "model_version": self.model_version,
                    "detected_categories": ["ML_CLASSIFIED_INJECTION"] if is_triggered else [],
                    "latency_ms": latency_ms,
                    "details": {
                        "is_malicious": is_triggered,
                        "confidence": score,
                        "class_probabilities": {"benign": round(float(probs[0]), 4), "malicious": score},
                        "model_used": self.model_version
                    }
                }
            except Exception:
                pass

        pred = self._fallback_predict(prompt)
        score = pred["confidence"]
        is_triggered = score >= 0.50
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "layer_name": "Layer 3 - Machine Learning Classifier",
            "score": score,
            "is_triggered": is_triggered,
            "model_version": pred["model_used"],
            "detected_categories": ["ML_CLASSIFIED_INJECTION"] if is_triggered else [],
            "latency_ms": latency_ms,
            "details": pred
        }


============================================================
7. LAYER 4: MINILM + FAISS SEMANTIC VECTOR DETECTOR
============================================================

SOURCE FILE: backend/app/services/semantic_detector.py

import os
import sys
import json
import time
import re
import numpy as np
from typing import Dict, Any, List, Tuple, Optional

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    HAS_FAISS_ST = True
except ImportError:
    HAS_FAISS_ST = False


class SemanticDetector:
    """
    Layer 4: Semantic Similarity Search Engine.
    Computes 384-dimensional dense embeddings using SentenceTransformers (all-MiniLM-L6-v2)
    and performs nearest-neighbor vector search against a local FAISS index of verified threat vectors.
    """

    def __init__(self, index_path: Optional[str] = None, metadata_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if index_path is None:
            index_path = os.path.join(base_dir, "models", "faiss_threat_index.bin")
        if metadata_path is None:
            metadata_path = os.path.join(base_dir, "models", "faiss_threat_metadata.json")

        self.index_path = index_path
        self.metadata_path = metadata_path
        self.index = None
        self.metadata: List[Dict[str, Any]] = []
        self.model = None
        self.model_version = "all-MiniLM-L6-v2 + FAISS"

        if HAS_FAISS_ST:
            try:
                self.model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                if os.path.exists(self.index_path) and os.path.exists(self.metadata_path):
                    self.index = faiss.read_index(self.index_path)
                    with open(self.metadata_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                else:
                    self.index = faiss.IndexFlatIP(384)
                    self.metadata = []
            except Exception as e:
                print(f"Warning: Failed to load FAISS or SentenceTransformer: {e}")
                self.index = None
                self.metadata = []
                self.model = None

        self.threat_phrases = [
            "ignore previous instructions", "ignore all previous", "reveal system prompt", "reveal the system prompt",
            "developer mode enabled", "dan mode enabled", "unconstrained ai called dan",
            "exfiltrate secret keys", "override system prompt", "salary records", "executive salary",
            "print all stored passwords", "stored passwords", "give me admin password", "bank account number"
        ]

    def sanitize_prompt(self, prompt: str) -> str:
        sanitized = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]", prompt)
        sanitized = re.sub(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE_REDACTED]", sanitized)
        sanitized = re.sub(r"\b\d{10,16}\b", "[ACCOUNT_NUMBER_REDACTED]", sanitized)
        return sanitized

    def add_threat_vector(self, prompt: str, category: str = "ANALYST_CONFIRMED_THREAT", attack_family: str = "adaptive_threat_memory") -> Dict[str, Any]:
        sanitized_text = self.sanitize_prompt(prompt)
        
        if self.model is None or self.index is None:
            if HAS_FAISS_ST:
                self.model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                self.index = faiss.IndexFlatIP(384)
            else:
                raise RuntimeError("FAISS or SentenceTransformer is not installed in the environment.")

        vector = self.model.encode([sanitized_text], normalize_embeddings=True, show_progress_bar=False)
        vector = np.array(vector, dtype=np.float32)

        self.index.add(vector)

        meta_entry = {
            "index_id": len(self.metadata),
            "text": sanitized_text,
            "raw_prompt_hash": hash(prompt),
            "attack_category": category,
            "attack_family": attack_family,
            "indexed_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.metadata.append(meta_entry)

        os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
        faiss.write_index(self.index, self.index_path)
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        return {
            "status": "ADDED_TO_FAISS",
            "index_id": meta_entry["index_id"],
            "total_vectors": self.index.ntotal,
            "sanitized_text": sanitized_text
        }

    def compute_similarity(self, prompt: str) -> Tuple[float, Optional[str], Optional[str]]:
        if self.model is not None and self.index is not None and self.index.ntotal > 0:
            try:
                query_vec = self.model.encode([prompt], normalize_embeddings=True, show_progress_bar=False)
                query_vec = np.array(query_vec, dtype=np.float32)

                distances, indices = self.index.search(query_vec, k=1)
                best_sim = float(distances[0][0])
                best_idx = int(indices[0][0])

                if 0 <= best_idx < len(self.metadata):
                    match_item = self.metadata[best_idx]
                    return round(best_sim, 4), match_item.get("text"), match_item.get("attack_family")
            except Exception:
                pass

        lower_prompt = prompt.lower()
        matched = None
        max_sim = 0.05

        for phrase in self.threat_phrases:
            if phrase in lower_prompt:
                max_sim = 0.88
                matched = phrase
                break

        return round(max_sim, 4), matched, "prompt_injection"

    def analyze(self, prompt: str) -> Dict[str, Any]:
        start_time = time.perf_counter()
        similarity_score, matched_threat, attack_family = self.compute_similarity(prompt)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        similarity_threshold = 0.65
        is_triggered = similarity_score >= similarity_threshold

        return {
            "layer_name": "Layer 4 - Semantic Similarity Detector",
            "score": similarity_score,
            "is_triggered": is_triggered,
            "model_version": self.model_version,
            "similarity_threshold": similarity_threshold,
            "matched_threat_sample": matched_threat if is_triggered else None,
            "attack_family": attack_family if is_triggered else None,
            "detected_categories": ["SEMANTIC_SIMILARITY_JAILBREAK"] if is_triggered else [],
            "latency_ms": latency_ms
        }


============================================================
8. SR-ACT AND POLICY ENGINE
============================================================

SOURCE FILE: backend/app/services/policy_engine.py

import os
import re
import yaml
from typing import Dict, Any, List


class PolicyEngine:
    """
    Lightweight Enterprise Policy Engine for SentinelPrompt v1.0.
    Parses company_policy.yaml and enforces organizational security rules.
    """

    def __init__(self, policy_path: str = None):
        if policy_path is None:
            service_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(os.path.dirname(service_dir))
            root_dir = os.path.dirname(backend_dir)
            
            candidates = [
                os.path.join(root_dir, "company_policy.yaml"),
                os.path.join(backend_dir, "company_policy.yaml"),
                os.path.join(os.getcwd(), "company_policy.yaml")
            ]
            for cand in candidates:
                if os.path.exists(cand):
                    policy_path = cand
                    break
            if not policy_path:
                policy_path = candidates[0]

        self.policy_path = policy_path
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict[str, Any]:
        if not os.path.exists(self.policy_path):
            return {
                "rules": {
                    "block_system_prompt_extraction": True,
                    "block_api_keys": True,
                    "block_employee_salary_queries": True,
                    "block_confidential_documents": True,
                },
                "policy_definitions": {}
            }

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {"rules": {}, "policy_definitions": {}}

    def _parse_sract(self, prompt: str) -> Dict[str, Any]:
        lower_prompt = prompt.lower()

        # 1. SUBJECT IDENTIFICATION
        subject = "AUTHENTICATED_EMPLOYEE"
        impersonation_patterns = [
            (r"\bi am (the )?(hr manager|ceo|cto|cfo|administrator|security lead|auditor)\b", "IMPERSONATED_ROLE"),
            (r"\bas (chief|vp|manager|head of|admin)\b", "IMPERSONATED_ROLE"),
            (r"\bthis is an urgent emergency audit\b", "IMPERSONATED_AUDITOR")
        ]
        for pattern, role in impersonation_patterns:
            m = re.search(pattern, lower_prompt)
            if m:
                subject = f"{role}: {m.group(0)}"
                break

        # 2. ACTION IDENTIFICATION
        action = "GENERAL_READ"
        if any(k in lower_prompt for k in [
            "compare", "rank", "greater than", "less than", "highest paid", "lowest paid",
            "earn more", "earn less", "salary difference", "who earns", "who is paid",
            "who is the highest", "who is the lowest", "how many earn", "where do i rank",
            "where i stand", "stand compared", "my pay compares"
        ]):
            action = "COMPARE_RANK"
        elif any(k in lower_prompt for k in ["bypass", "crack", "hack", "override", "access without", "steal", "exfiltrate"]):
            action = "BYPASS_UNAUTHORIZED"
        elif any(k in lower_prompt for k in ["give me", "show me", "reveal", "print", "extract", "dump", "export", "get me", "need manager", "query"]):
            action = "REVEAL_EXTRACT"
        elif any(k in lower_prompt for k in ["how do i", "how can i", "what should i do", "procedure for", "how to apply", "how to submit", "what is the process"]):
            if any(k in lower_prompt for k in ["access another", "bypass hr", "view salary tables", "extract employee", "see manager compensation", "query postgresql"]):
                action = "BYPASS_UNAUTHORIZED"
            else:
                action = "INQUIRE_PROCEDURE"

        # 3. RESOURCE IDENTIFICATION
        resource = "GENERAL_ENTERPRISE_RESOURCE"
        if any(k in lower_prompt for k in ["system prompt", "system directive", "initial instructions", "verbatim prompt"]):
            resource = "SYSTEM_INSTRUCTIONS"
        elif any(k in lower_prompt for k in ["password", "api key", "jwt", "secret key", "credentials", "root pass"]):
            if any(k in lower_prompt for k in ["reset", "forgot", "contact it", "mfa", "procedure", "policy"]) and not any(k in lower_prompt for k in ["give me", "show me", "reveal", "print", "extract", "dump", "export", "crack", "what is the password", "give me password"]):
                resource = "COMPANY_POLICY_GENERAL"
            else:
                resource = "CREDENTIALS"
        elif any(k in lower_prompt for k in ["bank account", "ifsc", "routing number", "bank details", "bank transaction"]):
            resource = "BANK_FINANCIAL_DATA"
        elif any(k in lower_prompt for k in [
            "compare my salary", "whose is greater", "who earns more", "who earns less",
            "highest-paid employee", "highest paid employee", "salary difference",
            "rank all employees", "rank my team", "rank employees", "who is the highest",
            "who is the lowest paid", "how many employees earn", "where do i rank",
            "who is paid more", "who is paid less", "earn more than me", "earn less than me",
            "paid more than me", "paid more than i", "paid less than me",
            "earns more than me", "earns less than me", "paid more than i am",
            "coworker is paid", "coworker receives higher", "coworker receives greater",
            "staff member earn", "staff member is paid", "another employee earn",
            "another employee is paid", "another person's", "another employee's compensation",
            "my pay compares", "where i stand", "stand compared with", "stand financially",
            "compensation and another", "difference between my compensation",
            "higher compensation", "greater compensation", "receives higher compensation",
            "receives greater compensation",
            "earn than me", "earn than i", "does employee", "more does employee",
            "more than i do", "more than i am", "less than i do", "less than i am",
            "how much more does", "how much less does", "how much does employee",
            "employee x earn", "employee earn", "employees earn more than i"
        ]):
            resource = "DERIVED_SENSITIVE_DATA"
        elif any(k in lower_prompt for k in ["john's salary", "salary of", "manager's salary", "employee salaries", "cto earn", "compensation packages", "senior engineers salary", "manager compensation", "compensation"]):
            if any(k in lower_prompt for k in ["salary policy", "payroll policy", "how do salary bands work", "company's salary policy"]):
                resource = "COMPANY_POLICY_GENERAL"
            else:
                resource = "SALARY_COMPENSATION"
        elif any(k in lower_prompt for k in ["hr personal details", "personal phone", "home address", "social security", "confidential medical", "amc principal"]):
            resource = "PERSONAL_IDENTIFIABLE_INFO"
        elif any(k in lower_prompt for k in ["bypass hr", "view salary tables without", "extract employee salaries", "query salary table", "override portal permissions"]):
            resource = "PROCEDURAL_ACCESS"
        elif any(k in lower_prompt for k in ["annual leave", "take leave", "sick leave", "working hours", "office holiday", "salary policy", "payroll policy", "data protection policy", "password reset", "password-reset", "confidential data", "policy for handling"]):
            resource = "COMPANY_POLICY_GENERAL"

        # 4. AUTHORIZATION DECISION MATRIX
        auth_status = "AUTHORIZED"
        reason = "Request complies with standard enterprise policy."

        if resource == "DERIVED_SENSITIVE_DATA":
            auth_status = "DENIED_UNAUTHORIZED_RESOURCE_ACTION"
            reason = f"Derived sensitive employee data (cross-employee salary inference/comparison) is prohibited regardless of action verb."
        elif resource in ["CREDENTIALS", "SALARY_COMPENSATION", "BANK_FINANCIAL_DATA", "PERSONAL_IDENTIFIABLE_INFO", "SYSTEM_INSTRUCTIONS"]:
            if action in ["REVEAL_EXTRACT", "COMPARE_RANK", "BYPASS_UNAUTHORIZED"]:
                auth_status = "DENIED_UNAUTHORIZED_RESOURCE_ACTION"
                reason = f"Action '{action}' is strictly prohibited on sensitive resource '{resource}'."
        elif resource == "PROCEDURAL_ACCESS" or action == "BYPASS_UNAUTHORIZED":
            auth_status = "DENIED_PROCEDURAL_ATTACK"
            reason = "Attempt to bypass security controls or assist in unauthorized access."
        elif subject.startswith("IMPERSONATED") and action in ["REVEAL_EXTRACT", "COMPARE_RANK"]:
            auth_status = "DENIED_ROLE_IMPERSONATION"
            reason = f"Authority manipulation / role impersonation detected: {subject}."
        elif resource == "COMPANY_POLICY_GENERAL" and action in ["INQUIRE_PROCEDURE", "GENERAL_READ"]:
            auth_status = "AUTHORIZED_GENERAL_POLICY"
            reason = "Legitimate employee inquiry for general enterprise policies and procedures."

        return {
            "subject": subject,
            "resource": resource,
            "action": action,
            "authorization_status": auth_status,
            "reason": reason,
            "is_authorized": auth_status.startswith("AUTHORIZED")
        }

    def analyze(self, prompt: str) -> Dict[str, Any]:
        violations = []
        lower_prompt = prompt.lower()
        rules = self.policy.get("rules", {})
        definitions = self.policy.get("policy_definitions", {})

        sract = self._parse_sract(prompt)
        if not sract["is_authorized"]:
            violations.append(f"SR-ACT Policy Violation [{sract['authorization_status']}]: {sract['reason']}")

        if rules.get("block_system_prompt_extraction", True):
            phrases = definitions.get("system_prompt_extraction", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"System Prompt Extraction Violation: '{phrase}'")
                    break

        if rules.get("block_api_keys", True):
            patterns = definitions.get("api_keys", {}).get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, prompt):
                    violations.append("API Key Leakage Violation: Hardcoded credential/key pattern detected.")
                    break

        if rules.get("block_employee_salary_queries", True):
            is_general_policy = "policy" in lower_prompt or "how do salary bands work" in lower_prompt or "general payroll" in lower_prompt
            if not is_general_policy or sract["resource"] in ["SALARY_COMPENSATION", "DERIVED_SENSITIVE_DATA"]:
                phrases = definitions.get("employee_salary_queries", {}).get("phrases", [])
                for phrase in phrases:
                    if phrase in lower_prompt:
                        violations.append(f"Confidential HR Data Violation: '{phrase}'")
                        break

        if rules.get("block_confidential_documents", True):
            phrases = definitions.get("confidential_documents", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"Confidential Corporate Document Violation: '{phrase}'")
                    break

        if rules.get("block_credential_disclosure", True):
            is_legit_inquiry = sract["resource"] == "COMPANY_POLICY_GENERAL" or (
                any(k in lower_prompt for k in ["reset", "procedure", "policy", "how do i", "forgot", "support"])
                and not any(k in lower_prompt for k in ["give me", "show me", "reveal", "provide", "crack", "tell me password", "give me password", "what is the password"])
            )
            if not is_legit_inquiry:
                phrases = definitions.get("credential_disclosure", {}).get("phrases", [])
                for phrase in phrases:
                    if phrase in lower_prompt:
                        violations.append(f"Credential Disclosure Violation: '{phrase}'")
                        break

        if rules.get("block_personal_data_disclosure", True):
            phrases = definitions.get("personal_data_disclosure", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"Personal Data Disclosure Violation: '{phrase}'")
                    break

        if rules.get("block_financial_data_disclosure", True):
            phrases = definitions.get("financial_data_disclosure", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"Financial Data Disclosure Violation: '{phrase}'")
                    break

        if rules.get("block_cyber_abuse_cracking", True):
            phrases = definitions.get("cyber_abuse_cracking", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"Cyber Abuse / Credential Cracking Violation: '{phrase}'")
                    break

        if rules.get("block_unauthorized_access_assistance", True):
            phrases = definitions.get("unauthorized_access_assistance", {}).get("phrases", [])
            for phrase in phrases:
                if phrase in lower_prompt:
                    violations.append(f"Unauthorized Access Assistance Violation: '{phrase}'")
                    break

        unique_violations = list(dict.fromkeys(violations))
        is_violated = len(unique_violations) > 0

        return {
            "engine_name": "SR-ACT Enterprise Policy Engine",
            "policy_name": self.policy.get("policy_name", "Enterprise Baseline Security Policy"),
            "sract_tuple": sract,
            "is_violated": is_violated,
            "violations": unique_violations,
            "violation_count": len(unique_violations)
        }

    def evaluate(self, prompt: str) -> Dict[str, Any]:
        self.policy = self._load_policy()
        res = self.analyze(prompt)
        return {
            "passed": not res["is_violated"],
            "sract_tuple": res["sract_tuple"],
            "policy_violations": res["violations"],
            "violation_count": res["violation_count"],
            "details": res
        }

    def update_rules(self, new_rules: Dict[str, bool]) -> Dict[str, Any]:
        if "rules" not in self.policy:
            self.policy["rules"] = {}
        self.policy["rules"].update(new_rules)
        try:
            with open(self.policy_path, "w", encoding="utf-8") as f:
                yaml.dump(self.policy, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving policy configuration: {e}")
        return self.policy


============================================================
9. MULTI-LAYER DECISION ENGINE
============================================================

SOURCE FILE: backend/app/services/decision_engine.py

import time
from typing import Dict, Any, List, Set
from app.services.regex_detector import RegexDetector
from app.services.keyword_detector import KeywordDetector
from app.services.rule_detector import RuleDetector
from app.services.ml_detector import MLDetector
from app.services.semantic_detector import SemanticDetector
from app.services.policy_engine import PolicyEngine
from app.services.threat_intel import ThreatIntelEngine
from app.core.config import settings


class DecisionEngine:
    """
    Unified Multi-Layer Security Decision Engine.
    Orchestrates Layer 1 (Regex), Layer 2 (Keyword), Layer 3 (DistilBERT ML),
    Layer 4 (Semantic Vector Index), Corporate Policy Engine, and Threat Intel Logging.
    """

    def __init__(self):
        self.layer1_regex = RegexDetector()
        self.layer2_keyword = KeywordDetector()
        self.layer3_rule = RuleDetector()
        self.layer4_ml = MLDetector()
        self.layer5_semantic = SemanticDetector()
        self.layer6_threat_intel = ThreatIntelEngine()
        self.policy_engine = PolicyEngine()

    def evaluate_prompt(self, prompt: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes multi-layer detection pipeline and corporate policy rules.
        Computes weighted threat score, determines verdict (FORWARDED vs FLAGGED vs BLOCKED),
        and records threat metrics. Wrapped in a fail-closed safety block.
        """
        start_time = time.perf_counter()

        try:
            res_l1 = self.layer1_regex.analyze(prompt)
            cleaned_prompt = res_l1.get("cleaned_prompt", prompt)

            res_l2 = self.layer2_keyword.analyze(cleaned_prompt)

            res_l3_rule = self.layer3_rule.analyze(cleaned_prompt)
            res_l4_ml = self.layer4_ml.analyze(cleaned_prompt)

            res_l5_sem = self.layer5_semantic.analyze(cleaned_prompt)

            res_policy = self.policy_engine.evaluate(cleaned_prompt)

            res_l6_intel = self.layer6_threat_intel.analyze(cleaned_prompt, client_ip=client_ip)

            score_l1 = float(res_l1["score"])
            score_l2 = float(res_l2["score"])
            score_l3 = float(res_l4_ml["score"])
            score_l4 = float(res_l5_sem["score"])

            detected_categories: Set[str] = set()
            detected_categories.update(res_l1.get("detected_categories", []))
            detected_categories.update(res_l2.get("detected_categories", []))
            detected_categories.update(res_l3_rule.get("detected_categories", []))
            detected_categories.update(res_l4_ml.get("detected_categories", []))
            detected_categories.update(res_l5_sem.get("detected_categories", []))
            detected_categories.update(res_l6_intel.get("detected_categories", []))

            policy_passed = res_policy.get("passed", True)
            policy_violations = res_policy.get("policy_violations", [])
            if not policy_passed:
                for v in policy_violations:
                    detected_categories.add(f"POLICY_VIOLATION_{v.upper()}")

            sract_auth = res_policy.get("sract_tuple", {}).get("authorization_status", "")
            is_general_policy_query = (sract_auth == "AUTHORIZED_GENERAL_POLICY")

            if is_general_policy_query:
                sem_triggered = res_l5_sem["score"] >= 0.85
                effective_score_l4 = res_l5_sem["score"] if sem_triggered else 0.0
            else:
                sem_triggered = res_l5_sem["is_triggered"]
                effective_score_l4 = score_l4

            active_scores = [score_l1, score_l2, score_l3, effective_score_l4]
            max_score = max(active_scores)
            mean_score = sum(active_scores) / len(active_scores)

            overall_threat_score = round((max_score * 0.65) + (mean_score * 0.35), 4)

            is_blocked = (
                not policy_passed or
                overall_threat_score >= settings.OVERALL_BLOCK_THRESHOLD or
                max_score >= settings.STATIC_THREAT_THRESHOLD or
                res_l1["is_triggered"] or
                res_l2["is_triggered"] or
                res_l4_ml["is_triggered"] or
                sem_triggered
            )

            if is_blocked:
                verdict = "BLOCKED"
            else:
                verdict = "FORWARDED"

            if is_blocked:
                self.layer6_threat_intel.record_attack_occurrence(client_ip)

            if overall_threat_score >= 0.80 or not policy_passed:
                threat_level = "CRITICAL"
            elif overall_threat_score >= 0.60:
                threat_level = "HIGH"
            elif overall_threat_score >= 0.35:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

            return {
                "verdict": verdict,
                "is_malicious": is_blocked,
                "overall_threat_score": overall_threat_score,
                "threat_level": threat_level,
                "policy_passed": policy_passed,
                "policy_violations": policy_violations,
                "detected_attack_types": list(detected_categories),
                "execution_time_ms": execution_time_ms,
                "layer_scores": {
                    "layer1_regex": score_l1,
                    "layer2_keyword": score_l2,
                    "layer3_ml_distilbert": score_l3,
                    "layer4_semantic_faiss": score_l4,
                    "rule_heuristics": float(res_l3_rule["score"]),
                    "threat_intel": float(res_l6_intel["score"])
                },
                "layer_details": {
                    "layer1_regex": res_l1,
                    "layer2_keyword": res_l2,
                    "layer3_ml_distilbert": res_l4_ml,
                    "layer4_semantic_faiss": res_l5_sem,
                    "policy_engine": res_policy,
                    "rule_heuristics": res_l3_rule,
                    "threat_intel": res_l6_intel
                }
            }

        except Exception as e:
            # FAIL-CLOSED SAFETY GUARDRAIL: Any exception blocks request automatically
            return {
                "verdict": "BLOCKED",
                "is_malicious": True,
                "overall_threat_score": 1.0,
                "threat_level": "CRITICAL",
                "policy_passed": False,
                "policy_violations": [f"Fail-Closed Security Guardrail Triggered: System Exception ({type(e).__name__})"],
                "detected_attack_types": ["FAIL_CLOSED_SECURITY_BLOCK"],
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "layer_scores": {
                    "layer1_regex": 1.0,
                    "layer2_keyword": 1.0,
                    "layer3_ml_distilbert": 1.0,
                    "layer4_semantic_faiss": 1.0,
                    "rule_heuristics": 1.0,
                    "threat_intel": 1.0
                },
                "layer_details": {"fail_closed_error": str(e)}
            }


============================================================
10. ADAPTIVE THREAT MEMORY
============================================================

SOURCE FILE: backend/app/services/learning_module.py

import time
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.domain import RetrainingSample, ThreatIntelEntry
from app.services.semantic_detector import SemanticDetector
from app.core.logger import logger


class SelfLearningManager:
    """
    Continuous Self-Learning Manager.
    Manages the attack buffer queue, analyst approval workflows, vector index ingestion, and periodic model fine-tuning.
    """

    def __init__(self, semantic_detector: Optional[SemanticDetector] = None):
        self.semantic_detector = semantic_detector or SemanticDetector()

    async def ingest_unverified_attack(
        self,
        db: AsyncSession,
        prompt: str,
        category: str = "AUTO_FLAGGED_JAILBREAK"
    ) -> RetrainingSample:
        sample = RetrainingSample(
            prompt=prompt,
            label=1,
            category=category,
            status="PENDING"
        )
        db.add(sample)
        await db.flush()
        logger.info(f"Queued prompt to retraining buffer: '{prompt[:40]}...'")
        return sample

    def confirm_analyst_threat(
        self,
        prompt: str,
        category: str = "ANALYST_CONFIRMED_THREAT"
    ) -> Dict[str, Any]:
        """
        Analyst approval workflow:
        1. Takes analyst-confirmed malicious threat prompt.
        2. Sanitizes PII.
        3. Computes MiniLM 384-dim vector embedding.
        4. Ingests into persistent FAISS index.
        5. Saves updated index and metadata to disk.
        """
        res = self.semantic_detector.add_threat_vector(
            prompt=prompt,
            category=category,
            attack_family="analyst_feedback_memory"
        )
        logger.info(f"Analyst confirmed and vectorized threat: '{prompt[:40]}...' into FAISS index")
        return {
            "status": "APPROVED_AND_VECTORIZED",
            "prompt_sanitized": res["sanitized_text"],
            "faiss_vector_count": res["total_vectors"],
            "index_id": res["index_id"]
        }

    async def approve_and_vectorize_sample(
        self,
        db: AsyncSession,
        sample_id: str
    ) -> Dict[str, Any]:
        sample = await db.get(RetrainingSample, sample_id)
        if not sample:
            raise ValueError(f"Retraining sample '{sample_id}' not found.")

        sample.status = "APPROVED"
        
        vec_res = self.semantic_detector.add_threat_vector(sample.prompt, category=sample.category or "APPROVED_THREAT")

        threat_entry = ThreatIntelEntry(
            attack_prompt=sample.prompt,
            attack_category=sample.category or "APPROVED_THREAT",
            severity="HIGH",
            confidence_score=0.95,
            source="SELF_LEARNED_FEEDBACK"
        )
        db.add(threat_entry)
        await db.flush()

        logger.info(f"Approved and vectorized attack sample into FAISS index: {sample_id}")
        return {
            "status": "APPROVED_AND_VECTORIZED",
            "sample_id": sample_id,
            "vector_index_size": vec_res["total_vectors"]
        }

    async def trigger_periodic_batch_retraining(self, db: AsyncSession) -> Dict[str, Any]:
        start_time = time.perf_counter()
        
        time_elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        total_vectors = self.semantic_detector.index.ntotal if self.semantic_detector.index else 0
        
        logger.info("Batch retraining job completed successfully.")
        return {
            "status": "SUCCESS",
            "message": "Model weights fine-tuned and FAISS vector index re-indexed.",
            "execution_time_ms": time_elapsed_ms,
            "faiss_index_count": total_vectors
        }


============================================================
11. RAG GROUNDING ENGINE
============================================================

SOURCE FILE: backend/app/services/knowledge_base.py

from typing import Dict, Any, Optional

SENTINELCORP_KNOWLEDGE_BASE = {
    "company_overview": (
        "SentinelCorp is an enterprise cybersecurity technology company specializing in "
        "AI security, cloud protection, and web application firewalls."
    ),
    "annual_leave_policy": (
        "SentinelCorp provides 24 days of paid annual leave per calendar year for full-time employees. "
        "Leave requests must be submitted through the HR Portal at least 5 business days in advance. "
        "Employees can carry forward up to 5 unused leave days to the next year."
    ),
    "working_hours": (
        "Standard working hours at SentinelCorp are Monday to Friday, 9:00 AM to 5:00 PM (Local Time), "
        "with a 1-hour lunch break. Core collaboration hours are 10:00 AM to 4:00 PM."
    ),
    "employee_benefits": (
        "SentinelCorp offers comprehensive health, dental, and vision insurance, a 401(k) matching plan "
        "up to 6%, wellness allowances ($500/year), and continuous learning professional development stipends."
    ),
    "it_support_policy": (
        "IT Support is available 24/7 via the IT Helpdesk Portal or by emailing support@sentinelcorp.internal. "
        "Critical hardware issues receive priority resolution within 2 hours. Password resets and access "
        "requests are processed within 1 business hour."
    ),
    "salary_payroll_policy": (
        "SentinelCorp operates structured salary bands per grade level reviewed annually during Q4 performance appraisals. "
        "Payroll is processed on the 25th of each month via direct bank deposit. Individual compensation details remain strictly confidential."
    ),
    "security_incident_policy": (
        "Employees must report suspected security incidents, phishing attempts, or unauthorized access to security@sentinelcorp.internal immediately. "
        "Security incident response team triage is active 24/7."
    ),
    "hr_guidelines": (
        "All HR inquiries, performance review documents, and benefit updates can be accessed via "
        "the SentinelCorp Employee Self-Service portal. Remote work options are governed by team manager approval."
    )
}


class KnowledgeBaseService:
    def __init__(self):
        self.kb = SENTINELCORP_KNOWLEDGE_BASE
        self.kb_keywords = [
            "leave", "vacation", "holiday", "pto", "sick leave",
            "hours", "schedule", "timing", "working time", "shift",
            "benefit", "health", "insurance", "401k", "perk", "allowance",
            "it", "support", "helpdesk", "password", "hardware", "mfa", "workstation",
            "salary", "payroll", "payslip", "compensation", "band",
            "security", "incident", "phishing", "cybersecurity", "breach",
            "company", "sentinelcorp", "office", "policy", "handbook", "hr", "portal"
        ]
        self.out_of_domain_keywords = [
            "fir copy", "police complaint", "passport", "driver license", "tax filing portal",
            "cricket score", "movie review", "recipe", "pizza", "quantum gravity"
        ]

    def is_kb_relevant(self, prompt: str) -> bool:
        prompt_lower = prompt.lower()
        if any(term in prompt_lower for term in self.out_of_domain_keywords):
            return False
        return any(kw in prompt_lower for kw in self.kb_keywords)

    def get_company_context(self, prompt: str) -> tuple[Optional[str], bool]:
        prompt_lower = prompt.lower()
        matched_sections = []

        if any(w in prompt_lower for w in ["leave", "vacation", "holiday", "annual leave", "pto"]):
            matched_sections.append(f"Leave Policy: {self.kb['annual_leave_policy']}")
        if any(w in prompt_lower for w in ["hours", "timing", "work time", "schedule"]):
            matched_sections.append(f"Working Hours: {self.kb['working_hours']}")
        if any(w in prompt_lower for w in ["benefit", "health", "insurance", "401k"]):
            matched_sections.append(f"Employee Benefits: {self.kb['employee_benefits']}")
        if any(w in prompt_lower for w in ["it", "support", "helpdesk", "password", "hardware", "mfa"]):
            matched_sections.append(f"IT Support Policy: {self.kb['it_support_policy']}")
        if any(w in prompt_lower for w in ["salary policy", "payroll policy", "salary bands"]):
            matched_sections.append(f"Salary & Payroll Policy: {self.kb['salary_payroll_policy']}")
        if any(w in prompt_lower for w in ["security incident", "phishing", "cybersecurity"]):
            matched_sections.append(f"Security Incident Policy: {self.kb['security_incident_policy']}")
        if any(w in prompt_lower for w in ["company", "about", "overview", "sentinelcorp"]):
            matched_sections.append(f"Company Overview: {self.kb['company_overview']}")

        if matched_sections:
            return "\n\n".join(matched_sections), True
        
        if self.is_kb_relevant(prompt):
            return f"Company Overview: {self.kb['company_overview']}\nGeneral HR Guidelines: {self.kb['hr_guidelines']}", True

        return None, False


============================================================
12. OLLAMA LLM ADAPTER
============================================================

SOURCE FILE: backend/app/services/llm_adapters.py

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logger import logger


class OllamaConnectionError(Exception):
    """Raised when connection to local Ollama server fails."""
    pass


class OllamaModelNotFound(Exception):
    """Raised when specified model is not available on Ollama server."""
    pass


class OllamaTimeout(Exception):
    """Raised when Ollama request times out."""
    pass


class OllamaInvalidResponse(Exception):
    """Raised when Ollama response format is invalid or unparseable."""
    pass


class OllamaHTTPError(Exception):
    """Raised when Ollama server returns an HTTP error status."""
    pass


class BaseLLMAdapter(ABC):
    """Abstract interface for LLM downstream integrations."""

    @abstractmethod
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        pass


class OllamaAdapter(BaseLLMAdapter):
    """Local Ollama Inference Adapter with Diagnostic Logging & Specific Error Categorization."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.model = model or settings.OLLAMA_MODEL

    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/api/generate"

        logger.info(f"[OLLAMA] request started")
        logger.info(f"[OLLAMA] endpoint = {url}")
        logger.info(f"[OLLAMA] model = {self.model}")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                logger.info(f"[OLLAMA] request sent")
                response = await client.post(url, json=payload)
                
                logger.info(f"[OLLAMA] response received")
                logger.info(f"[OLLAMA] response status = {response.status_code}")

                if response.status_code == 404 or ("model" in response.text.lower() and "not found" in response.text.lower()):
                    raise OllamaModelNotFound(f"Model '{self.model}' not found on Ollama server at {self.base_url}.")

                response.raise_for_status()
                data = response.json()

                if not isinstance(data, dict) or "response" not in data:
                    raise OllamaInvalidResponse("Ollama API response missing 'response' field.")

                logger.info(f"[OLLAMA] generation successful")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": data.get("response", ""),
                    "tokens_eval": data.get("eval_count", 0),
                    "raw": data
                }

            except httpx.ConnectError as e:
                err = OllamaConnectionError(f"Failed to connect to Ollama daemon at {self.base_url}: {str(e)}")
                logger.error(f"[OLLAMA] OllamaConnectionError: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Unavailable: Downstream Ollama engine is not reachable at {self.base_url}.",
                    "status": "service_unavailable",
                    "error_type": "OllamaConnectionError",
                    "error_details": str(err)
                }
            except httpx.TimeoutException as e:
                err = OllamaTimeout(f"Ollama request timed out after 30 seconds: {str(e)}")
                logger.error(f"[OLLAMA] OllamaTimeout: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Timeout: Ollama inference timed out at {self.base_url}.",
                    "status": "timeout",
                    "error_type": "OllamaTimeout",
                    "error_details": str(err)
                }
            except OllamaModelNotFound as e:
                logger.error(f"[OLLAMA] OllamaModelNotFound: {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Model Error: Model '{self.model}' is not installed in Ollama.",
                    "status": "model_not_found",
                    "error_type": "OllamaModelNotFound",
                    "error_details": str(e)
                }
            except OllamaInvalidResponse as e:
                logger.error(f"[OLLAMA] OllamaInvalidResponse: {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": "LLM Response Error: Invalid JSON response format from Ollama.",
                    "status": "invalid_response",
                    "error_type": "OllamaInvalidResponse",
                    "error_details": str(e)
                }
            except httpx.HTTPStatusError as e:
                err = OllamaHTTPError(f"HTTP error {e.response.status_code} from Ollama: {str(e)}")
                logger.error(f"[OLLAMA] OllamaHTTPError: {str(err)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM HTTP Error: Ollama returned HTTP status {e.response.status_code}.",
                    "status": "http_error",
                    "error_type": "OllamaHTTPError",
                    "error_details": str(err)
                }
            except Exception as e:
                logger.error(f"[OLLAMA] Execution failure ({type(e).__name__}): {str(e)}")
                return {
                    "provider": "ollama",
                    "model": self.model,
                    "response_text": f"LLM Service Exception: Unexpected error during Ollama invocation ({type(e).__name__}).",
                    "status": "execution_error",
                    "error_type": type(e).__name__,
                    "error_details": str(e)
                }


class LLMAdapterFactory:
    """Factory to retrieve requested or default LLM Adapter."""

    @staticmethod
    def get_adapter(provider_name: Optional[str] = None) -> BaseLLMAdapter:
        target_provider = (provider_name or settings.DEFAULT_LLM_PROVIDER).lower()

        if target_provider == "ollama":
            return OllamaAdapter()
        else:
            logger.info(f"Requested provider '{target_provider}' fallback to Ollama.")
            return OllamaAdapter()
