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
    """
    Evaluates prompt safety across all active detection layers.
    Does NOT forward request to downstream LLM.
    """
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
    """
    Inline Adaptive Security Gateway:
    1. Inspects prompt in real-time across all detection layers & SR-ACT policy.
    2. If MALICIOUS / BLOCKED: Blocks request immediately BEFORE RAG & BEFORE Ollama. Returns security violation report (llm_response=None, RAG=0, Ollama=0).
    3. If SAFE / FORWARDED:
       - Query classification: GENERAL_KNOWLEDGE vs COMPANY_SPECIFIC vs UNGROUNDED_COMPANY_FACT.
       - General Knowledge: Forwards prompt to Ollama directly without mandatory company KB grounding.
       - Company Specific (Grounded): Forwards prompt to Ollama enriched with verified SentinelCorp KB context.
       - Ungrounded Company Fact: Returns grounded refusal without calling Ollama (Ollama=0).
    """
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

    # HARD SECURITY BOUNDARY 1: Blocked requests MUST return llm_response=None, RAG=0, Ollama=0
    if eval_res["is_malicious"] or eval_res["verdict"] == "BLOCKED":
        security_report = {
            "status": "BLOCKED",
            "message": "Security Notice: This request was blocked because it attempts to access restricted, confidential, or unauthorized information.",
            "threat_score": eval_res["overall_threat_score"],
            "threat_level": eval_res["threat_level"],
            "detected_attack_types": eval_res["detected_attack_types"],
            "recommendation": "Refactor prompt to remove jailbreak syntax, system override instructions, or unauthorized data requests."
        }
        return ChatGatewayResponse(security_eval=scan_dto, security_report=security_report, llm_response=None)

    # HARD SECURITY BOUNDARY 2: RAG Knowledge Base Classification AFTER Security Authorization
    kb_context, is_grounded, query_type = knowledge_base.get_company_context(req.prompt)

    # Path A: Safe General Knowledge Query -> Forward directly to Ollama without company KB requirement
    if query_type == "GENERAL_KNOWLEDGE":
        system_prompt = req.system_prompt or "You are a helpful AI Cybersecurity Assistant. Answer general technical and security questions clearly and accurately."
        adapter = LLMAdapterFactory.get_adapter(req.llm_provider)
        llm_res = await adapter.generate_response(req.prompt, system_prompt=system_prompt, security_verdict=eval_res["verdict"])
        return ChatGatewayResponse(security_eval=scan_dto, llm_response=llm_res)

    # Path B: Ungrounded Company Fact -> Grounded refusal without calling Ollama
    if not is_grounded or query_type == "UNGROUNDED_COMPANY_FACT":
        llm_res = {
            "provider": req.llm_provider,
            "model": "sentinelcorp-rag-grounding",
            "text": "I don't have that information in the current SentinelCorp knowledge base.",
            "response_text": "I don't have that information in the current SentinelCorp knowledge base.",
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "error": None
        }
        return ChatGatewayResponse(security_eval=scan_dto, llm_response=llm_res)

    # Path C: Grounded Company Specific Query -> Forward to Ollama enriched with verified KB context
    system_prompt = req.system_prompt or f"You are SentinelCorp's AI Assistant. Use the following SentinelCorp company knowledge to answer employee questions accurately:\n\n{kb_context}"
    adapter = LLMAdapterFactory.get_adapter(req.llm_provider)
    llm_res = await adapter.generate_response(req.prompt, system_prompt=system_prompt, security_verdict=eval_res["verdict"])

    return ChatGatewayResponse(security_eval=scan_dto, llm_response=llm_res)
