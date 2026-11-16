from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.db.session import get_db
from app.db.repositories import SecurityLogRepository
from app.api.deps import get_current_admin

router = APIRouter(prefix="/dashboard", tags=["Dashboard Telemetry"])


@router.get("/stats")
async def get_dashboard_statistics(
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    repo = SecurityLogRepository(db)
    stats = await repo.get_dashboard_stats()
    return stats


@router.get("/logs")
async def get_recent_security_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    repo = SecurityLogRepository(db)
    logs = await repo.get_recent_logs(limit=limit)
    return logs


@router.get("/research-analytics")
async def get_research_analytics(admin: str = Depends(get_current_admin)):
    """Returns empirical benchmark evaluation metrics from evaluation_results.json."""
    import os, json
    curr_file = os.path.abspath(__file__)
    endpoint_dir = os.path.dirname(curr_file)
    api_dir = os.path.dirname(endpoint_dir)
    app_dir = os.path.dirname(api_dir)
    backend_dir = os.path.dirname(app_dir)
    root_dir = os.path.dirname(backend_dir)
    
    candidates = [
        os.path.join(backend_dir, "data", "reports", "evaluation_results.json"),
        os.path.join(root_dir, "backend", "data", "reports", "evaluation_results.json"),
        os.path.join(os.getcwd(), "backend", "data", "reports", "evaluation_results.json"),
        os.path.join(os.getcwd(), "data", "reports", "evaluation_results.json")
    ]

    for cand in candidates:
        if os.path.exists(cand):
            with open(cand, "r", encoding="utf-8") as f:
                return json.load(f)

    return {"error": "Evaluation report file not found."}


@router.post("/threats/confirm")
async def confirm_threat_memory(
    payload: dict,
    admin: str = Depends(get_current_admin)
):
    """
    Analyst Threat Memory Gateway:
    Analyst confirms a newly identified malicious prompt payload.
    Redacts PII, generates 384-dim embedding, and appends to persistent FAISS threat vector memory.
    """
    from app.services.learning_module import SelfLearningManager
    prompt = payload.get("prompt")
    category = payload.get("category", "ANALYST_CONFIRMED_THREAT")
    if not prompt:
        return {"error": "Prompt field is required."}

    manager = SelfLearningManager()
    result = manager.confirm_analyst_threat(prompt, category=category)
    return result
