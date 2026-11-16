from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
from pydantic import BaseModel
from app.services.policy_engine import PolicyEngine
from app.api.deps import get_current_admin

router = APIRouter(prefix="/policies", tags=["Policy Management"])
policy_engine = PolicyEngine()

class PolicyUpdateRequest(BaseModel):
    rules: Dict[str, bool]

@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def get_active_policies(admin: str = Depends(get_current_admin)):
    """Returns current active corporate policies and rule toggles."""
    return {
        "policy_name": policy_engine.policy.get("policy_name", "Enterprise Baseline Security Policy"),
        "policy_version": policy_engine.policy.get("policy_version", "1.0"),
        "rules": policy_engine.policy.get("rules", {}),
        "policy_definitions": policy_engine.policy.get("policy_definitions", {})
    }

@router.put("", status_code=status.HTTP_200_OK)
@router.put("/", status_code=status.HTTP_200_OK)
async def update_policies(
    req: PolicyUpdateRequest,
    admin: str = Depends(get_current_admin)
):
    """Updates organizational policy rules and persists changes to company_policy.yaml."""
    updated = policy_engine.update_rules(req.rules)
    return {
        "status": "SUCCESS",
        "message": "Policy configuration successfully updated.",
        "rules": updated.get("rules", {})
    }
