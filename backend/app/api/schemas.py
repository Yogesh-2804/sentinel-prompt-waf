from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field


# Auth Schemas
class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    role: Optional[str] = "admin"


class UserLoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: Optional[str] = None
    role: str


# Scan & Chat Schemas
class PromptScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Prompt text to analyze for security threats.")
    user_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class PromptScanResponse(BaseModel):
    verdict: str # BLOCKED or FORWARDED
    is_malicious: bool
    overall_threat_score: float
    threat_level: str # LOW, MEDIUM, HIGH, CRITICAL
    detected_attack_types: List[str]
    execution_time_ms: float
    layer_scores: Dict[str, float]
    layer_details: Dict[str, Any]


class ChatGatewayRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="User prompt to inspect and forward to LLM if safe.")
    llm_provider: Optional[str] = Field("ollama", description="Target LLM provider (ollama, openai, etc.)")
    system_prompt: Optional[str] = None


class ChatGatewayResponse(BaseModel):
    security_eval: PromptScanResponse
    llm_response: Optional[Dict[str, Any]] = None
    security_report: Optional[Dict[str, Any]] = None
