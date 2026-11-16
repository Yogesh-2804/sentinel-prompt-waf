from datetime import datetime
import uuid
from sqlalchemy import Column, String, Float, Boolean, DateTime, Integer, Text, JSON, ForeignKey
from app.db.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="admin", nullable=False) # admin, security_analyst, api_user
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SecurityEventLog(Base):
    __tablename__ = "security_event_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String(50), index=True, nullable=True)
    user_id = Column(String(36), nullable=True)
    prompt_hash = Column(String(64), index=True, nullable=False)
    prompt_snippet = Column(Text, nullable=False)
    is_malicious = Column(Boolean, index=True, nullable=False)
    action_taken = Column(String(20), nullable=False) # BLOCKED, FORWARDED
    threat_score = Column(Float, nullable=False)
    layer_scores = Column(JSON, nullable=False) # {"layer1": 0.0, "layer2": 1.0, ...}
    detected_attack_types = Column(JSON, nullable=True) # ["JAILBREAK", "BASE64_PAYLOAD"]
    llm_provider = Column(String(50), nullable=True)
    execution_time_ms = Column(Float, nullable=False)


class ThreatIntelEntry(Base):
    __tablename__ = "threat_intel_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attack_prompt = Column(Text, nullable=False)
    attack_category = Column(String(100), index=True, nullable=False)
    severity = Column(String(20), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    confidence_score = Column(Float, default=1.0)
    source = Column(String(50), default="AUTO_LEARNED") # PUBLIC_DATASET, AUTO_LEARNED, MANUAL_INGEST
    created_at = Column(DateTime, default=datetime.utcnow)


class RetrainingSample(Base):
    __tablename__ = "retraining_samples"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    prompt = Column(Text, nullable=False)
    label = Column(Integer, nullable=False) # 1 = Malicious, 0 = Safe
    category = Column(String(100), nullable=True)
    status = Column(String(20), default="PENDING") # PENDING, APPROVED, REJECTED, TRAINED
    added_at = Column(DateTime, default=datetime.utcnow)
