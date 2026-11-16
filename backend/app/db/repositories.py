from typing import List, Optional
import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from app.models.domain import User, SecurityEventLog, ThreatIntelEntry, RetrainingSample


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user


class SecurityLogRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        return hashlib.sha256(prompt.encode('utf-8')).hexdigest()

    async def log_event(
        self,
        prompt: str,
        is_malicious: bool,
        action_taken: str,
        threat_score: float,
        layer_scores: dict,
        detected_attack_types: List[str],
        execution_time_ms: float,
        client_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        llm_provider: Optional[str] = None
    ) -> SecurityEventLog:
        prompt_snippet = prompt[:200] + ("..." if len(prompt) > 200 else "")
        event = SecurityEventLog(
            client_ip=client_ip,
            user_id=user_id,
            prompt_hash=self.hash_prompt(prompt),
            prompt_snippet=prompt_snippet,
            is_malicious=is_malicious,
            action_taken=action_taken,
            threat_score=threat_score,
            layer_scores=layer_scores,
            detected_attack_types=detected_attack_types,
            llm_provider=llm_provider,
            execution_time_ms=execution_time_ms
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_recent_logs(self, limit: int = 50) -> List[SecurityEventLog]:
        stmt = select(SecurityEventLog).order_by(SecurityEventLog.timestamp.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_dashboard_stats(self) -> dict:
        total_stmt = select(func.count(SecurityEventLog.id))
        blocked_stmt = select(func.count(SecurityEventLog.id)).where(SecurityEventLog.is_malicious == True)
        avg_latency_stmt = select(func.avg(SecurityEventLog.execution_time_ms))
        
        total_res = await self.session.execute(total_stmt)
        blocked_res = await self.session.execute(blocked_stmt)
        avg_latency_res = await self.session.execute(avg_latency_stmt)
        
        total = total_res.scalar() or 0
        blocked = blocked_res.scalar() or 0
        avg_latency = avg_latency_res.scalar() or 0.0

        return {
            "total_requests": total,
            "blocked_threats": blocked,
            "safe_requests": total - blocked,
            "block_rate_percentage": round((blocked / total * 100), 2) if total > 0 else 0.0,
            "avg_latency_ms": round(avg_latency, 2)
        }
