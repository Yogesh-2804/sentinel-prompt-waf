from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine
from app.core.config import settings
from app.core.logger import logger

# Declarative Base
Base = declarative_base()

# SQLite fallback support if postgresql url is sqlite
is_sqlite = settings.DATABASE_URL.startswith("sqlite")

try:
    if is_sqlite:
        async_engine = create_async_engine(settings.DATABASE_URL, echo=False)
        sync_engine = create_engine(settings.DATABASE_URL_SYNC, echo=False)
    else:
        async_engine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20
        )
        sync_engine = create_engine(
            settings.DATABASE_URL_SYNC,
            pool_pre_ping=True
        )

    AsyncSessionLocal = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )
    SyncSessionLocal = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)
except Exception as e:
    logger.warning(f"Database connection error during initialization: {str(e)}")
    async_engine = None
    AsyncSessionLocal = None


async def get_db() -> AsyncGenerator:
    if AsyncSessionLocal is None:
        yield None
        return
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
