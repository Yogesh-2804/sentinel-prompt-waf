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
    # Initialize DB Tables if engine is configured
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

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
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
