import os
from typing import List, Union
from pydantic import field_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseSettings
    SettingsConfigDict = None


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelPrompt WAF"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    
    # Auth Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sentinel-jwt-signing-secret-key-env")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Admin Credentials (Loaded via Environment Variables)
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "SentinelAdminPass2026!")
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"
    DATABASE_URL_SYNC: str = "sqlite:///./sentinel.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # LLM Gateway Config
    DEFAULT_LLM_PROVIDER: str = "ollama"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "tinyllama")
    
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-flash"
    
    CLAUDE_API_KEY: str = ""
    CLAUDE_MODEL: str = "claude-3-haiku-20240307"

    # Threat Engine Thresholds
    STATIC_THREAT_THRESHOLD: float = 0.70
    ML_THREAT_THRESHOLD: float = 0.65
    SEMANTIC_SIMILARITY_THRESHOLD: float = 0.85
    OVERALL_BLOCK_THRESHOLD: float = 0.60

    # Vector Storage
    FAISS_INDEX_PATH: str = "./data/faiss_index.bin"
    EMBEDDING_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    if SettingsConfigDict:
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            case_sensitive=True,
            extra="ignore"
        )
    else:
        class Config:
            env_file = ".env"
            case_sensitive = True


settings = Settings()
