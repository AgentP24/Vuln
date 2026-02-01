"""
VulnGuard AI - Configuration Settings
Centralized configuration using Pydantic Settings
"""
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class ScannerSettings(BaseSettings):
    """Scanner platform API configurations"""

    # Qualys
    qualys_api_url: str = "https://qualysapi.qualys.com"
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_poll_interval: int = 900  # 15 minutes

    # Tenable
    tenable_api_url: str = "https://cloud.tenable.com"
    tenable_access_key: Optional[str] = None
    tenable_secret_key: Optional[str] = None
    tenable_poll_interval: int = 900

    # Rapid7
    rapid7_api_url: str = "https://insightvm.example.com"
    rapid7_api_key: Optional[str] = None
    rapid7_poll_interval: int = 900

    # IBM Guardium
    guardium_api_url: str = "https://guardium.example.com"
    guardium_username: Optional[str] = None
    guardium_password: Optional[str] = None
    guardium_poll_interval: int = 1800  # 30 minutes

    class Config:
        env_prefix = "SCANNER_"


class AnsibleSettings(BaseSettings):
    """Ansible Tower/AWX configuration"""

    tower_url: str = "https://ansible-tower.example.com"
    tower_token: Optional[str] = None
    tower_verify_ssl: bool = True
    default_inventory: str = "production"
    check_mode_required_tiers: List[str] = ["tier1", "tier2"]

    class Config:
        env_prefix = "ANSIBLE_"


class GuardrailSettings(BaseSettings):
    """Business guardrails configuration - THESE ARE NON-NEGOTIABLE"""

    # Business hours (no production changes during these times)
    business_hours_start: str = "08:00"
    business_hours_end: str = "18:00"
    business_hours_tz: str = "America/New_York"

    # Asset tier rules
    tier1_auto_approve: bool = False  # NEVER set to True
    tier1_requires_rollback: bool = True

    # High-value system thresholds
    high_value_transaction_threshold: int = 1_000_000_000  # $1B daily
    min_maintenance_window_minutes: int = 120  # For high-value systems

    # Check mode requirements
    check_mode_required_tiers: List[str] = ["tier1", "tier2"]

    # Approval SLAs (hours)
    critical_approval_sla: int = 4
    high_approval_sla: int = 24
    medium_approval_sla: int = 72
    low_approval_sla: int = 168  # 1 week

    class Config:
        env_prefix = "GUARDRAIL_"


class DatabaseSettings(BaseSettings):
    """Database configuration"""

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "vulnguard"
    postgres_password: str = "vulnguard_secret"
    postgres_db: str = "vulnguard"

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # Vector DB for RAG
    chromadb_host: str = "localhost"
    chromadb_port: int = 8000

    @property
    def postgres_url(self) -> str:
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    class Config:
        env_prefix = "DB_"


class AISettings(BaseSettings):
    """AI/LLM configuration"""

    anthropic_api_key: Optional[str] = None
    model_name: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.1  # Low temperature for deterministic responses

    # Embedding model for RAG
    embedding_model: str = "all-MiniLM-L6-v2"

    class Config:
        env_prefix = "AI_"


class Settings(BaseSettings):
    """Main application settings"""

    app_name: str = "VulnGuard AI"
    app_version: str = "1.0.0-mvp"
    debug: bool = False

    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # JWT
    jwt_secret: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Sub-settings
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    ansible: AnsibleSettings = Field(default_factory=AnsibleSettings)
    guardrails: GuardrailSettings = Field(default_factory=GuardrailSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    ai: AISettings = Field(default_factory=AISettings)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()
