"""Centralized typed configuration management using Pydantic Settings."""

import os
from pathlib import Path
from functools import lru_cache
from typing import List, Literal, Optional
from pydantic import Field, AliasChoices, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration with strict validation and environment mapping."""

    model_config = SettingsConfigDict(
        env_file=[".env", str(Path(__file__).resolve().parent.parent / ".env")],
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    APP_NAME: str = "FootprintIQ - Digital Footprint Investigator"
    APP_VERSION: str = "2.0.0"
    APP_ENV: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = False

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    DATABASE_URL: str = Field(
        default="sqlite:///./footprintiq.db",
        description="SQLAlchemy database connection URI"
    )
    DB_FALLBACK_TO_SQLITE: bool = Field(
        default=True,
        description="Whether to fall back gracefully to SQLite if the primary database is unreachable"
    )

    SECRET_KEY: str = Field(
        default="dev-insecure-secret-key-change-in-production-only",
        description="Cryptographic signing key"
    )

    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["structured", "standard"] = "structured"

    ALLOWED_HOSTS: List[str] = ["127.0.0.1", "localhost"]
    FORWARDED_ALLOW_IPS: str = Field(
        default="127.0.0.1",
        description="IP addresses or subnets of trusted reverse proxies allowed to pass X-Forwarded headers",
    )

    # Authentication & Session Security Configuration
    SESSION_COOKIE_NAME: str = "footprintiq_session"
    SESSION_MAX_AGE_SECONDS: int = 14400  # 4 hours
    SESSION_COOKIE_SECURE: Optional[bool] = None  # Auto-configured based on APP_ENV if None
    SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    CSRF_COOKIE_NAME: str = "footprintiq_csrf"
    
    # Account Lockout & Throttling
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Self-Service User Registration Policy
    ALLOW_PUBLIC_SIGNUP: bool = Field(
        default=True,
        description="Whether self-service investigator registration is permitted"
    )
    DEFAULT_SIGNUP_ROLE: str = Field(
        default="investigator",
        description="Legacy compatibility setting; public registrations always receive the investigator role"
    )

    # Local-only demonstration identities. Provisioning is disabled unless explicitly enabled.
    DEMO_ACCOUNTS_ENABLED: bool = False
    DEMO_ADMIN_USERNAME: str = "footprint_admin_demo"
    DEMO_ADMIN_EMAIL: str = "admin@footprint.org"
    DEMO_ADMIN_PASSWORD: Optional[str] = None
    DEMO_INVESTIGATOR_USERNAME: str = "footprint_investigator_demo"
    DEMO_INVESTIGATOR_EMAIL: str = "investigator@footprint.org"
    DEMO_INVESTIGATOR_PASSWORD: Optional[str] = None

    # Passive Reconnaissance & Evidence Storage (Phase 4 & 5)
    STORAGE_BACKEND: str = Field(
        default="filesystem",
        description="Evidence storage provider backend: 'filesystem' or 'seaweedfs'"
    )
    EVIDENCE_STORAGE_PATH: str = Field(
        default="./evidence_storage",
        description="Filesystem root for storing raw forensic evidence files (local adapter)"
    )
    SEAWEEDFS_FILER_URL: str = Field(
        default="http://localhost:8888",
        description="Base URL of SeaweedFS Filer HTTP REST API"
    )
    SEAWEEDFS_COLLECTION: str = Field(
        default="evidence",
        description="SeaweedFS collection namespace for evidence objects"
    )
    SEAWEEDFS_REPLICATION: str = Field(
        default="",
        description="SeaweedFS replication setting for new volumes (e.g. '001', '010', empty for default)"
    )
    SEAWEEDFS_TIMEOUT_SECONDS: float = Field(
        default=10.0,
        description="SeaweedFS HTTP client timeout in seconds"
    )
    SEAWEEDFS_MAX_RETRIES: int = Field(
        default=3,
        description="Maximum bounded retry attempts for transient SeaweedFS HTTP failures"
    )
    SEAWEEDFS_AUTH_TOKEN: Optional[str] = Field(
        default=None,
        description="Optional Bearer token for authenticated SeaweedFS Filer requests"
    )
    SEAWEEDFS_FALLBACK_TO_FILESYSTEM: bool = Field(
        default=False,
        validation_alias=AliasChoices("SEAWEEDFS_FALLBACK_TO_FILESYSTEM", "STORAGE_FALLBACK_TO_FILESYSTEM"),
        description="Allow fallback to local filesystem if SeaweedFS is unavailable (locked out in staging/prod)"
    )

    @property
    def STORAGE_FALLBACK_TO_FILESYSTEM(self) -> bool:
        """Backward-compatible alias for SEAWEEDFS_FALLBACK_TO_FILESYSTEM."""
        return self.SEAWEEDFS_FALLBACK_TO_FILESYSTEM
    RDAP_BOOTSTRAP_URL: str = Field(
        default="https://rdap.org/domain",
        description="Bootstrap endpoint for RDAP domain lookups"
    )
    CRTSH_BASE_URL: str = Field(
        default="https://crt.sh",
        description="Public Certificate Transparency API endpoint"
    )
    THEHARVESTER_BIN: Optional[str] = Field(
        default=None,
        description="Optional absolute path or executable name for theHarvester"
    )
    RECON_TIMEOUT_SECONDS: int = Field(
        default=15,
        description="Network query timeout for individual passive reconnaissance collectors"
    )
    RECON_MAX_CONCURRENCY: int = Field(
        default=4,
        description="Maximum concurrent collectors running per investigation job"
    )

    # Active Reconnaissance & Nmap Execution (Phase 5)
    NMAP_BIN: Optional[str] = Field(
        default=None,
        description="Optional path to Nmap binary; auto-discovered from system PATH or common paths if None"
    )
    NMAP_DEFAULT_TIMEOUT_SECONDS: int = Field(
        default=120,
        description="Default timeout for active Nmap scan execution in seconds"
    )
    NMAP_MAX_CONCURRENCY: int = Field(
        default=2,
        description="Maximum concurrent active Nmap scans permitted across the application"
    )

    # Vulnerability Assessment & Greenbone/OpenVAS Integration (Phase 6)
    GVM_HOST: Optional[str] = Field(
        default=None,
        description="Hostname or IP address of the Greenbone / OpenVAS GMP service"
    )
    GVM_PORT: int = Field(
        default=9390,
        description="TLS port for Greenbone GMP service (default: 9390)"
    )
    GVM_UNIX_SOCKET: Optional[str] = Field(
        default=None,
        description="Path to Greenbone gvmd Unix domain socket (e.g. /run/gvmd/gvmd.sock)"
    )
    GVM_USERNAME: Optional[str] = Field(
        default=None,
        description="Greenbone administrative/service username"
    )
    GVM_PASSWORD: Optional[str] = Field(
        default=None,
        description="Greenbone service password (read from secret environment variable)"
    )
    GVM_TIMEOUT_SECONDS: int = Field(
        default=180,
        description="Network query and connection timeout for Greenbone GMP requests in seconds"
    )
    GVM_POLL_INTERVAL_SECONDS: int = Field(
        default=5,
        description="Polling frequency in seconds when monitoring Greenbone scan tasks"
    )
    GVM_MAX_POLL_ATTEMPTS: int = Field(
        default=60,
        description="Maximum polling cycles before timing out a running Greenbone assessment task"
    )
    GVM_TLS_VERIFY: bool = Field(
        default=True,
        description="Enforce TLS certificate verification when connecting to Greenbone over TLS"
    )
    GVM_USE_TLS: bool = Field(
        default=False,
        description="Whether to use TLS for TCP connections to Greenbone (True for direct remote TLS, False for localhost TCP bridge)"
    )
    GVM_CA_FILE: Optional[str] = Field(
        default=None,
        description="Optional CA bundle path used to verify the Greenbone GMP TLS certificate"
    )

    @field_validator("DATABASE_URL")
    @classmethod
    def resolve_database_url(cls, v: str) -> str:
        if v.startswith("sqlite:///./"):
            rel_name = v.replace("sqlite:///./", "")
            app_dir = Path(__file__).resolve().parent.parent
            app_db = app_dir / rel_name
            return f"sqlite:///{app_db.resolve().as_posix()}"
        return v

    @field_validator("EVIDENCE_STORAGE_PATH")
    @classmethod
    def resolve_evidence_storage(cls, v: str) -> str:
        if v.startswith("./"):
            rel_name = v[2:]
            app_dir = Path(__file__).resolve().parent.parent
            return str((app_dir / rel_name).resolve())
        return v

    @field_validator("DEBUG", mode="before")
    @classmethod
    def set_debug_mode(cls, v, values):
        # Default debug to True only in development mode if not explicitly set
        if v is None:
            return values.data.get("APP_ENV") == "development"
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_production_secret(cls, v: str, info):
        env = info.data.get("APP_ENV")
        if env in {"staging", "production"}:
            if not v or "dev-insecure" in v or len(v) < 32 or len(set(v)) < 16:
                raise ValueError(
                    "CRITICAL: Production deployment requires a secure, high-entropy SECRET_KEY (min 32 chars). "
                    "Generate via: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
        return v

    @field_validator("DEBUG")
    @classmethod
    def validate_production_debug(cls, v: bool, info):
        env = info.data.get("APP_ENV")
        if env in {"staging", "production"} and v is True:
            raise ValueError("CRITICAL: DEBUG mode must be disabled (False) in staging and production environments.")
        return v

    @field_validator("STORAGE_BACKEND")
    @classmethod
    def validate_storage_backend(cls, v: str) -> str:
        cleaned = (v or "").strip().lower()
        if cleaned not in {"filesystem", "seaweedfs"}:
            raise ValueError(f"STORAGE_BACKEND must be 'filesystem' or 'seaweedfs', got '{v}'")
        return cleaned

    @model_validator(mode="after")
    def validate_demo_provisioning(self):
        if self.APP_ENV in {"staging", "production"}:
            # Condition 1: SQLite fallback is strictly locked out in staging and production
            object.__setattr__(self, "DB_FALLBACK_TO_SQLITE", False)
            # Storage fallback to filesystem is locked out in staging and production
            object.__setattr__(self, "SEAWEEDFS_FALLBACK_TO_FILESYSTEM", False)
            if self.STORAGE_BACKEND == "seaweedfs" and not self.SEAWEEDFS_FILER_URL:
                raise ValueError("SEAWEEDFS_FILER_URL must be configured when STORAGE_BACKEND is 'seaweedfs'.")
        if self.APP_ENV in {"staging", "production"} and self.DEMO_ACCOUNTS_ENABLED:
            raise ValueError("Demo account provisioning cannot be enabled in production or staging.")
        if self.APP_ENV in {"staging", "production"} and self.SESSION_COOKIE_SECURE is False:
            raise ValueError("Secure session cookies are required in staging and production.")
        if self.SESSION_COOKIE_SAMESITE == "none" and self.SESSION_COOKIE_SECURE is False:
            raise ValueError("SameSite=None cookies require SESSION_COOKIE_SECURE=True.")
        if self.APP_ENV in {"staging", "production"} and not self.ALLOWED_HOSTS:
            raise ValueError("ALLOWED_HOSTS must be configured in staging and production.")
        if self.APP_ENV in {"staging", "production"} and "*" in self.ALLOWED_HOSTS:
            raise ValueError("Wildcard ALLOWED_HOSTS is not permitted in staging or production.")
        if self.DEMO_ACCOUNTS_ENABLED and (
            not self.DEMO_ADMIN_PASSWORD or not self.DEMO_INVESTIGATOR_PASSWORD
        ):
            raise ValueError(
                "DEMO_ADMIN_PASSWORD and DEMO_INVESTIGATOR_PASSWORD are required when "
                "DEMO_ACCOUNTS_ENABLED is true."
            )
        return self

    @property
    def is_sqlite(self) -> bool:
        """Returns True if database connection string targets SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == "test"

    @property
    def cookie_secure(self) -> bool:
        """Determines if cookies should be sent with Secure flag."""
        if self.SESSION_COOKIE_SECURE is not None:
            return self.SESSION_COOKIE_SECURE
        return self.APP_ENV in {"staging", "production"}

    def __repr__(self) -> str:
        """Sanitized representation to prevent leaking secrets in logging."""
        return (
            f"<Settings app_name='{self.APP_NAME}' "
            f"env='{self.APP_ENV}' "
            f"debug={self.DEBUG} "
            f"db='{'sqlite' if self.is_sqlite else 'relational'}'>"
        )


@lru_cache()
def get_settings() -> Settings:
    """Returns singleton cached instance of application settings."""
    return Settings()


settings = get_settings()
