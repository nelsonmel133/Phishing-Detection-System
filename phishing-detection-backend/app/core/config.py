import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Application Settings configuration.
    
    Pydantic Settings automatically handles reading environment variables from 
    both the local OS environment and a '.env' file, parsing data types 
    (e.g., turning strings into integers) automatically.
    """
    
    # 1. Project Metadata
    PROJECT_NAME: str = "Phishing Detection & Mitigation Engine"
    API_V1_STR: str = "/api/v1"
    
    # 2. Database Connection URI
    # Default fallback points to a local PostgreSQL instance
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://postgres:postgres@localhost:5432/phish_db"
    )
    
    # 3. Cryptographic Security Configurations
    # Used for signing and verifying JWT security credentials.
    # No insecure default: SECRET_KEY must be set via env var or .env file.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # Token validity length (7 days)

    # 4. CORS — comma-separated list of allowed origins in production
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://localhost:3000")

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


# Instantiate a single, global settings object to share across your backend tasks
settings = Settings()