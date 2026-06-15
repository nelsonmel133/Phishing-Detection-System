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
    # In production environments, change this to a long, complex random hex string.
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", 
        "SUPER_SECRET_THREAT_INTELLIGENCE_CORE_SIGNING_KEY_NODE_DO_NOT_SHARE"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # Token validity length (7 days)

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"  
        
# Instantiate a single, global settings object to share across your backend tasks
settings = Settings()