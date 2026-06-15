from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# 1. Create the SQLAlchemy Engine Instance
# The engine manages a pool of active connections to PostgreSQL.
# 'pool_pre_ping=True' is a production-grade safety feature that checks if a 
# database connection is still alive before using it, preventing "lost connection" errors.
engine = create_engine(
    settings.DATABASE_URL, 
    pool_pre_ping=True,
    echo=False  # Set to True if you want to see raw SQL statements printed in your terminal
)

# 2. Configure the Session Factory
# This creates a blueprint for generating isolated session transactions.
# 'autocommit=False' and 'autoflush=False' ensure your transactions only save 
# to the database when explicitly told to via 'db.commit()'.
SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine
)

# 3. Request Dependency Generator (yield pattern)
def get_db():
    """
    Dependency function that yields a database session context.
    
    This ensures that each API request gets its own isolated database transaction,
    and guarantees that the connection is safely closed immediately after the 
    request finishes—even if an error occurs during execution.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()