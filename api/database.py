# api/database.py
# PostgreSQL se connection setup karta hai
# SQLAlchemy ORM use karta hai — Python objects se database tables interact karte hain

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Float, Integer, DateTime, JSON, Boolean, Text
from sqlalchemy.sql import func
import os
from loguru import logger


# ─────────────────────────────────────────────
# Database engine — PostgreSQL connection pool
# ─────────────────────────────────────────────
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:devpassword@localhost:5432/devsecops_db"
)

# create_async_engine — async version jo FastAPI ke saath kaam karta hai
# pool_size=10 — 10 simultaneous connections rakhega
# max_overflow=20 — peak load pe 20 extra connections allow
engine = create_async_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    echo=False,     # True karo to SQL queries log hogi (debug ke liye)
)

# Session factory — har request ke liye ek session banata hai
# Session = ek database transaction
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Commit ke baad bhi objects accessible rahein
)


# ─────────────────────────────────────────────
# Base class — saare database models inherit karenge
# ─────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────
# Database Models — Python classes jo database tables hain
# ─────────────────────────────────────────────

class ScanResult(Base):
    """
    Har scan run ka record.
    Ek scan mein multiple findings ho sakti hain (separate table).
    """
    __tablename__ = "scan_results"

    id          = Column(String(36), primary_key=True)   # UUID
    scan_type   = Column(String(50))                      # "sast", "full", etc.
    target_path = Column(String(500))                     # Kya scan kiya
    branch      = Column(String(100))                     # Git branch
    commit_sha  = Column(String(40))                      # Git commit hash
    risk_level  = Column(String(10))                      # "PASS", "FAIL", "WARN"
    risk_score  = Column(Integer, default=0)
    
    # Finding counts by severity
    count_critical = Column(Integer, default=0)
    count_high     = Column(Integer, default=0)
    count_medium   = Column(Integer, default=0)
    count_low      = Column(Integer, default=0)
    count_info     = Column(Integer, default=0)
    
    # Full findings stored as JSON (avoids N+1 queries for small datasets)
    findings_json  = Column(JSON, default=list)
    
    # Tool-specific counts
    tool_counts    = Column(JSON, default=dict)
    
    # Timestamps — func.now() = current time in DB timezone
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    duration_ms = Column(Integer, default=0)   # Scan duration in milliseconds
    
    triggered_by = Column(String(100), default="manual")  # "github_actions", "api", "manual"


class Finding(Base):
    """
    Individual findings — har vulnerability ek row hai.
    """
    __tablename__ = "findings"

    id          = Column(String(12), primary_key=True)   # Our hash-based ID
    scan_id     = Column(String(36))                      # FK to scan_results.id
    scanner     = Column(String(50))                      # "semgrep", "bandit", etc.
    vuln_type   = Column(String(200))
    file_path   = Column(String(500))
    line_number = Column(Integer, nullable=True)
    description = Column(Text)
    severity    = Column(String(20))                      # "critical", "high", etc.
    cvss_score  = Column(Float, default=0.0)
    remediation = Column(Text)
    
    # Is this a known false positive?
    is_false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text, nullable=True)
    
    # AI triage result
    ai_confirmed = Column(Boolean, nullable=True)
    ai_reasoning = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_output = Column(JSON, default=dict)


class Notification(Base):
    """Notification log — kaun kaun ko kab bataya."""
    __tablename__ = "notifications"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    scan_id    = Column(String(36))
    channel    = Column(String(20))   # "slack", "email", "pr_comment"
    status     = Column(String(20))   # "sent", "failed"
    message    = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────

async def create_tables():
    """
    Application startup pe tables create karo agar exist nahi karte.
    Production mein Alembic migrations use karein — yeh sirf development ke liye.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")


async def get_db():
    """
    FastAPI dependency injection ke liye.
    Har API request ke liye ek fresh DB session deta hai.
    
    Usage in routes:
    async def my_endpoint(db: AsyncSession = Depends(get_db)):
        ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()