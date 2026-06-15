import uuid
from datetime import datetime
import enum
from sqlalchemy import Text, Integer, ForeignKey, Enum as SAEnum, DateTime, func, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class InputType(str, enum.Enum):
    URL = "url"
    TEXT = "text"

class ThreatStatus(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    input_type: Mapped[InputType] = mapped_column(
        SAEnum(InputType, name="input_type"), nullable=False
    )
    raw_input: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_status: Mapped[ThreatStatus] = mapped_column(
        SAEnum(ThreatStatus, name="threat_status"), nullable=False, default=ThreatStatus.SAFE
    )
    dominant_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    user: Mapped["User | None"] = relationship(back_populates="scan_requests")