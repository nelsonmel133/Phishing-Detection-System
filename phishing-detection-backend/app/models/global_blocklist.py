import uuid
from datetime import datetime
import enum
from sqlalchemy import String, ForeignKey, Enum as SAEnum, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class IndicatorType(str, enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    KEYWORD = "keyword"

class GlobalBlocklist(Base):
    __tablename__ = "global_blocklist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    indicator_type: Mapped[IndicatorType] = mapped_column(
        SAEnum(IndicatorType, name="indicator_type"), nullable=False
    )
    value: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    added_by_user: Mapped["User | None"] = relationship(back_populates="blocklist_entries")