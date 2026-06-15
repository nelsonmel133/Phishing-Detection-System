import uuid
from datetime import datetime
import enum
from sqlalchemy import String, Enum as SAEnum, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base  # We will create Base next

class UserRole(str, enum.Enum):
    END_USER = "end_user"
    ANALYST = "analyst"

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role"), nullable=False, default=UserRole.END_USER
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan_requests: Mapped[list["ScanRequest"]] = relationship(back_populates="user")
    blocklist_entries: Mapped[list["GlobalBlocklist"]] = relationship(back_populates="added_by_user")