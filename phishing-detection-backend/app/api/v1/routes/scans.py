import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.scan_request import ScanRequest, InputType, ThreatStatus
from app.models.user import User
from app.services.heuristic_engine import PhishingHeuristicEngine
from app.dependencies import get_optional_current_user, require_analyst

# Initialize router prefixing all endpoints with /api/v1
router = APIRouter(prefix="/api/v1", tags=["scans"])

# Instantiating the engine at the module level since it is stateless and safe to share
engine = PhishingHeuristicEngine()

# ----------------------------------------------------------------------------
# Pydantic Schemas for Input Validation
# ----------------------------------------------------------------------------
class ScanCreateRequest(BaseModel):
    """Inbound payload validation schema from clients."""
    input_type: InputType
    raw_input: str = Field(..., min_length=1, max_length=4096, description="URL or free-text block to analyze")

class ScanDetailResponse(BaseModel):
    """Outbound data serialization schema returning calculations to clients."""
    id: uuid.UUID
    input_type: InputType
    raw_input: str
    risk_score: int
    threat_status: ThreatStatus
    dominant_vector: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


# ----------------------------------------------------------------------------
# API Routing Endpoints
# ----------------------------------------------------------------------------

@router.post("/scan", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def create_scan_request(
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Core Threat Analysis Endpoint.
    
    Accepts text or URL inputs from mobile/web clients, evaluates malicious vectors,
    persists a tracking snapshot to PostgreSQL, and returns live metrics.
    """
    try:
        # 1. Feed payload directly into our stateless heuristic worker engine
        analysis = engine.analyze_input(payload.raw_input)
        
        # 2. Map calculated metrics into our database ORM instance structure
        scan_record = ScanRequest(
            user_id=current_user.id if current_user else None,
            input_type=payload.input_type,
            raw_input=payload.raw_input,
            risk_score=analysis["score"],
            threat_status=analysis["threat_status"],
            dominant_vector=analysis["dominant_vector"]
        )
        
        # 3. Open session context, stage block insertion, and commit record safely
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        # 4. Format date cleanly to string structure before returning data payload
        return ScanDetailResponse(
            id=scan_record.id,
            input_type=scan_record.input_type,
            raw_input=scan_record.raw_input,
            risk_score=scan_record.risk_score,
            threat_status=scan_record.threat_status,
            dominant_vector=scan_record.dominant_vector,
            created_at=scan_record.created_at.isoformat()
        )
        
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Core threat engine compilation fault: {str(exc)}"
        )


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan_details(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Analyst Deep Dive Endpoint.
    
    Allows authenticated users possessing the 'analyst' role to query 
    and inspect specific historical threat flags using their unique ID token.
    """
    scan_record = db.query(ScanRequest).filter(ScanRequest.id == scan_id).first()
    if not scan_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat profile entity with ID token {scan_id} could not be mapped."
        )
    
    return ScanDetailResponse(
        id=scan_record.id,
        input_type=scan_record.input_type,
        raw_input=scan_record.raw_input,
        risk_score=scan_record.risk_score,
        threat_status=scan_record.threat_status,
        dominant_vector=scan_record.dominant_vector,
        created_at=scan_record.created_at.isoformat()
    )