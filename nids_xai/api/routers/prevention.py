"""
Prevention / enforcement endpoints for NIDS-XAI.

GET  /api/blocked             — list currently blocked IPs
POST /api/unblock/{ip}        — unblock a specific IP
GET  /api/prevention/mode     — get current enforcement mode
POST /api/prevention/mode     — set enforcement mode at runtime
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.services.prevention_service import prevention_service

router = APIRouter(tags=["prevention"])


# ------------------------------------------------------------------ #
#  Schema                                                              #
# ------------------------------------------------------------------ #

class ModeBody(BaseModel):
    mode: str


# ------------------------------------------------------------------ #
#  Endpoints                                                           #
# ------------------------------------------------------------------ #

@router.get("/api/blocked")
def list_blocked():
    """Return all currently blocked IPs with TTL metadata."""
    return {"blocked": prevention_service.get_blocked()}


@router.post("/api/unblock/{ip}")
def unblock_ip(ip: str):
    """Unblock a specific IP address."""
    result = prevention_service.unblock_ip(ip)
    return result


@router.get("/api/prevention/mode")
def get_mode():
    """Return the current enforcement mode."""
    return {"mode": prevention_service.mode}


@router.post("/api/prevention/mode")
def set_mode(body: ModeBody):
    """
    Set the enforcement mode at runtime.
    Accepted values: "monitor", "dry_run", "enforce".
    """
    try:
        prevention_service.set_mode(body.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"mode": prevention_service.mode, "changed": True}
