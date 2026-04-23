"""
Autonomous Breach Containment (ABC) — toggle and status endpoints.
"""

from fastapi import APIRouter

router = APIRouter(tags=["abc"])


@router.post("/api/abc/toggle")
async def toggle_abc(enabled: bool):
    """Enable or disable autonomous auto-prove mode."""
    from tasks import set_abc_mode, get_abc_status
    set_abc_mode(enabled)
    return get_abc_status()


@router.get("/api/abc/status")
async def abc_status():
    """Return current ABC mode state."""
    from tasks import get_abc_status
    return get_abc_status()
