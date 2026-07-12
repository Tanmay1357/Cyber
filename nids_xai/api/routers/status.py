from fastapi import APIRouter
from api.services.model_service import model_service
from api.services.monitor_service import monitor_service

router = APIRouter()


@router.get("/api/status")
def get_status():
    return {
        "model_loaded": model_service.is_loaded,
        "model_file": model_service.status()["model_file"],
        "monitor_running": monitor_service.is_running,
        "monitor_mode": monitor_service.mode,
        "monitor_source": monitor_service.source,
    }
