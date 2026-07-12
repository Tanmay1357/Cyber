import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from api.ws.manager import stats_manager
from api.services.monitor_service import monitor_service

router = APIRouter()


@router.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    await stats_manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(1)
            payload = monitor_service.get_stats_payload()
            await websocket.send_json(payload)
    except (WebSocketDisconnect, Exception):
        stats_manager.disconnect(websocket)
