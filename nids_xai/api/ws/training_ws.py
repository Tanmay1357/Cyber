from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from api.services.training_service import training_service

router = APIRouter()


@router.websocket("/ws/training")
async def training_ws(websocket: WebSocket):
    await training_service.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep alive; client sends nothing
    except WebSocketDisconnect:
        training_service.disconnect(websocket)
