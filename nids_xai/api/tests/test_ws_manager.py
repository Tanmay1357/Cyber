import asyncio
import pytest
from unittest.mock import AsyncMock
from api.ws.manager import ConnectionManager

@pytest.mark.asyncio
async def test_connect_registers_client():
    mgr = ConnectionManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    await mgr.connect(ws)
    assert ws in mgr.active_connections

@pytest.mark.asyncio
async def test_disconnect_removes_client():
    mgr = ConnectionManager()
    ws = AsyncMock()
    ws.accept = AsyncMock()
    await mgr.connect(ws)
    mgr.disconnect(ws)
    assert ws not in mgr.active_connections

@pytest.mark.asyncio
async def test_broadcast_sends_to_all():
    mgr = ConnectionManager()
    ws1, ws2 = AsyncMock(), AsyncMock()
    ws1.accept, ws2.accept = AsyncMock(), AsyncMock()
    await mgr.connect(ws1)
    await mgr.connect(ws2)
    await mgr.broadcast({"kind": "flow"})
    ws1.send_json.assert_called_once_with({"kind": "flow"})
    ws2.send_json.assert_called_once_with({"kind": "flow"})
