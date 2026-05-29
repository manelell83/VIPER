import asyncio
import logging
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)

router = APIRouter()

PING_INTERVAL = 25  # seconds between server-initiated pings


class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self._connections.setdefault(scan_id, []).append(websocket)
        log.debug(f"WS connected: {scan_id} (total: {len(self._connections.get(scan_id, []))})")

    def disconnect(self, websocket: WebSocket, scan_id: str):
        conns = self._connections.get(scan_id, [])
        if websocket in conns:
            conns.remove(websocket)
        if not conns:
            self._connections.pop(scan_id, None)
        log.debug(f"WS disconnected: {scan_id}")

    async def emit(self, scan_id: str, data: dict):
        conns = list(self._connections.get(scan_id, []))  # copy to avoid mutation during iteration
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, scan_id)

    def has_listeners(self, scan_id: str) -> bool:
        return bool(self._connections.get(scan_id))


manager = ConnectionManager()


@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Wait for any client message OR timeout (acts as keepalive check)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=PING_INTERVAL)
            except asyncio.TimeoutError:
                # Send a ping to check if client is still alive
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break  # client is gone
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, scan_id)
