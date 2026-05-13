import asyncio
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db

router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self._connections.setdefault(scan_id, []).append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        conns = self._connections.get(scan_id, [])
        if websocket in conns:
            conns.remove(websocket)
        if not conns:
            self._connections.pop(scan_id, None)

    async def emit(self, scan_id: str, data: dict):
        conns = self._connections.get(scan_id, [])
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
            # Keep connection alive; client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
