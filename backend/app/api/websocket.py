import asyncio
import logging
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_token
from app.models.user import User

log = logging.getLogger(__name__)

router = APIRouter()

PING_INTERVAL = 25  # seconds between server-initiated pings
AUTH_TIMEOUT = 10   # seconds the client has to send its auth message


class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    def connect(self, websocket: WebSocket, scan_id: str):
        """Subscribe an accepted, authenticated socket to a scan's events."""
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


def _is_valid_user_token(token, db: Session) -> bool:
    """True if the token is a valid JWT for an existing, active user."""
    if not isinstance(token, str):
        return False
    try:
        user_id = verify_token(token)
    except HTTPException:
        return False
    user = db.query(User).filter(User.id == user_id).first()
    return user is not None and user.is_active


@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str, db: Session = Depends(get_db)):
    """Live scan events.

    Browsers cannot set an Authorization header on a WebSocket, and a token in
    the URL would end up in server/proxy logs. So the client must send
    {"type": "auth", "token": "<JWT>"} as its first message; until then it
    receives nothing. Invalid or missing auth closes the socket with 1008.
    """
    await websocket.accept()
    try:
        first = await asyncio.wait_for(websocket.receive_json(), timeout=AUTH_TIMEOUT)
    except WebSocketDisconnect:
        return
    except (asyncio.TimeoutError, ValueError):   # no message in time / not JSON
        first = None

    authenticated = (isinstance(first, dict) and first.get("type") == "auth"
                     and _is_valid_user_token(first.get("token"), db))
    # Release the DB connection now: the socket may stay open for a long time
    db.close()

    if not authenticated:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    manager.connect(websocket, scan_id)
    await websocket.send_json({"type": "auth_ok"})
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
