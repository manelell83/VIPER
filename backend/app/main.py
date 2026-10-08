from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base
from app.api.deps import get_current_user
from app.api.routes import interfaces, scan, topology, results, reports
from app.api.routes import vulnerabilities
from app.api.routes import attack_graph
from app.api.routes import exploitability
from app.api.routes import auth
from app.api import websocket as ws

# Register all models with SQLAlchemy before create_all()
import app.models.scan                    # noqa: F401
import app.models.user                    # noqa: F401
import app.vulnerability_scanner.models   # noqa: F401
import app.attack_graph.models            # noqa: F401
import app.exploitability.models          # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Real-time dynamic network scanning platform for cybersecurity",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Auth uses a bearer token in the Authorization header (no cookies), so
# credentials are not needed for CORS; only the methods/headers we use are allowed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Public: /auth/login, /health, / and the API docs. Every other HTTP route
# requires a valid JWT (enforced here, once, for each router).
# The WebSocket authenticates itself with its first message (see websocket.py).
protected = [Depends(get_current_user)]

app.include_router(auth.router,                                                tags=["Auth"])
app.include_router(interfaces.router,      prefix="/interfaces",      dependencies=protected, tags=["Interfaces"])
app.include_router(scan.router,            prefix="/scan",            dependencies=protected, tags=["Scan"])
app.include_router(topology.router,        prefix="/topology",        dependencies=protected, tags=["Topology"])
app.include_router(results.router,         prefix="/results",         dependencies=protected, tags=["Results"])
app.include_router(reports.router,         prefix="/reports",         dependencies=protected, tags=["Reports"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", dependencies=protected, tags=["Vulnerabilities"])
app.include_router(attack_graph.router,    prefix="/attack-graph",    dependencies=protected, tags=["Attack Graph"])
app.include_router(exploitability.router,  prefix="/exploitability",  dependencies=protected, tags=["Exploitability"])
app.include_router(ws.router,                                                  tags=["WebSocket"])


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "version": settings.VERSION, "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
