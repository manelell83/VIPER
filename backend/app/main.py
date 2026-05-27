from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base
from app.api.routes import interfaces, scan, topology, results, reports
from app.api.routes import vulnerabilities
from app.api.routes import attack_graph
from app.api.routes import exploitability
from app.api import websocket as ws

# Import models so SQLAlchemy registers them before create_all()
import app.models.scan  # noqa: F401
import app.vulnerability_scanner.models  # noqa: F401
import app.attack_graph.models  # noqa: F401
import app.exploitability.models  # noqa: F401


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(interfaces.router, prefix="/interfaces", tags=["Interfaces"])
app.include_router(scan.router, prefix="/scan", tags=["Scan"])
app.include_router(topology.router, prefix="/topology", tags=["Topology"])
app.include_router(results.router, prefix="/results", tags=["Results"])
app.include_router(reports.router, prefix="/reports", tags=["Reports"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(attack_graph.router, prefix="/attack-graph", tags=["Attack Graph"])
app.include_router(exploitability.router, prefix="/exploitability", tags=["Exploitability"])
app.include_router(ws.router, tags=["WebSocket"])


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
