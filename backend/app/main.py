from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base
from app.api.routes import interfaces, scan, topology, results, reports
from app.api import websocket as ws


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
