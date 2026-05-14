"""
main.py — FastAPI entry point for the SOC AI Dashboard backend.

Responsibilities:
- Mounts all API routers
- Configures CORS for Next.js frontend
- Initializes Supabase client
- Provides health check endpoint
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from routers import alerts, analysis, devices, auth
from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SOC Dashboard API starting up...")
    yield
    logger.info("SOC Dashboard API shutting down...")


app = FastAPI(
    title="SOC AI Dashboard API",
    description="AI-powered alert interpretation layer for Wazuh SIEM alerts",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow Next.js dev server and Vercel production domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        settings.FRONTEND_URL,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(alerts.router,   prefix="/api/alerts",   tags=["Alerts"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["AI Analysis"])
app.include_router(devices.router,  prefix="/api/devices",  tags=["Devices"])
app.include_router(auth.router,     prefix="/api/auth",     tags=["Auth"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "soc-dashboard-api"}
