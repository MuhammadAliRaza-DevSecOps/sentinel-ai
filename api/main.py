# api/main.py
# This is the main entry point for our FastAPI web server
# FastAPI = a modern Python web framework that automatically generates API docs
# Think of it like Flask but faster and with automatic documentation

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel

# Import our database setup
from .database import engine, create_tables

# Import our route handlers (defined in routes/scans.py etc.)
from .routes import scans, reports


# ─────────────────────────────────────────────
# Lifespan: runs on startup and shutdown
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Code before 'yield' runs at startup.
    Code after 'yield' runs at shutdown.
    
    This is where we:
    - Create database tables if they don't exist
    - Set up connections
    """
    logger.info("🚀 DevSecOps Pipeline API starting up...")
    
    # Create database tables based on our SQLAlchemy models
    await create_tables()
    logger.info("✅ Database tables ready")
    
    yield  # Application runs here
    
    logger.info("🛑 DevSecOps Pipeline API shutting down...")


# ─────────────────────────────────────────────
# Create the FastAPI application
# ─────────────────────────────────────────────
app = FastAPI(
    title="DevSecOps Pipeline Orchestrator API",
    description="""
    ## Automated Security Scanning Pipeline
    
    This API orchestrates security scans across:
    - **SAST** — Static code analysis with Semgrep + Bandit
    - **SCA** — Dependency vulnerability scanning
    - **Container** — Docker image scanning with Trivy
    - **DAST** — Dynamic application testing with OWASP ZAP
    - **Secrets** — Hardcoded credential detection
    
    Results are scored with CVSS and stored for trend analysis.
    """,
    version="1.0.0",
    lifespan=lifespan,
    # Where to find the auto-generated docs
    docs_url="/docs",      # Swagger UI: http://localhost:8000/docs
    redoc_url="/redoc",    # ReDoc: http://localhost:8000/redoc
)


# ─────────────────────────────────────────────
# CORS Middleware
# ─────────────────────────────────────────────
# CORS = Cross-Origin Resource Sharing
# This tells the browser which origins (domains) can call our API
# Without this, the Streamlit dashboard on localhost:8501 
# can't call the API on localhost:8000
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",   # Streamlit dashboard
        "http://localhost:3000",   # React frontend (if added later)
    ],
    allow_credentials=True,
    allow_methods=["*"],    # Allow GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],    # Allow any HTTP headers
)


# ─────────────────────────────────────────────
# Include routers
# ─────────────────────────────────────────────
# Routers are like blueprints — they group related endpoints
# /api/v1/scans → handled by scans.py
# /api/v1/reports → handled by reports.py
app.include_router(
    scans.router,
    prefix="/api/v1/scans",
    tags=["Scans"],          # Groups them in the auto-generated docs
)
app.include_router(
    reports.router,
    prefix="/api/v1/reports",
    tags=["Reports"],
)


# ─────────────────────────────────────────────
# Root endpoint
# ─────────────────────────────────────────────
@app.get("/")
async def root():
    """Health check endpoint — returns basic API info."""
    return {
        "service": "DevSecOps Pipeline Orchestrator",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """
    Health check for Docker/Kubernetes.
    Kubernetes uses this to know if the pod is healthy.
    Returns 200 OK if healthy, 503 if not.
    """
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}