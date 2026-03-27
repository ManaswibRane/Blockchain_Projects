"""
api.py
FastAPI web application: REST API + static web UI.

Endpoints:
  GET  /api/health   → { "ok": true }
  POST /api/build    → Accepts fixture JSON, returns PSBT report
  GET  /             → Serves static/index.html
"""

import os
from typing import Any, Optional

from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.builder import build_transaction

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Coin Smith",
    description="Safe PSBT transaction builder — BIP-174",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow all origins (needed for local dev and evaluator)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["health"])
async def health() -> dict:
    """
    Phase 1 evaluation endpoint.
    Must return HTTP 200 { "ok": true }.
    """
    return {"ok": True}


# ── PSBT builder ─────────────────────────────────────────────────────────────

@app.post("/api/build", tags=["psbt"])
async def build(
    request: Request,
    strategy: str = Query(default="auto", description="Coin selection strategy: auto | greedy | bnb | knapsack | consolidate"),
) -> JSONResponse:
    """
    Accept a fixture JSON body, validate it, build a PSBT, return a report.

    Request body: fixture JSON object (see README for schema)
    Query param:  ?strategy=auto (default) | greedy | bnb | knapsack | consolidate

    Returns:
        200 on success  — { "ok": true, ... }
        422 on error    — { "ok": false, "error": { "code": "...", "message": "..." } }
    """
    # ── Parse body ────────────────────────────────────────────────────────────
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "Content-Type must be application/json",
                },
            },
        )

    try:
        raw_fixture: Any = await request.json()
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": {
                    "code": "INVALID_JSON",
                    "message": f"Failed to parse JSON body: {exc}",
                },
            },
        )

    if not isinstance(raw_fixture, dict):
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": {
                    "code": "INVALID_FIXTURE",
                    "message": "Fixture must be a JSON object, not array or primitive",
                },
            },
        )

    # Validate strategy param
    if strategy not in ("auto", "greedy", "bnb", "knapsack", "consolidate"):
        strategy = "auto"

    # ── Build ─────────────────────────────────────────────────────────────────
    report = build_transaction(raw_fixture, strategy=strategy)

    status_code = 200 if report.get("ok") else 422
    return JSONResponse(status_code=status_code, content=report)


# ── Static files / Web UI ────────────────────────────────────────────────────
# Mount static files AFTER API routes so /api/* is not caught by StaticFiles

if os.path.isdir(STATIC_DIR):
    # Serve index.html at root
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    # Serve all other static assets (js, css, etc.)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ── Global exception handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(exc),
            },
        },
    )