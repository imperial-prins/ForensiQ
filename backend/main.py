import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

load_dotenv()

logger = logging.getLogger("codeflux")

from backend.api.endpoints import router as api_router
from backend.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("CodeFlux database initialized")
    yield


app = FastAPI(
    title="CodeFlux AI Email Security & Investigation Platform",
    description="A provider-neutral email analysis pipeline for Gmail and RFC822 uploads with explainable risk, safe actions, and deep investigation views.",
    version="2.0.0",
    lifespan=lifespan,
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

app.include_router(api_router)


@app.get("/health")
@app.get("/api/health")
def health_check():
    return {"status": "online", "service": "CodeFlux Email Security", "version": "2.0.0"}


# Mount frontend production build if present
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("backend.main:app", host=host, port=port, reload=True)
