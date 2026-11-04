"""Health check routes."""

from fastapi import APIRouter
from app.api.health import router as health_router

router = health_router

