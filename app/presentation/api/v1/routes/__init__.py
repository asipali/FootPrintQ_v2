"""API v1 routers."""

from fastapi import APIRouter
from app.presentation.api.v1.routes.investigations import router as investigations_router
from app.presentation.api.v1.routes.evidence import router as evidence_router
from app.presentation.api.v1.routes.workflows import router as workflows_router
from app.presentation.api.v1.routes.health import router as health_router

api_v1_router = APIRouter(prefix="/v1")
api_v1_router.include_router(health_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(workflows_router)

__all__ = [
    "api_v1_router",
    "investigations_router",
    "evidence_router",
    "workflows_router",
    "health_router",
]

