"""Reporting application commands."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class GenerateDossierCommand:
    """Command to generate an investigation dossier."""
    investigation_id: str
    user_id: str
    is_admin: bool = False
    title: Optional[str] = None


@dataclass
class ExportGraphMLCommand:
    """Command to export investigation correlation graph as GraphML."""
    investigation_id: str
    user_id: str
    is_admin: bool = False

