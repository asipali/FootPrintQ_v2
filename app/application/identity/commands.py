"""Identity application commands."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class RegisterUserCommand:
    """Command to register a new user."""
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = "investigator"


@dataclass
class AuthenticateUserCommand:
    """Command to authenticate user credentials."""
    username: str
    password: str
    client_ip: Optional[str] = None

