"""
Session management for role-based authentication.
Handles cookies, headers, and JWT tokens for multi-role testing.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List
from datetime import datetime


@dataclass
class Session:
    """Represents an authenticated session for a specific role."""
    role: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    jwt_token: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    def get_headers_with_auth(self) -> Dict[str, str]:
        """Get headers with Bearer token auto-attached if JWT exists."""
        headers = self.headers.copy()
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        return headers


class SessionStore:
    """
    Centralized store for managing authenticated sessions across different roles.
    """

    def __init__(self):
        self._sessions: Dict[str, Session] = {}

    def add(self, session: Session) -> None:
        """
        Add or update a session for a role.
        
        Args:
            session: Session object with role, cookies, headers, jwt_token
        """
        self._sessions[session.role] = session

    def get(self, role: str) -> Optional[Session]:
        """
        Get a session by role.
        
        Args:
            role: Role identifier
            
        Returns:
            Session object if found, None otherwise
        """
        return self._sessions.get(role)

    def all_roles(self) -> List[str]:
        """
        Get list of all authenticated roles.
        
        Returns:
            List of role names
        """
        return list(self._sessions.keys())

    def get_headers(self, role: str) -> Dict[str, str]:
        """
        Get headers for a role with Bearer token auto-attached if JWT exists.
        
        Args:
            role: Role identifier
            
        Returns:
            Headers dictionary with Authorization header if JWT token exists
            
        Raises:
            ValueError: If role session not found
        """
        session = self.get(role)
        if not session:
            raise ValueError(f"No session found for role: {role}")
        return session.get_headers_with_auth()

    def get_cookies(self, role: str) -> Dict[str, str]:
        """
        Get cookies for a role.
        
        Args:
            role: Role identifier
            
        Returns:
            Cookies dictionary
            
        Raises:
            ValueError: If role session not found
        """
        session = self.get(role)
        if not session:
            raise ValueError(f"No session found for role: {role}")
        return session.cookies.copy()

    def remove(self, role: str) -> bool:
        """
        Remove a session by role.
        
        Args:
            role: Role identifier
            
        Returns:
            True if removed, False if not found
        """
        if role in self._sessions:
            del self._sessions[role]
            return True
        return False

    def clear(self) -> None:
        """Clear all sessions."""
        self._sessions.clear()

    def __len__(self) -> int:
        """Get number of active sessions."""
        return len(self._sessions)

    def __repr__(self) -> str:
        roles = ", ".join(self.all_roles())
        return f"SessionStore(roles=[{roles}])"
