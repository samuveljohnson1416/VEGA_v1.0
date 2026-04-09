"""
Authentication handler for multi-role login and session management.
REST login via HTTP POST to /rest/user/login endpoint.
"""

import json
import base64
import httpx
from typing import List, Dict, Optional

from core.session_store import SessionStore, Session


def login_all_roles(target_url: str, credentials: List[Dict[str, str]]) -> SessionStore:
    """
    Login all roles via REST API.
    
    Args:
        target_url: Target application URL (e.g., http://localhost:3000)
        credentials: List of dicts with username, password, role
        
    Returns:
        SessionStore with authenticated sessions for all roles
    """
    session_store = SessionStore()
    
    print(f"[+] Starting authentication for {len(credentials)} roles...")
    
    for cred in credentials:
        role = cred.get("role", "unknown")
        username = cred.get("username", "")
        password = cred.get("password", "")
        
        try:
            # REST API login
            login_url = f"{target_url}/rest/user/login"
            payload = {"email": username, "password": password}
            
            response = httpx.post(
                login_url,
                json=payload,
                verify=False,
                timeout=10.0
            )
            
            if response.status_code not in [200, 201]:
                print(f"[-] Login failed for {role}: HTTP {response.status_code}")
                continue
            
            # Parse token
            data = response.json()
            jwt_token = data["authentication"]["token"]
            
            # Create Session object
            session = Session(
                role=role,
                cookies={},
                headers={},
                jwt_token=jwt_token
            )
            
            # Store in session_store
            session_store.add(session)
            
            print(f"[+] Logged in as {role}")
        
        except Exception as e:
            print(f"[-] Login failed for {role}: {type(e).__name__}: {e}")
    
    print()
    return session_store


def tamper_jwt(token: str, claim_overrides: dict) -> str:
    """
    Tamper with JWT claims without re-signing.
    Used for RBAC testing by modifying role/permission claims.
    NOTE: Resulting token will have invalid signature - for testing only.
    
    Args:
        token: JWT token (3 parts separated by dots)
        claim_overrides: Dictionary of claims to override (e.g., {"role": "admin"})
        
    Returns:
        Modified JWT token with tampered claims but invalid signature
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format - must have 3 parts")
        
        # Decode payload (part 1)
        payload_b64 = parts[1]
        
        # Add padding if needed for base64 decoding
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        
        # Decode JSON payload
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Override claims
        payload.update(claim_overrides)
        
        # Re-encode payload (without padding for JWT standard)
        new_payload_json = json.dumps(payload, separators=(',', ':'))
        new_payload_b64 = base64.urlsafe_b64encode(
            new_payload_json.encode()
        ).decode().rstrip("=")
        
        # Reconstruct token with original signature (which is now invalid)
        tampered_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
        return tampered_token
        
    except Exception as e:
        print(f"[AUTH] JWT tampering failed: {e}")
        return token


# Utility function to decode JWT without verification (for inspection)
def decode_jwt_payload(token: str) -> Optional[dict]:
    """
    Decode JWT payload without signature verification.
    Used for inspection only.
    
    Args:
        token: JWT token
        
    Returns:
        Decoded payload dictionary or None if invalid
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        
        return json.loads(base64.urlsafe_b64decode(payload_b64))
        
    except Exception as e:
        print(f"[AUTH] JWT decode failed: {e}")
        return None
