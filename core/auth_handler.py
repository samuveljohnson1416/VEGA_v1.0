"""
Authentication handler for multi-role login and session management.
Uses Playwright for browser-based login with Juice Shop.
Fallback to HTTP POST if Playwright fails.
"""

import asyncio
import json
import base64
from typing import List, Optional
import httpx
from playwright.async_api import async_playwright

from core.session_store import Session, SessionStore
from shared.models import RoleCredential


async def login_all_roles(target_url: str, credentials: List[RoleCredential]) -> SessionStore:
    """
    Login all roles via Playwright and extract session data.
    
    Args:
        target_url: Target application URL (e.g., http://localhost:3000)
        credentials: List of RoleCredential objects with role, email, password
        
    Returns:
        SessionStore with authenticated sessions for all roles
    """
    session_store = SessionStore()
    
    for cred in credentials:
        session = await _login_role(target_url, cred)
        if session:
            session_store.add(session)
    
    return session_store


async def _login_role(target_url: str, credential: RoleCredential) -> Optional[Session]:
    """
    Login a single role via Playwright or HTTP fallback.
    
    Args:
        target_url: Target application URL
        credential: RoleCredential with role, email, password
        
    Returns:
        Session object with cookies and JWT, or None if login failed
    """
    # Try Playwright first
    session = await _login_via_playwright(target_url, credential)
    if session:
        return session
    
    # Fallback to HTTP POST
    return await _login_via_http(target_url, credential)


async def _login_via_playwright(target_url: str, credential: RoleCredential) -> Optional[Session]:
    """
    Login via Playwright headless chromium.
    Extracts cookies and JWT from browser context and localStorage.
    
    Args:
        target_url: Target application URL
        credential: RoleCredential with role, email, password
        
    Returns:
        Session object or None if login failed
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            # Navigate to login page
            await page.goto(f"{target_url}/#/login", wait_until="networkidle")
            
            # Wait for email input to be visible
            await page.wait_for_selector('input[type="email"]', timeout=5000)
            
            # Fill login form
            await page.fill('input[type="email"]', credential.email)
            await page.fill('input[type="password"]', credential.password)
            
            # Submit form and wait for navigation
            async with page.expect_response(lambda r: "/rest/user/login" in r.url) as response_info:
                await page.click('button[type="submit"]')
            
            response = await response_info.value
            response_json = await response.json()
            
            # Extract JWT from response
            jwt_token = response_json.get("authentication", {}).get("token")
            
            # Extract cookies
            cookies_list = await context.cookies()
            cookies = {c["name"]: c["value"] for c in cookies_list}
            
            # Try to get token from localStorage as fallback
            if not jwt_token:
                jwt_token = await page.evaluate("() => localStorage.getItem('token')")
            
            # Build headers
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            session = Session(
                role=credential.role,
                cookies=cookies,
                headers=headers,
                jwt_token=jwt_token
            )
            
            await browser.close()
            return session
            
        except Exception as e:
            print(f"[AUTH] Playwright login failed for {credential.role}: {e}")
            await browser.close()
            return None


async def _login_via_http(target_url: str, credential: RoleCredential) -> Optional[Session]:
    """
    Fallback login via HTTP POST to /rest/user/login endpoint.
    Used if Playwright login fails.
    
    Args:
        target_url: Target application URL
        credential: RoleCredential with role, email, password
        
    Returns:
        Session object or None if login failed
    """
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        try:
            response = await client.post(
                f"{target_url}/rest/user/login",
                json={"email": credential.email, "password": credential.password},
                timeout=10.0
            )
            response.raise_for_status()
            
            data = response.json()
            jwt_token = data.get("authentication", {}).get("token")
            
            # Extract cookies from response
            cookies = {}
            for cookie in response.cookies.jar:
                cookies[cookie.name] = cookie.value
            
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            session = Session(
                role=credential.role,
                cookies=cookies,
                headers=headers,
                jwt_token=jwt_token
            )
            
            return session
            
        except Exception as e:
            print(f"[AUTH] HTTP login failed for {credential.role}: {e}")
            return None


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
