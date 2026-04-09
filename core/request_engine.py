"""
Request execution engine for vulnerability testing.
Executes attack payloads against discovered endpoints.
Compares baseline vs attack responses.
"""

import httpx
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlencode

from core.session_store import SessionStore
from shared.models import AttackResult, Endpoint


async def execute_attack(
    endpoint: Endpoint,
    payload: Dict[str, Any],
    session_store: SessionStore,
    role: Optional[str] = None,
    baseline: Optional[str] = None,
    target_url: str = "http://localhost:3000"
) -> AttackResult:
    """
    Execute attack payload against an endpoint.
    
    Args:
        endpoint: Endpoint object with path, method, parameters
        payload: Dictionary of parameters to send
        session_store: SessionStore with authenticated sessions
        role: Role to use for authentication (None for unauthenticated)
        baseline: Baseline response body for diff comparison
        target_url: Base URL of target application
        
    Returns:
        AttackResult with response status, headers, body, and diff
    """
    try:
        # Build full URL
        full_url = urljoin(target_url, endpoint.path)
        
        # Prepare headers
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        cookies = {}
        
        # Add authentication if role specified
        if role:
            try:
                auth_headers = session_store.get_headers(role)
                headers.update(auth_headers)
                cookies = session_store.get_cookies(role)
            except ValueError:
                # Role not found in session store
                pass
        
        # Execute request based on method
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=10.0
        ) as client:
            response = None
            
            if endpoint.method.upper() == "GET":
                # Send payload as query parameters
                query_string = urlencode(payload)
                request_url = f"{full_url}?{query_string}" if query_string else full_url
                
                response = await client.get(
                    request_url,
                    headers=headers,
                    cookies=cookies
                )
            
            elif endpoint.method.upper() in ["POST", "PUT", "PATCH"]:
                # Send payload as JSON body
                method = endpoint.method.upper()
                
                if method == "POST":
                    response = await client.post(
                        full_url,
                        json=payload,
                        headers=headers,
                        cookies=cookies
                    )
                elif method == "PUT":
                    response = await client.put(
                        full_url,
                        json=payload,
                        headers=headers,
                        cookies=cookies
                    )
                elif method == "PATCH":
                    response = await client.patch(
                        full_url,
                        json=payload,
                        headers=headers,
                        cookies=cookies
                    )
            
            elif endpoint.method.upper() == "DELETE":
                response = await client.delete(
                    full_url,
                    headers=headers,
                    cookies=cookies
                )
            
            elif endpoint.method.upper() == "HEAD":
                response = await client.head(
                    full_url,
                    headers=headers,
                    cookies=cookies
                )
            
            else:
                # Default to GET
                response = await client.get(
                    full_url,
                    headers=headers,
                    cookies=cookies
                )
            
            # Extract response data
            status_code = response.status_code
            response_headers = dict(response.headers)
            response_body = response.text
            
            # Truncate response body to 2000 chars
            if len(response_body) > 2000:
                response_body = response_body[:2000] + "...[truncated]"
            
            # Compare with baseline if provided
            diff = None
            if baseline:
                diff = _diff_responses(baseline, response_body)
            
            # Create and return AttackResult
            result = AttackResult(
                endpoint_path=endpoint.path,
                method=endpoint.method,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                payload_sent=payload,
                role_used=role,
                diff_from_baseline=diff
            )
            
            return result
    
    except Exception as e:
        # Return error result
        error_msg = str(e)
        if len(error_msg) > 2000:
            error_msg = error_msg[:2000] + "...[truncated]"
        
        result = AttackResult(
            endpoint_path=endpoint.path,
            method=endpoint.method,
            status_code=0,
            response_headers={},
            response_body=f"ERROR: {error_msg}",
            payload_sent=payload,
            role_used=role,
            diff_from_baseline=None
        )
        
        return result


def _diff_responses(baseline_body: str, new_body: str) -> str:
    """
    Compare baseline and new response bodies.
    Returns summary of differences.
    
    Args:
        baseline_body: Original response body
        new_body: New response body to compare
        
    Returns:
        String describing differences
    """
    try:
        # Calculate basic metrics
        baseline_lines = baseline_body.split('\n')
        new_lines = new_body.split('\n')
        
        line_diff = len(new_lines) - len(baseline_lines)
        char_diff = len(new_body) - len(baseline_body)
        
        if baseline_body == new_body:
            return "No differences detected"
        
        # Find first differing line
        first_diff_line = None
        for i, (b_line, n_line) in enumerate(zip(baseline_lines, new_lines)):
            if b_line != n_line:
                first_diff_line = i
                break
        
        # Build diff summary
        diff_summary = f"Line count: {line_diff:+d} | "
        diff_summary += f"Char count: {char_diff:+d} | "
        
        if first_diff_line is not None:
            diff_summary += f"First diff at line {first_diff_line}"
        else:
            diff_summary += "Length mismatch detected"
        
        return diff_summary
    
    except Exception as e:
        return f"Diff error: {str(e)}"


def _build_request_url(
    base_url: str,
    endpoint_path: str,
    payload: Dict[str, Any]
) -> str:
    """
    Build request URL with query parameters.
    
    Args:
        base_url: Base URL of target
        endpoint_path: Path to endpoint
        payload: Query parameters
        
    Returns:
        Full URL with encoded parameters
    """
    try:
        full_url = urljoin(base_url, endpoint_path)
        query_string = urlencode(payload)
        return f"{full_url}?{query_string}" if query_string else full_url
    except:
        return urljoin(base_url, endpoint_path)
