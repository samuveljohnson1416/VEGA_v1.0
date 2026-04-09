"""
Role-Based Access Control (RBAC) testing.
Tests endpoints with different roles and detects authorization bypass vulnerabilities.
"""

import asyncio
from typing import List, Dict, Any, Optional

from core.session_store import SessionStore
from core.request_engine import execute_attack
from shared.models import AppMap, AttackResult


async def test_rbac(app_map: AppMap, session_store: SessionStore) -> List[Dict[str, Any]]:
    """
    Test RBAC by calling each endpoint with all available roles.
    Detects authorization bypass vulnerabilities.
    
    Args:
        app_map: AppMap with discovered endpoints
        session_store: SessionStore with authenticated sessions for different roles
        
    Returns:
        List of violation dictionaries with type, endpoint, admin_result, user_result
    """
    violations = []
    roles = session_store.all_roles()
    
    if not roles:
        return violations
    
    # For each endpoint
    for endpoint in app_map.endpoints:
        try:
            # Call endpoint with each role
            role_results = {}
            
            for role in roles:
                try:
                    # Build minimal payload for the endpoint
                    payload = _build_payload_for_endpoint(endpoint)
                    
                    # Execute attack with this role
                    result = await execute_attack(
                        endpoint=endpoint,
                        payload=payload,
                        session_store=session_store,
                        role=role,
                        target_url="http://localhost:3000"
                    )
                    
                    role_results[role] = result
                
                except Exception as e:
                    # Silent failure per role
                    pass
            
            # Compare results between roles
            violations.extend(
                _compare_role_responses(endpoint, role_results, roles)
            )
        
        except Exception as e:
            # Silent failure per endpoint
            pass
    
    return violations


def _build_payload_for_endpoint(endpoint) -> Dict[str, Any]:
    """
    Build a minimal payload for an endpoint based on its parameters.
    
    Args:
        endpoint: Endpoint object with parameters list
        
    Returns:
        Dictionary payload with dummy values for each parameter
    """
    payload = {}
    
    if endpoint.parameters:
        for param in endpoint.parameters:
            # Default values based on parameter name
            param_lower = param.lower()
            
            if "id" in param_lower:
                payload[param] = "1"
            elif "email" in param_lower:
                payload[param] = "test@example.com"
            elif "name" in param_lower:
                payload[param] = "test"
            elif "search" in param_lower or "query" in param_lower:
                payload[param] = "test"
            elif "password" in param_lower:
                payload[param] = "password123"
            elif "price" in param_lower or "amount" in param_lower:
                payload[param] = "10"
            else:
                payload[param] = "test"
    
    return payload


def _compare_role_responses(
    endpoint,
    role_results: Dict[str, AttackResult],
    all_roles: List[str]
) -> List[Dict[str, Any]]:
    """
    Compare responses across roles to detect RBAC violations.
    
    Args:
        endpoint: The endpoint being tested
        role_results: Dictionary of role -> AttackResult
        all_roles: List of all available roles
        
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    try:
        # Find admin and user roles
        admin_result = None
        admin_role = None
        user_results = []
        user_roles = []
        
        for role in all_roles:
            if role not in role_results:
                continue
            
            result = role_results[role]
            
            if "admin" in role.lower():
                admin_result = result
                admin_role = role
            else:
                user_results.append(result)
                user_roles.append(role)
        
        # If no admin result, can't compare
        if not admin_result:
            return violations
        
        # Compare each user result with admin result
        for user_result, user_role in zip(user_results, user_roles):
            violation = _check_rbac_violation(
                endpoint, admin_role, admin_result, user_role, user_result
            )
            
            if violation:
                violations.append(violation)
    
    except Exception as e:
        pass  # Silent failure
    
    return violations


def _check_rbac_violation(
    endpoint,
    admin_role: str,
    admin_result: AttackResult,
    user_role: str,
    user_result: AttackResult
) -> Optional[Dict[str, Any]]:
    """
    Check if a single admin/user pair indicates an RBAC violation.
    
    Args:
        endpoint: The endpoint being tested
        admin_role: Name of admin role
        admin_result: Response from admin
        user_role: Name of user role
        user_result: Response from user
        
    Returns:
        Violation dictionary if detected, None otherwise
    """
    try:
        # Both got 200 status
        if admin_result.status_code == 200 and user_result.status_code == 200:
            # User got substantial response (> 100 chars)
            if user_result.response_body and len(user_result.response_body) > 100:
                # Check if responses are similar (likely unauthorized access)
                if _responses_similar(admin_result.response_body, user_result.response_body):
                    return {
                        "type": "RBAC_VIOLATION",
                        "severity": "HIGH",
                        "endpoint": {
                            "path": endpoint.path,
                            "method": endpoint.method,
                            "parameters": endpoint.parameters
                        },
                        "admin_role": admin_role,
                        "user_role": user_role,
                        "admin_status": admin_result.status_code,
                        "user_status": user_result.status_code,
                        "admin_response_length": len(admin_result.response_body) if admin_result.response_body else 0,
                        "user_response_length": len(user_result.response_body) if user_result.response_body else 0,
                        "admin_result": admin_result,
                        "user_result": user_result,
                        "description": f"User role '{user_role}' can access endpoint meant for '{admin_role}' and received substantial data"
                    }
        
        # User got 200 but admin got 403/401 (unusual but possible misconfiguration)
        elif user_result.status_code == 200 and admin_result.status_code in [403, 401]:
            if user_result.response_body and len(user_result.response_body) > 100:
                return {
                    "type": "RBAC_MISCONFIGURATION",
                    "severity": "HIGH",
                    "endpoint": {
                        "path": endpoint.path,
                        "method": endpoint.method,
                        "parameters": endpoint.parameters
                    },
                    "admin_role": admin_role,
                    "user_role": user_role,
                    "admin_status": admin_result.status_code,
                    "user_status": user_result.status_code,
                    "user_response_length": len(user_result.response_body) if user_result.response_body else 0,
                    "admin_result": admin_result,
                    "user_result": user_result,
                    "description": f"User role '{user_role}' bypassed access control for admin endpoint"
                }
    
    except Exception as e:
        pass  # Silent failure
    
    return None


def _responses_similar(response1: Optional[str], response2: Optional[str], threshold: float = 0.7) -> bool:
    """
    Check if two responses are similar (indicating same data returned).
    
    Args:
        response1: First response body
        response2: Second response body
        threshold: Similarity threshold (0-1)
        
    Returns:
        True if responses are similar, False otherwise
    """
    try:
        if not response1 or not response2:
            return False
        
        # Truncate to first 500 chars for comparison
        r1 = response1[:500]
        r2 = response2[:500]
        
        # Simple similarity: check common lines
        lines1 = set(r1.split('\n')[:20])
        lines2 = set(r2.split('\n')[:20])
        
        if not lines1 or not lines2:
            return False
        
        intersection = len(lines1 & lines2)
        union = len(lines1 | lines2)
        
        similarity = intersection / union if union > 0 else 0
        
        return similarity >= threshold
    
    except Exception as e:
        return False
