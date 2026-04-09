"""
Smoke test for all core modules.
Verifies that all imports work and modules are ready.
"""

import sys
import asyncio

try:
    # Test SessionStore imports
    from core.session_store import Session, SessionStore
    print("[✓] session_store imports OK")
    
    # Test auth_handler imports
    from core.auth_handler import login_all_roles, tamper_jwt, decode_jwt_payload
    print("[✓] auth_handler imports OK")
    
    # Test crawler imports
    from core.crawler import crawl
    print("[✓] crawler imports OK")
    
    # Test request_engine imports
    from core.request_engine import execute_attack, _diff_responses
    print("[✓] request_engine imports OK")
    
    # Test vuln_checks imports
    from core.vuln_checks import (
        SQLI_PAYLOADS, XSS_PAYLOADS, CSRF_CHECK, IDOR_PATTERNS,
        JWT_ATTACKS, GRAPHQL_INTROSPECTION, get_payloads_for_param
    )
    print("[✓] vuln_checks imports OK")
    
    # Test rbac_tester imports
    from core.rbac_tester import test_rbac
    print("[✓] rbac_tester imports OK")
    
    # Test dom_analyzer imports
    from core.dom_analyzer import analyze_dom, check_dom_storage_xss
    print("[✓] dom_analyzer imports OK")
    
    # Test graphql_tester imports
    from core.graphql_tester import test_graphql, test_graphql_union_attacks
    print("[✓] graphql_tester imports OK")
    
    # Test chain_builder imports
    from core.chain_builder import (
        ChainBuilder, create_authentication_bypass_chain,
        create_privilege_escalation_chain, create_idor_chain,
        create_data_extraction_chain
    )
    print("[✓] chain_builder imports OK")
    
    # Test shared models imports
    from shared.models import Endpoint, AppMap, AttackResult, RoleCredential
    print("[✓] shared.models imports OK")
    
    print("\n" + "="*50)
    print("ALL IMPORTS OK")
    print("="*50)
    print("\nCore modules ready for Member 1 integration:")
    print("  - session_store: Session, SessionStore")
    print("  - auth_handler: login_all_roles(), tamper_jwt()")
    print("  - crawler: crawl()")
    print("  - request_engine: execute_attack()")
    print("  - rbac_tester: test_rbac()")
    print("  - vuln_checks: payloads + get_payloads_for_param()")
    print("  - dom_analyzer: analyze_dom()")
    print("  - graphql_tester: test_graphql()")
    print("  - chain_builder: ChainBuilder class + templates")
    
except ImportError as e:
    print(f"[✗] IMPORT FAILED: {e}")
    sys.exit(1)
except Exception as e:
    print(f"[✗] ERROR: {e}")
    sys.exit(1)
