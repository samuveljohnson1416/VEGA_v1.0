"""
Attack chain builder for multi-step vulnerability exploitation.
Builds and executes chains of attacks where each step can use context from previous steps.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from core.request_engine import execute_attack
from core.session_store import SessionStore
from shared.models import AttackResult, Endpoint


@dataclass
class ChainStep:
    """Represents a single step in an attack chain."""
    endpoint: Endpoint
    payload: Dict[str, Any]
    role: Optional[str] = None
    description: Optional[str] = None
    baseline: Optional[str] = None
    result: Optional[AttackResult] = None


class ChainBuilder:
    """
    Builder for multi-step attack chains.
    Executes attacks sequentially, passing context between steps.
    """

    def __init__(self, name: str = "AttackChain"):
        """
        Initialize chain builder.
        
        Args:
            name: Name of this attack chain
        """
        self.name = name
        self.steps: List[ChainStep] = []
        self.execution_results: List[AttackResult] = []

    def add_step(
        self,
        endpoint: Endpoint,
        payload: Dict[str, Any],
        role: Optional[str] = None,
        description: Optional[str] = None,
        baseline: Optional[str] = None
    ) -> "ChainBuilder":
        """
        Add a step to the attack chain.
        
        Args:
            endpoint: Endpoint to attack
            payload: Payload to send
            role: Role to use for authentication (None for unauthenticated)
            description: Human-readable description of this step
            baseline: Baseline response for comparison
            
        Returns:
            Self for method chaining
        """
        step = ChainStep(
            endpoint=endpoint,
            payload=payload,
            role=role,
            description=description,
            baseline=baseline
        )
        self.steps.append(step)
        return self

    def get_chain(self) -> List[ChainStep]:
        """
        Get all steps in the chain.
        
        Returns:
            List of ChainStep objects
        """
        return self.steps.copy()

    async def execute_chain(self, session_store: SessionStore, target_url: str = "http://localhost:3000") -> List[AttackResult]:
        """
        Execute all steps in the chain sequentially.
        Passes context from previous step to next step.
        
        Args:
            session_store: SessionStore with authenticated sessions
            target_url: Base URL of target application
            
        Returns:
            List of AttackResult objects from each step
        """
        self.execution_results = []
        previous_result = None
        
        for i, step in enumerate(self.steps):
            try:
                # Build payload for this step
                current_payload = step.payload.copy()
                
                # Inject context from previous step if available
                if previous_result:
                    current_payload = _inject_previous_context(
                        current_payload,
                        previous_result
                    )
                
                # Execute this step
                result = await execute_attack(
                    endpoint=step.endpoint,
                    payload=current_payload,
                    session_store=session_store,
                    role=step.role,
                    baseline=step.baseline,
                    target_url=target_url
                )
                
                # Store result
                step.result = result
                self.execution_results.append(result)
                previous_result = result
            
            except Exception as e:
                # Silent failure per step, but create error result
                error_result = AttackResult(
                    endpoint_path=step.endpoint.path,
                    method=step.endpoint.method,
                    status_code=0,
                    response_headers={},
                    response_body=f"ERROR in step {i}: {str(e)[:200]}",
                    payload_sent=step.payload,
                    role_used=step.role,
                    diff_from_baseline=None
                )
                self.execution_results.append(error_result)
        
        return self.execution_results

    def get_results(self) -> List[AttackResult]:
        """
        Get results from last execution.
        
        Returns:
            List of AttackResult objects from most recent execution
        """
        return self.execution_results

    def clear(self) -> None:
        """Clear all steps from chain."""
        self.steps = []
        self.execution_results = []

    def __len__(self) -> int:
        """Get number of steps in chain."""
        return len(self.steps)

    def __repr__(self) -> str:
        return f"ChainBuilder(name={self.name}, steps={len(self.steps)})"


def _inject_previous_context(
    current_payload: Dict[str, Any],
    previous_result: AttackResult
) -> Dict[str, Any]:
    """
    Inject context from previous step result into current payload.
    Looks for ID values in response and uses them in next step.
    
    Args:
        current_payload: Payload for current step
        previous_result: Result from previous step
        
    Returns:
        Payload with injected context
    """
    try:
        # Extract potential ID values from previous response
        import json
        import re
        
        response_body = previous_result.response_body
        if not response_body:
            return current_payload
        
        # Try to parse as JSON
        try:
            response_data = json.loads(response_body)
            
            # Look for common ID field names
            id_fields = ["id", "userId", "user_id", "productId", "product_id", "orderId", "order_id"]
            
            for id_field in id_fields:
                if id_field in response_data:
                    # Inject into payload if there's a corresponding parameter
                    for payload_key in current_payload:
                        if payload_key.lower() in [f.lower() for f in id_fields]:
                            current_payload[payload_key] = response_data[id_field]
                            break
        
        except (json.JSONDecodeError, TypeError):
            # Response not JSON, try regex extraction
            pass
        
        # Extract IDs via regex (look for numeric IDs)
        id_pattern = r'"id["\']?\s*:\s*(\d+)'
        matches = re.findall(id_pattern, response_body)
        
        if matches:
            extracted_id = matches[0]
            # Inject into payload parameters that look like IDs
            for key in current_payload:
                if "id" in key.lower():
                    current_payload[key] = extracted_id
                    break
    
    except Exception as e:
        # Silent failure - return original payload
        pass
    
    return current_payload


# Predefined chain templates for common attack scenarios

def create_authentication_bypass_chain(admin_endpoint: Endpoint) -> ChainBuilder:
    """
    Create a chain to test authentication bypass.
    Step 1: Access endpoint unauthenticated
    Step 2: Access endpoint as regular user
    Step 3: Access endpoint as admin
    
    Args:
        admin_endpoint: Endpoint that should be admin-only
        
    Returns:
        ChainBuilder with bypass test steps
    """
    chain = ChainBuilder("Authentication Bypass Test")
    
    # Step 1: Unauthenticated access
    chain.add_step(
        endpoint=admin_endpoint,
        payload={},
        role=None,
        description="Attempt unauthenticated access"
    )
    
    # Step 2: Regular user access
    chain.add_step(
        endpoint=admin_endpoint,
        payload={},
        role="user",
        description="Attempt access as regular user"
    )
    
    # Step 3: Admin access
    chain.add_step(
        endpoint=admin_endpoint,
        payload={},
        role="admin",
        description="Attempt access as admin"
    )
    
    return chain


def create_privilege_escalation_chain(
    user_endpoint: Endpoint,
    admin_endpoint: Endpoint
) -> ChainBuilder:
    """
    Create a chain to test privilege escalation.
    Step 1: Access user-level resource
    Step 2: Attempt to access admin resource with user role
    
    Args:
        user_endpoint: User-level endpoint
        admin_endpoint: Admin-level endpoint
        
    Returns:
        ChainBuilder with escalation test steps
    """
    chain = ChainBuilder("Privilege Escalation Test")
    
    chain.add_step(
        endpoint=user_endpoint,
        payload={"id": "1"},
        role="user",
        description="Access as user to get context"
    )
    
    chain.add_step(
        endpoint=admin_endpoint,
        payload={"id": "1"},
        role="user",
        description="Attempt admin endpoint access as user"
    )
    
    return chain


def create_idor_chain(
    endpoint: Endpoint,
    id_values: List[str] = None
) -> ChainBuilder:
    """
    Create a chain to test IDOR (Insecure Direct Object References).
    Tests accessing resources with different ID values.
    
    Args:
        endpoint: Endpoint to test
        id_values: List of ID values to test
        
    Returns:
        ChainBuilder with IDOR test steps
    """
    if id_values is None:
        id_values = ["1", "2", "3", "999", "admin", "0"]
    
    chain = ChainBuilder("IDOR Test")
    
    for id_val in id_values:
        chain.add_step(
            endpoint=endpoint,
            payload={"id": id_val},
            role="user",
            description=f"IDOR test with id={id_val}"
        )
    
    return chain


def create_data_extraction_chain(
    search_endpoint: Endpoint,
    details_endpoint: Endpoint
) -> ChainBuilder:
    """
    Create a chain for data extraction attack.
    Step 1: Search/enumerate to find resource IDs
    Step 2: Access each resource via details endpoint
    
    Args:
        search_endpoint: Endpoint to search/enumerate
        details_endpoint: Endpoint to fetch details
        
    Returns:
        ChainBuilder for data extraction
    """
    chain = ChainBuilder("Data Extraction Attack")
    
    chain.add_step(
        endpoint=search_endpoint,
        payload={"query": "*", "limit": "100"},
        role="admin",
        description="Search/enumerate all resources"
    )
    
    chain.add_step(
        endpoint=details_endpoint,
        payload={"id": "1"},
        role="admin",
        description="Extract resource details (ID from previous step)"
    )
    
    return chain
