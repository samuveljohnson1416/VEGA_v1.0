import json
import os
from typing import List, Dict, Any, Optional
from langchain_groq import ChatGroq
from shared.models import AttackResult


class LLMResultAnalyzer:
    """LLM-powered analyzer for attack results and vulnerability narrative generation."""
    
    def __init__(self):
        """Initialize analyzer with FAST and SMART LLM models."""
        llm_model_fast = os.getenv("LLM_MODEL_FAST", "llama-3.1-8b-instant")
        llm_model_smart = os.getenv("LLM_MODEL_SMART", "llama-3.3-70b-versatile")
        
        self.llm_fast = ChatGroq(model=llm_model_fast, temperature=0.0)
        self.llm_smart = ChatGroq(model=llm_model_smart, temperature=0.7)
    
    def analyze(self, attack_result: AttackResult) -> Dict[str, Any]:
        """
        Analyze HTTP response to determine if it indicates a real vulnerability.
        Uses FAST model for quick analysis.
        
        Args:
            attack_result: AttackResult object with response_code and response_body
        
        Returns:
            Dict with: is_vulnerable (bool), confidence (0-100), reason (str)
        """
        try:
            # Extract response details
            response_code = getattr(attack_result, 'response_code', 200)
            response_body = getattr(attack_result, 'response_body', '')
            
            # Truncate body to avoid token limits
            body_snippet = str(response_body)[:5000]
            
            # Build prompt
            prompt = f"""You are a web security analyst. An attack payload was sent to a web application.
Determine if the response indicates a real vulnerability.

Payload type: {attack_result.payload.get('type', 'unknown')}
Payload value: {attack_result.payload.get('value', '')}
Target param: {attack_result.payload.get('param', '')}
HTTP Status: {response_code}
Response body (first 1000 chars): {body_snippet[:1000]}

Rules:
- SQLi: vulnerable if SQL error, stack trace, or unexpected data dump in response
- XSS: vulnerable if payload is reflected back unescaped in response body
- IDOR: vulnerable if status 200 with another user's data
- CSRF: vulnerable if action succeeded without token validation

Return JSON only:
{{"is_vulnerable": boolean, "confidence": number, "reason": "string"}}"""
            
            # Call FAST model for quick analysis
            response = self.llm_fast.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # Extract and parse JSON
            json_str = response_text.strip()
            
            # Remove markdown code blocks
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            elif json_str.startswith("```"):
                json_str = json_str[3:]
            
            if json_str.endswith("```"):
                json_str = json_str[:-3]
            
            # Parse JSON response
            data = json.loads(json_str.strip())
            
            return {
                "is_vulnerable": bool(data.get("is_vulnerable", False)),
                "confidence": int(data.get("confidence", 0)),
                "reason": str(data.get("reason", ""))
            }
        
        except Exception as e:
            print(f"[-] Analyzer error: {e}")
        
        return {
            "is_vulnerable": False,
            "confidence": 0,
            "reason": ""
        }
    
    def generate_narrative(self, results: List[Dict[str, Any]]) -> str:
        """
        Generate professional vulnerability report narrative from confirmed findings.
        Uses SMART model for detailed reasoning.
        
        Args:
            results: List of confirmed vulnerability dicts
        
        Returns:
            Professional narrative string
        """
        try:
            # Format results for prompt
            results_str = json.dumps(results, indent=2)
            
            # Truncate if too large
            if len(results_str) > 10000:
                results_str = results_str[:10000] + "\n[truncated...]"
            
            # Build prompt
            prompt = f"""You are a security expert. Write a professional vulnerability report narrative for these findings:

{results_str}

Include: severity, impact, and recommendation for each vulnerability. Format as a clear, concise report."""
            
            # Call SMART model for detailed analysis
            response = self.llm_smart.invoke(prompt)
            narrative = response.content if hasattr(response, 'content') else str(response)
            
            return narrative.strip()
        
        except Exception:
            pass
        
        return ""
