"""
DOM analysis for reflected XSS detection.
Analyzes page DOM for vulnerability indicators and tests XSS payload reflection.
"""

import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs
from playwright.async_api import Page

from core.vuln_checks import XSS_PAYLOADS


# XSS Indicators to look for in DOM
XSS_INDICATORS = [
    "<script",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onclick=",
    "onfocus=",
    "javascript:",
    "eval(",
    "document.write(",
    "innerHTML",
    "dangerouslySetInnerHTML",
]


async def analyze_dom(page: Page, url: str) -> List[Dict[str, Any]]:
    """
    Analyze page DOM for reflected XSS vulnerabilities.
    Tests XSS payload reflection and identifies dangerous patterns.
    
    Args:
        page: Playwright Page object already loaded
        url: URL of the page to analyze
        
    Returns:
        List of vulnerability findings with type, url, indicator, payload
    """
    findings = []
    
    try:
        # Get current DOM content
        dom_content = await page.content()
        
        # Step 1: Check for XSS indicators in current DOM
        indicator_findings = _check_xss_indicators(dom_content, url)
        findings.extend(indicator_findings)
        
        # Step 2: Test XSS payload reflection
        reflection_findings = await _test_payload_reflection(page, url)
        findings.extend(reflection_findings)
    
    except Exception as e:
        # Silent failure
        pass
    
    return findings


async def _test_payload_reflection(page: Page, base_url: str) -> List[Dict[str, Any]]:
    """
    Test XSS payloads by injecting them into URL params and checking reflection.
    
    Args:
        page: Playwright Page object
        base_url: Base URL to test
        
    Returns:
        List of findings where payloads are reflected unescaped in DOM
    """
    findings = []
    
    try:
        # Parse URL to get base and existing params
        parsed = urlparse(base_url)
        base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        existing_params = parse_qs(parsed.query)
        
        # Identify injectable parameters from URL
        injectable_params = set()
        if existing_params:
            injectable_params = set(existing_params.keys())
        else:
            # Common parameter names if none in URL
            injectable_params = {"q", "search", "input", "text", "query", "id", "name"}
        
        # Test each parameter with each payload
        for param in injectable_params:
            for payload in XSS_PAYLOADS:
                try:
                    # Create test URL with payload in this parameter
                    test_params = {param: payload}
                    test_url = f"{base_path}?{urlencode(test_params)}"
                    
                    # Navigate to test URL
                    await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                    
                    # Get DOM content
                    dom_content = await page.content()
                    
                    # Check if payload appears unescaped in DOM
                    if _is_payload_reflected_unescaped(dom_content, payload):
                        findings.append({
                            "type": "REFLECTED_XSS",
                            "severity": "HIGH",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "indicator": "Payload found unescaped in DOM",
                            "dom_location": _find_payload_in_dom(dom_content, payload)
                        })
                
                except Exception as e:
                    # Silent failure per payload
                    pass
    
    except Exception as e:
        # Silent failure
        pass
    
    return findings


def _check_xss_indicators(dom_content: str, url: str) -> List[Dict[str, Any]]:
    """
    Check DOM for dangerous XSS patterns and indicators.
    
    Args:
        dom_content: Full DOM HTML content
        url: URL being analyzed
        
    Returns:
        List of findings for each indicator found
    """
    findings = []
    
    try:
        for indicator in XSS_INDICATORS:
            # Case-insensitive search
            if indicator.lower() in dom_content.lower():
                # Try to extract context around indicator
                context = _extract_context(dom_content, indicator, num_chars=100)
                
                findings.append({
                    "type": "XSS_INDICATOR",
                    "severity": "MEDIUM",
                    "url": url,
                    "indicator": indicator,
                    "payload": None,
                    "context": context,
                    "description": f"XSS indicator '{indicator}' found in DOM"
                })
    
    except Exception as e:
        # Silent failure
        pass
    
    return findings


def _is_payload_reflected_unescaped(dom_content: str, payload: str) -> bool:
    """
    Check if payload appears unescaped in DOM.
    Returns False if payload is HTML-encoded or included in quotes.
    
    Args:
        dom_content: DOM content to search
        payload: Payload to check for
        
    Returns:
        True if payload appears unescaped, False otherwise
    """
    try:
        if not payload or not dom_content:
            return False
        
        # Check for exact payload in DOM
        if payload not in dom_content:
            return False
        
        # Check if payload is HTML-encoded (would be safe)
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in dom_content and payload not in dom_content:
            return False
        
        # Check if payload is in a data attribute or text content (likely vulnerable)
        # Look for context around payload
        index = dom_content.find(payload)
        if index >= 0:
            # Get surrounding context (100 chars before and after)
            start = max(0, index - 100)
            end = min(len(dom_content), index + len(payload) + 100)
            context = dom_content[start:end]
            
            # If payload is in a script tag, attribute value, or event handler -> vulnerable
            if any(pattern in context.lower() for pattern in [
                "<script", "on|=", "javascript:", "eval(", "innerHTML", "document.write"
            ]):
                return True
        
        return False
    
    except Exception as e:
        return False


def _find_payload_in_dom(dom_content: str, payload: str) -> Optional[str]:
    """
    Find and return context around payload in DOM.
    
    Args:
        dom_content: DOM content
        payload: Payload to find
        
    Returns:
        Context string around payload or None if not found
    """
    try:
        if not payload or not dom_content:
            return None
        
        index = dom_content.find(payload)
        if index < 0:
            return None
        
        # Get surrounding context (150 chars before and after)
        start = max(0, index - 150)
        end = min(len(dom_content), index + len(payload) + 150)
        context = dom_content[start:end]
        
        return context.strip()
    
    except Exception as e:
        return None


def _extract_context(text: str, search_term: str, num_chars: int = 100) -> str:
    """
    Extract context around a search term in text.
    
    Args:
        text: Text to search in
        search_term: Term to find
        num_chars: Number of characters before/after to include
        
    Returns:
        Context string around the search term
    """
    try:
        # Case-insensitive search
        lower_text = text.lower()
        lower_term = search_term.lower()
        
        index = lower_text.find(lower_term)
        if index < 0:
            return ""
        
        start = max(0, index - num_chars)
        end = min(len(text), index + len(search_term) + num_chars)
        context = text[start:end]
        
        # Replace newlines with spaces for readability
        context = context.replace('\n', ' ').replace('\r', ' ')
        
        return context.strip()
    
    except Exception as e:
        return ""


async def check_dom_storage_xss(page: Page) -> List[Dict[str, Any]]:
    """
    Check localStorage and sessionStorage for dangerous values.
    
    Args:
        page: Playwright Page object
        
    Returns:
        List of findings for suspicious storage values
    """
    findings = []
    
    try:
        # Extract localStorage
        local_storage = await page.evaluate(
            "() => Object.assign({}, localStorage)"
        )
        
        # Extract sessionStorage
        session_storage = await page.evaluate(
            "() => Object.assign({}, sessionStorage)"
        )
        
        # Check for XSS payloads in storage
        for key, value in local_storage.items():
            if isinstance(value, str) and _contains_xss_payload(value):
                findings.append({
                    "type": "DOM_STORAGE_XSS",
                    "severity": "MEDIUM",
                    "storage_type": "localStorage",
                    "key": key,
                    "value": value[:100],  # Truncate for display
                    "description": f"Suspicious XSS pattern in localStorage[{key}]"
                })
        
        for key, value in session_storage.items():
            if isinstance(value, str) and _contains_xss_payload(value):
                findings.append({
                    "type": "DOM_STORAGE_XSS",
                    "severity": "MEDIUM",
                    "storage_type": "sessionStorage",
                    "key": key,
                    "value": value[:100],  # Truncate for display
                    "description": f"Suspicious XSS pattern in sessionStorage[{key}]"
                })
    
    except Exception as e:
        # Silent failure
        pass
    
    return findings


def _contains_xss_payload(text: str) -> bool:
    """
    Check if text contains common XSS payload patterns.
    
    Args:
        text: Text to check
        
    Returns:
        True if suspicious XSS patterns found
    """
    try:
        dangerous_patterns = [
            "<script",
            "onerror=",
            "onload=",
            "javascript:",
            "eval(",
            "document.write",
            "innerHTML",
        ]
        
        text_lower = text.lower()
        return any(pattern.lower() in text_lower for pattern in dangerous_patterns)
    
    except:
        return False
