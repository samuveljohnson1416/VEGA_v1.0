"""
Web crawler for discovering endpoints and API routes.
Uses Playwright to intercept network requests and extract forms/links.
Builds an AppMap of all discovered endpoints.
"""

import asyncio
from typing import Set, List, Optional
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright, Page, Request

from core.session_store import SessionStore
from shared.models import AppMap, Endpoint


async def crawl(target_url: str, session_store: SessionStore) -> AppMap:
    """
    Crawl target URL and discover all endpoints.
    
    Args:
        target_url: Target application URL (e.g., http://localhost:3000)
        session_store: SessionStore with authenticated sessions
        
    Returns:
        AppMap with all discovered endpoints
    """
    # Get first available role for authentication
    roles = session_store.all_roles()
    if not roles:
        print("[CRAWLER] No authenticated sessions available")
        return AppMap(endpoints=[])
    
    first_role = roles[0]
    headers = session_store.get_headers(first_role)
    cookies = session_store.get_cookies(first_role)
    
    endpoints: Set[tuple] = set()  # (method, path, params_list)
    visited_urls: Set[str] = set()
    discovered_links: List[str] = []
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        
        # Set authentication headers and cookies
        await context.add_init_script(
            f"Object.defineProperty(window, 'authHeaders', {{value: {headers}}})"
        )
        
        page = await context.new_page()
        
        # Setup request interception
        async def handle_request(request: Request) -> None:
            try:
                path = urlparse(request.url).path
                method = request.method
                
                # Try to extract request body for POST/PUT/PATCH
                request_data = {}
                try:
                    if request.method in ["POST", "PUT", "PATCH"]:
                        post_data = request.post_data
                        if post_data:
                            import json
                            request_data = json.loads(post_data)
                except:
                    pass
                
                # Extract parameter names from request
                params = list(request_data.keys()) if request_data else []
                
                # Add to endpoints (normalize tuple for set)
                endpoint_key = (method, path, tuple(sorted(params)))
                endpoints.add(endpoint_key)
            except Exception as e:
                pass  # Silent failure
        
        page.on("request", handle_request)
        
        # Start crawling
        queue = [target_url]
        
        while queue and len(visited_urls) < 30:
            url = queue.pop(0)
            
            if url in visited_urls:
                continue
            
            visited_urls.add(url)
            
            try:
                # Navigate to page
                await page.goto(url, wait_until="networkidle", timeout=10000)
                
                # Extract forms
                forms = await page.evaluate("""
                    () => {
                        const forms = [];
                        document.querySelectorAll('form').forEach(form => {
                            const inputs = [];
                            form.querySelectorAll('input, textarea, select').forEach(input => {
                                if (input.name) {
                                    inputs.push(input.name);
                                }
                            });
                            forms.push({
                                action: form.action || '',
                                method: form.method || 'GET',
                                inputs: inputs
                            });
                        });
                        return forms;
                    }
                """)
                
                # Process extracted forms
                for form in forms:
                    try:
                        action = form.get('action', '')
                        if action:
                            action_url = urljoin(url, action)
                            action_path = urlparse(action_url).path
                            method = form.get('method', 'GET').upper()
                            inputs = form.get('inputs', [])
                            
                            endpoint_key = (method, action_path, tuple(sorted(inputs)))
                            endpoints.add(endpoint_key)
                    except:
                        pass
                
                # Extract links
                links = await page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            links.push(a.href);
                        });
                        return links;
                    }
                """)
                
                # Add discovered links to queue
                for link in links:
                    try:
                        link_parsed = urlparse(link)
                        target_parsed = urlparse(target_url)
                        
                        # Only crawl same domain
                        if link_parsed.netloc == target_parsed.netloc:
                            if link not in visited_urls and len(queue) < 30:
                                queue.append(link)
                    except:
                        pass
            
            except Exception as e:
                # Silent failure on timeouts, 404s, etc.
                pass
        
        await browser.close()
    
    # Convert endpoint tuples to Endpoint objects
    endpoint_objects = []
    for method, path, params in endpoints:
        try:
            endpoint = Endpoint(
                path=path,
                method=method,
                parameters=list(params) if params else []
            )
            endpoint_objects.append(endpoint)
        except:
            pass
    
    # Create and return AppMap
    app_map = AppMap(endpoints=endpoint_objects)
    return app_map


async def _extract_json_from_request(request: Request) -> Optional[dict]:
    """
    Extract JSON body from request if available.
    
    Args:
        request: Playwright Request object
        
    Returns:
        Parsed JSON dict or None
    """
    try:
        import json
        post_data = request.post_data
        if post_data:
            return json.loads(post_data)
    except:
        pass
    return None


async def _is_same_domain(url: str, base_url: str) -> bool:
    """
    Check if URL is on same domain as base URL.
    
    Args:
        url: URL to check
        base_url: Base URL for comparison
        
    Returns:
        True if same domain, False otherwise
    """
    try:
        url_parsed = urlparse(url)
        base_parsed = urlparse(base_url)
        return url_parsed.netloc == base_parsed.netloc
    except:
        return False
