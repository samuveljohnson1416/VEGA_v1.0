import asyncio
import httpx
import json
import os
import traceback
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urljoin
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from shared.models import AppMap, Endpoint

# Load environment variables
load_dotenv()


class LLMCrawler:
    """LLM-powered web crawler for discovering endpoints via HTML analysis."""
    
    def __init__(self, target_url: str, session_store):
        self.target_url = target_url
        self.session_store = session_store
        self.visited_urls: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        self.max_endpoints = 30
        
        # Initialize LLM with FAST model from env
        llm_model = os.getenv("LLM_MODEL_FAST", "llama-3.1-8b-instant")
        print(f"[*] Using LLM model: {llm_model}")
        self.llm = ChatGroq(model=llm_model, temperature=0.0)
        
        # httpx client timeout
        self.timeout = 10.0
    
    async def crawl(self) -> AppMap:
        """
        Crawl target URL to discover endpoints using LLM analysis.
        Returns AppMap with discovered endpoints (max 30).
        """
        try:
            # Queue for BFS traversal
            to_visit: List[str] = [self.target_url]
            
            while to_visit and len(self.endpoints) < self.max_endpoints:
                url = to_visit.pop(0)
                
                # Skip if already visited
                if url in self.visited_urls:
                    continue
                
                self.visited_urls.add(url)
                
                # Fetch HTML from URL
                print(f"[*] Fetching homepage...")
                html = await self._fetch_html(url)
                if not html:
                    print(f"[-] Failed to fetch HTML from {url}")
                    continue
                
                print(f"[*] Fetched {len(html)} bytes from {url}")
                
                # Analyze HTML with LLM
                print(f"[*] Sending HTML to LLM...")
                discovered = await self._analyze_html_with_llm(html)
                if not discovered:
                    print(f"[-] LLM analysis returned no results")
                    continue
                
                # Process discovered endpoints
                endpoint_count = 0
                for ep_data in discovered.get("endpoints", []):
                    if len(self.endpoints) >= self.max_endpoints:
                        break
                    
                    ep_url = ep_data.get("url", "").strip()
                    if not ep_url:
                        continue
                    
                    # Convert relative URLs to absolute
                    abs_url = urljoin(self.target_url, ep_url)
                    
                    # Skip external URLs (not part of target domain)
                    if not abs_url.startswith(self.target_url):
                        print(f"[*] Skipping external URL: {abs_url}")
                        continue
                    
                    # Skip if already visited
                    if abs_url in self.visited_urls:
                        continue
                    
                    # Create Endpoint object
                    try:
                        endpoint = Endpoint(
                            url=abs_url,
                            method=ep_data.get("method", "GET").upper(),
                            params=ep_data.get("params", []),
                            auth_required=bool(ep_data.get("auth_required", False)),
                            roles_allowed=[]
                        )
                        # Dedup: skip if URL already in endpoints
                        if not any(e.url == endpoint.url for e in self.endpoints):
                            self.endpoints.append(endpoint)
                            
                            # Only crawl HTML pages, not API endpoints
                            # Skip /api/ and /rest/ from recursive crawling
                            if "/api/" not in abs_url and "/rest/" not in abs_url:
                                to_visit.append(abs_url)
                                print(f"[*] Added {abs_url} to crawl queue")
                            else:
                                print(f"[*] Added API endpoint (not crawling): {abs_url}")
                            
                            endpoint_count += 1
                        else:
                            print(f"[*] Skipping duplicate endpoint: {abs_url}")
                    except Exception as e:
                        print(f"[-] Failed to create endpoint: {e}")
                        pass
                
                print(f"[*] Parsed endpoints: {endpoint_count}")
            
            # Probe common paths before returning
            print("[*] Probing common paths...")
            async with httpx.AsyncClient() as client:
                await self._probe_common_paths(self.target_url, client)
            
            # Build AppMap
            app_map = AppMap(
                target_url=self.target_url,
                endpoints=self.endpoints,
                roles=self.session_store.all_roles() if self.session_store else []
            )
            print(f"[+] Crawl complete: discovered {len(self.endpoints)} endpoints")
            return app_map
        
        except Exception as e:
            print(f"[-] CRAWL ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
        
        # Return empty AppMap on failure
        return AppMap(target_url=self.target_url, endpoints=[], roles=[])
    
    async def _fetch_html(self, url: str) -> Optional[str]:
        """Fetch HTML content from URL via httpx async."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    timeout=self.timeout,
                    follow_redirects=True,
                    headers={"User-Agent": "LLMCrawler/1.0"}
                )
                if response.status_code == 200:
                    return response.text
                else:
                    print(f"[-] HTTP {response.status_code} from {url}")
        except Exception as e:
            print(f"[-] FETCH ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
        
        return None
    
    async def _analyze_html_with_llm(self, html: str) -> Optional[Dict[str, Any]]:
        """
        Send HTML to Llama 3.1 8B for endpoint discovery.
        Returns parsed JSON with discovered endpoints.
        """
        try:
            # Truncate HTML to avoid token limits
            html_snippet = html[:8000]
            
            prompt = f"""Analyze this HTML. List all endpoints, forms, links, API calls you see. Return JSON only:
{{"endpoints": [{{"url": "string", "method": "string", "params": [], "auth_required": boolean}}]}}

HTML:
{html_snippet}"""
            
            # Call LLM
            response = self.llm.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            print(f"[*] LLM raw response: {response_text[:200]}...")
            
            # Extract JSON from response
            json_str = response_text.strip()
            
            # Remove markdown code blocks if present
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            elif json_str.startswith("```"):
                json_str = json_str[3:]
            
            if json_str.endswith("```"):
                json_str = json_str[:-3]
            
            # Parse JSON
            data = json.loads(json_str.strip())
            return data
        
        except json.JSONDecodeError as e:
            print(f"[-] JSON PARSE ERROR: {e}")
            print(f"[-] Response was: {response_text[:500] if 'response_text' in locals() else 'N/A'}")
            traceback.print_exc()
            return None
        except Exception as e:
            print(f"[-] LLM ANALYSIS ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
            return None
    
    async def _probe_common_paths(self, base_url: str, client: httpx.AsyncClient):
        """Probe common paths and add discovered endpoints."""
        common_paths = [
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
            "/admin", "/swagger", "/swagger.json", "/openapi.json",
            "/.env", "/config", "/backup", "/debug", "/login",
            "/logout", "/register", "/profile", "/dashboard",
            "/api/v1/users", "/api/v1/products", "/api/v1/orders",
            "/api/v1/feedbacks", "/api/v1/complaints", "/api/v1/challenges"
        ]
        for path in common_paths:
            full_url = base_url.rstrip("/") + path
            try:
                r = await client.get(full_url, timeout=5.0)
                if r.status_code < 500:
                    print(f"[*] Probing found: {path} ({r.status_code})")
                    ep = Endpoint(url=full_url, method="GET", params=[], auth_required=False, roles_allowed=[])
                    if not any(e.url == full_url for e in self.endpoints):
                        self.endpoints.append(ep)
            except Exception:
                pass
