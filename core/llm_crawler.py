import asyncio
import httpx
import json
import os
from typing import List, Optional, Dict, Any, Set
from langchain_groq import ChatGroq
from shared.models import AppMap, Endpoint


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
                html = await self._fetch_html(url)
                if not html:
                    continue
                
                # Analyze HTML with LLM
                discovered = await self._analyze_html_with_llm(html)
                if not discovered:
                    continue
                
                # Process discovered endpoints
                for ep_data in discovered.get("endpoints", []):
                    if len(self.endpoints) >= self.max_endpoints:
                        break
                    
                    ep_url = ep_data.get("url", "").strip()
                    if not ep_url or ep_url in self.visited_urls:
                        continue
                    
                    # Create Endpoint object
                    try:
                        endpoint = Endpoint(
                            url=ep_url,
                            method=ep_data.get("method", "GET").upper(),
                            params=ep_data.get("params", []),
                            auth_required=bool(ep_data.get("auth_required", False))
                        )
                        self.endpoints.append(endpoint)
                        to_visit.append(ep_url)
                    except Exception:
                        pass
            
            # Build AppMap
            app_map = AppMap(
                target_url=self.target_url,
                endpoints=self.endpoints
            )
            return app_map
        
        except Exception:
            pass
        
        # Return empty AppMap on failure
        return AppMap(target_url=self.target_url, endpoints=[])
    
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
        except Exception:
            pass
        
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
        
        except Exception:
            pass
        
        return None
