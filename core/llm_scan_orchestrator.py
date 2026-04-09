import asyncio
from typing import List, Dict, Any, Optional
from shared.models import AppMap, AttackResult
from core.llm_crawler import LLMCrawler
from core.llm_payload_generator import LLMPayloadGenerator
from core.llm_result_analyzer import LLMResultAnalyzer
from core.request_engine import execute_attack
from core.auth_handler import login_all_roles


class LLMScanOrchestrator:
    """Orchestrates complete LLM-powered security scan."""
    
    def __init__(self, target_url: str, credentials: List[Dict[str, str]]):
        """
        Initialize scan orchestrator.
        
        Args:
            target_url: Target URL to scan
            credentials: List of dicts with username, password, role
        """
        self.target_url = target_url
        self.credentials = credentials
        self.session_store = None
        self.app_map: Optional[AppMap] = None
        self.confirmed_vulns: List[Dict[str, Any]] = []
        self.all_attacks: List[Dict[str, Any]] = []
    
    async def run_scan(self) -> Dict[str, Any]:
        """
        Execute full security scan pipeline.
        
        Returns:
            Report dict with target, endpoints, attacks, vulnerabilities, narrative
        """
        try:
            # Step 1: Authenticate all roles
            print("[*] Step 1: Authenticating all roles...")
            try:
                self.session_store = await login_all_roles(self.credentials)
                print("[+] Authentication successful")
            except Exception:
                print("[-] Authentication failed, continuing without session")
                self.session_store = None
            
            # Step 2: Crawl endpoints
            print("[*] Step 2: Crawling endpoints...")
            try:
                crawler = LLMCrawler(self.target_url, self.session_store)
                self.app_map = await crawler.crawl()
                print(f"[+] Discovered {len(self.app_map.endpoints)} endpoints")
            except Exception:
                print("[-] Crawling failed")
                return self._build_report()
            
            # Step 3: Generate payloads and execute attacks
            print("[*] Step 3: Generating payloads and executing attacks...")
            payload_gen = LLMPayloadGenerator()
            analyzer = LLMResultAnalyzer()
            
            attack_count = 0
            
            for endpoint in self.app_map.endpoints:
                try:
                    # Generate payloads for endpoint
                    payloads = payload_gen.generate(endpoint)
                    
                    for payload in payloads:
                        try:
                            # Execute attack
                            attack_result = await execute_attack(
                                endpoint=endpoint,
                                payload=payload,
                                session_store=self.session_store
                            )
                            attack_count += 1
                            
                            # Analyze result
                            analysis = analyzer.analyze(attack_result)
                            
                            # Track attack
                            attack_entry = {
                                "endpoint": endpoint.url,
                                "method": endpoint.method,
                                "payload_type": payload.get("type", "unknown"),
                                "param": payload.get("param", ""),
                                "is_vulnerable": analysis["is_vulnerable"],
                                "confidence": analysis["confidence"],
                                "reason": analysis["reason"]
                            }
                            self.all_attacks.append(attack_entry)
                            
                            # Store confirmed vulnerabilities (confidence > 70)
                            if analysis["is_vulnerable"] and analysis["confidence"] > 70:
                                vuln_entry = {
                                    "endpoint": endpoint.url,
                                    "method": endpoint.method,
                                    "type": payload.get("type", "unknown"),
                                    "param": payload.get("param", ""),
                                    "confidence": analysis["confidence"],
                                    "reason": analysis["reason"],
                                    "payload_value": payload.get("value", "")
                                }
                                self.confirmed_vulns.append(vuln_entry)
                                print(f"[!] VULNERABILITY: {vuln_entry['type']} at {endpoint.url}")
                        
                        except Exception:
                            pass
                
                except Exception:
                    pass
            
            print(f"[+] Executed {attack_count} attacks")
            print(f"[+] Found {len(self.confirmed_vulns)} confirmed vulnerabilities")
            
            # Step 4: Generate narrative for confirmed vulnerabilities
            print("[*] Step 4: Generating vulnerability narrative...")
            narrative = ""
            if self.confirmed_vulns:
                try:
                    narrative = analyzer.generate_narrative(self.confirmed_vulns)
                    print("[+] Narrative generated")
                except Exception:
                    print("[-] Narrative generation failed")
            
            # Step 5: Build final report
            print("[*] Step 5: Building final report...")
            report = self._build_report()
            report["narrative"] = narrative
            
            print("[+] Scan complete")
            return report
        
        except Exception:
            pass
        
        return self._build_report()
    
    def _build_report(self) -> Dict[str, Any]:
        """Build final report dict."""
        endpoint_count = len(self.app_map.endpoints) if self.app_map else 0
        
        return {
            "target": self.target_url,
            "total_endpoints": endpoint_count,
            "total_attacks": len(self.all_attacks),
            "vulnerabilities_found": len(self.confirmed_vulns),
            "vulnerabilities": self.confirmed_vulns,
            "narrative": ""
        }


# Async runner for CLI
async def run_orchestrator(target_url: str, credentials: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Run orchestrator and return report.
    
    Args:
        target_url: Target URL to scan
        credentials: List of role credentials
    
    Returns:
        Final report dict
    """
    orchestrator = LLMScanOrchestrator(target_url, credentials)
    report = await orchestrator.run_scan()
    return report
