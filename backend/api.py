from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from dotenv import load_dotenv
import asyncio, uuid, json

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- In-memory scan state ---
scan_state = {
    "phase": "idle",
    "progress": 0,
    "current_action": "",
    "endpoints": [],
    "vulns": [],
    "graph": {"nodes": [], "edges": []},
    "logs": [],
    "report": ""
}

# --- Request models ---
class RoleCredential(BaseModel):
    username: str
    password: str
    role: str

class ScanRequest(BaseModel):
    target_url: str
    roles: List[RoleCredential]

# --- Routes ---
@app.post("/scan/start")
async def start_scan(req: ScanRequest):
    scan_state["phase"] = "starting"
    scan_state["progress"] = 0
    scan_state["logs"] = []
    scan_state["vulns"] = []
    scan_state["endpoints"] = []
    scan_state["graph"] = {"nodes": [], "edges": []}

    asyncio.create_task(run_scan(req))
    return {"scan_id": str(uuid.uuid4())}

@app.get("/scan/status")
def get_status():
    return {
        "phase": scan_state["phase"],
        "progress": scan_state["progress"],
        "current_action": scan_state["current_action"]
    }

@app.get("/scan/endpoints")
def get_endpoints():
    return scan_state["endpoints"]

@app.get("/scan/vulns")
def get_vulns():
    return scan_state["vulns"]

@app.get("/scan/graph")
def get_graph():
    return scan_state["graph"]

@app.get("/scan/report")
def get_report():
    return {"markdown": scan_state["report"]}

@app.get("/scan/stream")
async def stream_logs():
    async def event_generator():
        sent = 0
        while scan_state["phase"] not in ["done", "error"]:
            logs = scan_state["logs"]
            while sent < len(logs):
                yield f"data: {logs[sent]}\n\n"
                sent += 1
            await asyncio.sleep(0.5)
        # flush remaining
        logs = scan_state["logs"]
        while sent < len(logs):
            yield f"data: {logs[sent]}\n\n"
            sent += 1
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# --- Background scan runner ---
async def run_scan(req: ScanRequest):
    try:
        from shared.models import AppMap, Endpoint, AttackResult
        from agent.agent_loop import build_agent

        scan_state["phase"] = "crawling"
        scan_state["progress"] = 10
        scan_state["current_action"] = "Crawling target application..."
        scan_state["logs"].append(f"Starting scan on {req.target_url}")

        # Placeholder endpoints until M2 crawler is ready
        placeholder_endpoints = [
            {
                "id": "ep_1",
                "url": f"{req.target_url}/api/users/1",
                "method": "GET",
                "params": {"id": "1"},
                "auth_required": True,
                "roles_allowed": [r.role for r in req.roles]
            }
        ]
        scan_state["endpoints"] = placeholder_endpoints
        scan_state["logs"].append(f"Discovered {len(placeholder_endpoints)} endpoints")

        scan_state["phase"] = "hypothesizing"
        scan_state["progress"] = 30
        scan_state["current_action"] = "Generating attack hypotheses..."

        app_map = AppMap(
            target_url=req.target_url,
            endpoints=[
                Endpoint(
                    url=ep["url"],
                    method=ep["method"],
                    params=ep["params"],
                    auth_required=ep["auth_required"],
                    roles_allowed=ep["roles_allowed"]
                ) for ep in placeholder_endpoints
            ],
            roles=[r.role for r in req.roles]
        )

        scan_state["phase"] = "attacking"
        scan_state["progress"] = 50
        scan_state["current_action"] = "Running attack chain..."

        dummy_result = AttackResult(
            endpoint=app_map.endpoints[0],
            payload={"id": "2"},
            response_code=200,
            response_body='{"id":2,"email":"victim@juice-sh.op","role":"customer"}',
            diff_from_baseline="Length diff: 50 chars."
        )

        scan_state["phase"] = "analyzing"
        scan_state["progress"] = 70
        scan_state["current_action"] = "Analyzing results..."

        agent = build_agent()
        final_state = agent.invoke({
            "app_map": app_map,
            "hypotheses": [],
            "attack_results": [dummy_result],
            "confirmed_vulns": [],
            "logs": []
        })

        for log in final_state["logs"]:
            scan_state["logs"].append(log)

        scan_state["vulns"] = final_state["confirmed_vulns"]

        # Build graph from vulns
        nodes, edges = [], []
        for vuln in final_state["confirmed_vulns"]:
            n_id = vuln["id"]
            nodes.append({"id": n_id, "label": vuln["type"], "type": "vuln"})
            ep_id = f"ep_{n_id}"
            nodes.append({"id": ep_id, "label": vuln["chain"][0]["endpoint"]["url"], "type": "endpoint"})
            edges.append({"source": ep_id, "target": n_id, "label": "exploited via"})

        scan_state["graph"] = {"nodes": nodes, "edges": edges}

        # Build markdown report
        report = f"# VEGA Scan Report\n\nTarget: {req.target_url}\n\n"
        for vuln in final_state["confirmed_vulns"]:
            report += f"## {vuln['type']} [{vuln['severity']}]\n\n"
            report += f"**Evidence:** {vuln['evidence']}\n\n"
            report += f"**Narrative:**\n{vuln['narrative']}\n\n---\n\n"
        scan_state["report"] = report

        scan_state["phase"] = "done"
        scan_state["progress"] = 100
        scan_state["current_action"] = "Scan complete"
        scan_state["logs"].append("Scan complete.")

    except Exception:
        import traceback
        scan_state["phase"] = "error"
        scan_state["logs"].append(f"Error detail: {traceback.format_exc()}")
