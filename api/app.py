from flask import Flask, jsonify, render_template, request
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import json
import os

load_dotenv()

app = Flask(__name__)

es = Elasticsearch(
    os.getenv("ELASTIC_URL"),
    api_key=os.getenv("ELASTIC_API_KEY")
)

# Dynamic path resolution to ensure Railway finds the data folder
base_dir = os.path.dirname(os.path.dirname(__file__))
with open(os.path.join(base_dir, "data", "pci_dss_map.json")) as f:
    PCI_MAP = json.load(f)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/playbook/daily-brief", methods=["GET"])
def daily_brief():
    try:
        result = es.search(
            index="aegis-cves",
            query={"terms": {"severity": ["CRITICAL", "HIGH"]}},
            sort=[{"published_date": {"order": "desc"}}],
            size=10
        )

        cves = []
        for hit in result["hits"]["hits"]:
            doc = hit["_source"]
            cve_id = doc.get("cve_id", "")
            pci_info = PCI_MAP.get(cve_id, None)
            cves.append({
                "cve_id": cve_id,
                "severity": doc.get("severity"),
                "description": doc.get("description"),
                "pci_compliance": pci_info
            })
            
        return jsonify({
            "playbook": "Daily Threat Brief",
            "total_threats": len(cves),
            "cves": cves
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/playbook/active-threats", methods=["GET"])
def active_threats():
    try:
        result = es.search(index="aegis-iocs", query={"match_all": {}}, size=10)
        iocs = [hit["_source"] for hit in result["hits"]["hits"]]
        
        return jsonify({
            "playbook": "Active Fintech Threats (IOCs)",
            "total_monitored": result["hits"]["total"]["value"],
            "recent_iocs": iocs
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/playbook/mitre-hunt", methods=["GET"])
def mitre_hunt():
    try:
        result = es.search(
            index="aegis-ttpps",
            query={"match_all": {}},
            sort=[{"technique_id.keyword": {"order": "asc"}}],
            size=20
        )
        
        techniques = []
        for hit in result["hits"]["hits"]:
            doc = hit["_source"]
            desc = doc.get("description", "")
            techniques.append({
                "technique_id": doc.get("technique_id"),
                "name": doc.get("name"),
                "tactics": doc.get("tactics", []),
                "description": desc[:200] + ("..." if len(desc) > 200 else ""),
                "url": doc.get("url")
            })
            
        cve_result = es.search(
            index="aegis-cves",
            query={"term": {"severity": "CRITICAL"}},
            size=5
        )
        
        critical_cves = [
            hit["_source"].get("cve_id")
            for hit in cve_result["hits"]["hits"]
        ]
        
        return jsonify({
            "playbook": "Threat Hunt — MITRE ATT&CK Financial Services",
            "total_techniques_monitored": result["hits"]["total"]["value"],
            "active_critical_cves": len(critical_cves),
            "top_critical_cves": critical_cves,
            "techniques": techniques
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/playbook/compliance-report", methods=["GET"])
def compliance_report():
    try:
        mapped = []
        for cve_id, pci_info in PCI_MAP.items():
            mapped.append({
                "cve_id": cve_id,
                "pci_requirement": pci_info["pci_requirement"],
                "requirement_title": pci_info["requirement_title"],
                "risk": pci_info["risk"],
                "remediation": pci_info["remediation"]
            })
        return jsonify({
            "playbook": "PCI-DSS Compliance Report",
            "total_mapped": len(mapped),
            "report": mapped
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/mcp", methods=["GET", "POST"])
def mcp_server():
    if request.method == "GET":
        return jsonify({"status": "MCP Server online"})
    
    try:
        data = request.get_json() or {}
        method = data.get("method", "")
        params = data.get("params", {})
        req_id = data.get("id")
        
        # MCP Handshake
        if method == "initialize":
            return jsonify({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "AEGIS", "version": "1.0.0"}
                }
            })
            
        # Tool Discovery Schema
        if method == "tools/list":
            return jsonify({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {"name": "searchCVEs", "description": "Search CVEs affecting fintech stacks", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                        {"name": "searchIOCs", "description": "Search malicious IOC URLs", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                        {"name": "searchMITRE", "description": "Search MITRE ATT&CK techniques", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                        {"name": "complianceReport", "description": "Get PCI-DSS compliance mapping", "inputSchema": {"type": "object", "properties": {}}}
                    ]
                }
            })
            
        # Tool Calls Execution Engine
        if method == "tools/call":
            tool_name = params.get("name")
            
            if tool_name == "searchCVEs":
                result = es.search(index="aegis-cves", size=10)
                hits = [h["_source"] for h in result["hits"]["hits"]]
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(hits)}]}})
                
            elif tool_name == "searchIOCs":
                result = es.search(index="aegis-iocs", size=10)
                hits = [h["_source"] for h in result["hits"]["hits"]]
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(hits)}]}})
                
            elif tool_name == "searchMITRE":
                result = es.search(index="aegis-ttpps", size=10)
                hits = [h["_source"] for h in result["hits"]["hits"]]
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(hits)}]}})
                
            elif tool_name == "complianceReport":
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(PCI_MAP)}]}})
                
            else:
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Tool {tool_name} not found"}], "isError": True}})
                
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {}})
        
    except Exception as e:
        return jsonify({
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "result": {
                "content": [{"type": "text", "text": f"Elastic Engine Exception: {str(e)}"}],
                "isError": True
            }
        })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))