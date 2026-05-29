from flask import Flask, jsonify, render_template
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

# Load static PCI mapping data
with open("data/pci_dss_map.json") as f:
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
        # v8.x compliant search (no body={} parameter)
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
            cve_entry = {
                "cve_id": cve_id,
                "severity": doc.get("severity"),
                "vendor": doc.get("vendor"),
                "description": doc.get("description"),
                "published_date": doc.get("published_date"),
                "pci_requirement": pci_info["pci_requirement"] if pci_info else None,
                "pci_title": pci_info["requirement_title"] if pci_info else None,
                "remediation": pci_info["remediation"] if pci_info else None
            }
            cves.append(cve_entry)

        return jsonify({
            "playbook": "Daily Threat Brief",
            "total_threats": len(cves),
            "cves": cves
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/playbook/compliance-report", methods=["GET"])
def compliance_report():
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

@app.route("/playbook/active-threats", methods=["GET"])
def active_threats():
    try:
        result = es.search(
            index="aegis-iocs",
            query={"match_all": {}},
            size=15
        )
        iocs = []
        for hit in result["hits"]["hits"]:
            doc = hit["_source"]
            iocs.append({
                "ioc_value": doc.get("ioc_value"),
                "threat_actor": doc.get("threat_actor"),
                "tags": doc.get("tags", []),
                "date_added": doc.get("date_added")
            })
        return jsonify({
            "playbook": "Active Fintech Threats (IOCs)",
            "total_monitored": result["hits"]["total"]["value"],
            "recent_iocs": iocs
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/playbook/threat-hunt", methods=["GET"])
def threat_hunt():
    try:
        # Pull MITRE ATT&CK techniques relevant to fintech (v8.x compliant)
        result = es.search(
            index="aegis-ttpps",
            query={"term": {"financial_relevant": True}},
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
            
        # Cross-reference with CVEs in aegis-cves (v8.x compliant)
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)