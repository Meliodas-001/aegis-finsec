from flask import Flask, jsonify, request, render_template
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
    result = es.search(index="aegis-cves", body={
        "query": {
            "terms": {
                "severity": ["CRITICAL", "HIGH"]
            }
        },
        "sort": [{"published_date": {"order": "desc"}}],
        "size": 10
    })

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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)