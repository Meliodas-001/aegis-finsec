import requests
import json
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os

load_dotenv()

es = Elasticsearch(
    os.getenv("ELASTIC_URL"),
    api_key=os.getenv("ELASTIC_API_KEY")
)

VENDORS = ["microsoft", "node", "mongodb", "stripe", "plaid", "nginx", "express"]

def create_index():
    if not es.indices.exists(index="aegis-cves"):
        es.indices.create(index="aegis-cves", body={
            "mappings": {
                "properties": {
                    "cve_id": {"type": "keyword"},
                    "description": {"type": "text"},
                    "cvss_score": {"type": "float"},
                    "severity": {"type": "keyword"},
                    "vendor": {"type": "keyword"},
                    "product": {"type": "keyword"},
                    "published_date": {"type": "date"},
                    "pci_relevant": {"type": "boolean"}
                }
            }
        })
        print("Index aegis-cves created")

def load_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()
    
    count = 0
    for vuln in data["vulnerabilities"]:
        vendor = vuln.get("vendorProject", "").lower()
        if any(v in vendor for v in VENDORS):
            doc = {
                "cve_id": vuln.get("cveID"),
                "description": vuln.get("shortDescription"),
                "severity": "HIGH",
                "vendor": vendor,
                "product": vuln.get("product", ""),
                "published_date": vuln.get("dateAdded"),
                "pci_relevant": True
            }
            es.index(index="aegis-cves", id=doc["cve_id"], body=doc)
            count += 1
    
    print(f"Loaded {count} CVEs from CISA KEV")

if __name__ == "__main__":
    create_index()
    load_kev()