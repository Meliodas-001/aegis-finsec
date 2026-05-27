import requests
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os
import time

load_dotenv()

es = Elasticsearch(
    os.getenv("ELASTIC_URL"),
    api_key=os.getenv("ELASTIC_API_KEY")
)

VENDORS = ["node", "mongodb", "stripe", "plaid", "nginx", "express", "microsoft"]

def get_severity(cvss_score):
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    return "LOW"

def load_nvd():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    headers = {"apiKey": os.getenv("NVD_API_KEY")}
    count = 0

    for vendor in VENDORS:
        params = {
            "keywordSearch": vendor,
            "pubStartDate": "2023-01-01T00:00:00.000+00:00",
            "pubEndDate": "2024-12-31T23:59:59.000+00:00",
            "resultsPerPage": 100
        }

        try:
            response = requests.get(base_url, params=params, headers=headers)
            print(f"Status for {vendor}: {response.status_code}")
            data = response.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                if cvss_score < 7.0:
                    continue

                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                doc = {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": get_severity(cvss_score),
                    "vendor": vendor,
                    "product": vendor,
                    "published_date": cve.get("published", "")[:10],
                    "pci_relevant": True
                }

                es.index(index="aegis-cves", id=cve_id, body=doc)
                count += 1

            time.sleep(0.6)

        except Exception as e:
            print(f"Error for {vendor}: {e}")
            continue

    print(f"Loaded {count} additional CVEs from NVD")

if __name__ == "__main__":
    load_nvd()