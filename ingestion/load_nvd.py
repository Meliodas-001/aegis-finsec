import requests
from elasticsearch import Elasticsearch, helpers
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

def create_cve_index():
    if not es.indices.exists(index="aegis-cves"):
        es.indices.create(index="aegis-cves")
        print("Created index: aegis-cves")

def load_nvd():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    create_cve_index()
    actions = []
    
    # Grab the API key from the environment
    nvd_api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    
    if not nvd_api_key:
        print("WARNING: No NVD_API_KEY found in .env. Rate limits will be severe.")

    for vendor in VENDORS:
        print(f"Fetching CVEs for {vendor}...")
        
        # FIXED: Added the +00:00 timezone offset per strict NVD requirements
        params = {
            "keywordSearch": vendor,
            "pubStartDate": "2023-01-01T00:00:00.000+00:00",
            "pubEndDate": "2024-12-31T23:59:59.000+00:00",
            "resultsPerPage": 100
        }

        try:
            # FIXED: Passing the headers containing the API key
            response = requests.get(base_url, params=params, headers=headers)
            
            if response.status_code != 200:
                print(f"NVD API Error for {vendor} (Status {response.status_code}). Skipping...")
                time.sleep(6)
                continue
                
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            print(f"Found {len(vulnerabilities)} raw records for {vendor}")

            for item in vulnerabilities:
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
                    "_index": "aegis-cves",
                    "_id": cve_id, 
                    "_source": {
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": get_severity(cvss_score),
                        "vendor": vendor,
                        "product": vendor,
                        "published_date": cve.get("published", "")[:10],
                        "pci_relevant": True
                    }
                }
                actions.append(doc)

            # Optimization: With an API key, we can safely sleep for just 1 second
            sleep_time = 1 if nvd_api_key else 6
            time.sleep(sleep_time) 

        except Exception as e:
            print(f"Error processing {vendor}: {e}")
            continue

    if actions:
        print(f"\nBulk indexing {len(actions)} High/Critical CVEs to Elasticsearch...")
        try:
            success, _ = helpers.bulk(es, actions)
            print(f"Successfully loaded {success} CVEs into AEGIS.")
        except Exception as e:
            print(f"Failed to index CVEs: {e}")
    else:
        print("No valid CVEs found to index.")

if __name__ == "__main__":
    load_nvd()