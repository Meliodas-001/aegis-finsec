import requests
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv
import os
import csv

load_dotenv()

es = Elasticsearch(os.getenv("ELASTIC_URL"), api_key=os.getenv("ELASTIC_API_KEY"))

def create_ioc_index():
    if not es.indices.exists(index="aegis-iocs"):
        es.indices.create(index="aegis-iocs")
        print("Created index: aegis-iocs")
    else:
        print("Index aegis-iocs already exists")

def load_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    print("Fetching recent IOCs from URLhaus...")
    response = requests.get(url)
    
    # FIX: Explicitly define the CSV headers. 
    headers = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    
    # Filter out comments but keep the raw data lines
    lines = [line for line in response.text.splitlines() if not line.startswith('#') and line.strip()]
    
    if not lines:
        print("Could not find valid CSV data.")
        return

    print(f"Data rows found: {len(lines)}")
    
    # Pass the headers directly to DictReader
    reader = csv.DictReader(lines, fieldnames=headers)
    actions = []
    
    for row in reader:
        try:
            ioc_value = row.get("url", "").strip()
            if not ioc_value:
                continue
                
            date_added = row.get("dateadded", "").split(" ")[0] if row.get("dateadded") else ""
            
            doc = {
                "_index": "aegis-iocs",
                "_source": {
                    "ioc_value": ioc_value,
                    "ioc_type": "url",
                    "threat_actor": row.get("threat", "unknown").strip(),
                    "source": "abuse.ch URLhaus",
                    "date_added": date_added if date_added else None,
                    "tags": row.get("tags", "").split(",") if row.get("tags") else []
                }
            }
            actions.append(doc)
            
        except Exception as e:
            print(f"Error parsing row: {e}")
            continue

    if actions:
        print(f"Bulk indexing {len(actions)} IOCs to Elasticsearch...")
        try:
            success, _ = helpers.bulk(es, actions)
            print(f"Successfully loaded {success} IOCs into AEGIS.")
        except Exception as e:
            print(f"Failed to index IOCs: {e}")
    else:
        print("No valid IOCs to index.")

if __name__ == "__main__":
    create_ioc_index()
    load_urlhaus()