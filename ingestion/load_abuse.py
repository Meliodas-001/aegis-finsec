import requests
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os
import csv
import io

load_dotenv()

es = Elasticsearch(
    os.getenv("ELASTIC_URL"),
    api_key=os.getenv("ELASTIC_API_KEY")
)

def create_ioc_index():
    if not es.indices.exists(index="aegis-iocs"):
        es.indices.create(index="aegis-iocs", body={
            "mappings": {
                "properties": {
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "threat_actor": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "date_added": {"type": "date"},
                    "tags": {"type": "keyword"}
                }
            }
        })
        print("Index aegis-iocs created")
    else:
        print("Index aegis-iocs already exists")

def load_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    response = requests.get(url)
    
    count = 0
    lines = response.text.splitlines()
    # Skip comment lines starting with #
    data_lines = [l for l in lines if not l.startswith("#")]
    reader = csv.DictReader(data_lines)
    
    for row in reader:
        try:
            doc = {
                "ioc_value": row.get("url", ""),
                "ioc_type": "url",
                "threat_actor": row.get("threat", "unknown"),
                "source": "abuse.ch URLhaus",
                "date_added": row.get("dateadded", "").split(" ")[0],
                "tags": row.get("tags", "").split(",") if row.get("tags") else []
            }
            if doc["ioc_value"]:
                es.index(index="aegis-iocs", body=doc)
                count += 1
        except Exception as e:
            continue

    print(f"Loaded {count} IOCs from URLhaus")

if __name__ == "__main__":
    create_ioc_index()
    load_urlhaus()