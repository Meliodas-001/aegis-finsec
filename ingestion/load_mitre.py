import requests
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv
import os

load_dotenv()

es = Elasticsearch(
    os.getenv("ELASTIC_URL"),
    api_key=os.getenv("ELASTIC_API_KEY")
)

def create_ttpps_index():
    index_name = "aegis-ttpps"
    
    index_settings = {
        "number_of_shards": 1,
        "number_of_replicas": 0
    }
    
    index_mappings = {
        "properties": {
            "technique_id": {"type": "keyword"},
            "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "description": {"type": "text"},
            "tactics": {"type": "keyword"},
            "financial_relevant": {"type": "boolean"},
            "url": {"type": "keyword"}
        }
    }

    if not es.indices.exists(index=index_name):
        es.indices.create(
            index=index_name,
            settings=index_settings,
            mappings=index_mappings
        )
        print(f"Created index with explicit mappings: {index_name}")
    else:
        print(f"Index {index_name} already exists.")

def load_attack():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print("Fetching MITRE ATT&CK data...")
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Failed to fetch data from MITRE GitHub: {e}")
        return
    
    fin_relevant = [
        "T1190", "T1133", "T1078", "T1110", "T1055",
        "T1059", "T1547", "T1543", "T1053", "T1218",
        "T1552", "T1539", "T1528", "T1557", "T1562",
        "T1070", "T1027", "T1036", "T1041", "T1048",
        "T1567", "T1071", "T1105", "T1219", "T1486",
        "T1490", "T1485", "T1531", "T1489", "T1657"
    ]
    
    actions = []
    
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        
        ext_refs = obj.get("external_references", [])
        technique_id = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break
        
        if not technique_id:
            continue
            
        base_id = technique_id.split(".")[0]
        if base_id not in fin_relevant:
            continue
        
        raw_desc = obj.get("description", "")
        clean_desc = raw_desc[:700] + "..." if len(raw_desc) > 700 else raw_desc
        
        doc = {
            "_index": "aegis-ttpps",
            "_id": technique_id,
            "_source": {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": clean_desc,
                "tactics": [
                    phase["phase_name"].replace("-", " ").title()
                    for phase in obj.get("kill_chain_phases", [])
                ],
                "financial_relevant": True,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
            }
        }
        actions.append(doc)
    
    if actions:
        print(f"Indexing {len(actions)} financial ATT&CK techniques...")
        success, failed = helpers.bulk(es, actions, raise_on_error=False)
        print(f"Successfully loaded {success} techniques into aegis-ttpps. Errors: {len(failed)}")
    else:
        print("No matches discovered matching the current FinSec footprint.")

if __name__ == "__main__":
    create_ttpps_index()
    load_attack()