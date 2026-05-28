# AEGIS — Autonomous Financial Threat Intelligence Agent

> The $500K PCI-DSS fine starts with a CVE nobody caught. AEGIS catches them, maps them to compliance requirements, and reports automatically.

## 🔴 Live Demo
**[https://aegis-finsec-production.up.railway.app](https://aegis-finsec-production.up.railway.app)**

## What AEGIS Does
AEGIS is an autonomous threat intelligence agent for fintech teams. It monitors your payment stack (Node.js, MongoDB, Stripe SDK, Plaid SDK) for critical CVEs, maps each vulnerability to the exact PCI-DSS v4.0 requirement it threatens, and runs four playbooks without being prompted.

## 4 Autonomous Playbooks

| Playbook | Description |
|---|---|
| **Daily Threat Brief** | New CVEs affecting your registered fintech stack |
| **PCI-DSS Compliance Report** | CVEs mapped to exact PCI-DSS v4.0 requirements |
| **Active Threat Intelligence** | Live IOCs from URLhaus targeting payment infrastructure |
| **Agent Architecture** | Full system overview and data sources |

## Architecture
```text
CISA KEV + NVD + URLhaus
           ↓
Elastic Search (MCP Server)
           ↓
Gemini + Google Cloud Agent Builder
           ↓
Flask API (4 Playbook Endpoints)
           ↓
AEGIS Dashboard (Railway)
```

## Tech Stack
- **AI**: Gemini via Google Cloud Agent Builder
- **Search**: Elastic Cloud Serverless (MCP Server) — GCP us-central1
- **Data**: 379 CVEs (CISA KEV + NVD) · 21,588 IOCs (URLhaus)
- **Compliance**: 15 CVEs manually mapped to PCI-DSS v4.0 requirements
- **Backend**: Python · Flask · Elasticsearch Python SDK
- **Deploy**: Railway · Docker

## API Endpoints
```text
GET /                           → Dashboard UI
GET /health                     → Health check
GET /playbook/daily-brief       → Top 10 critical CVEs for fintech stacks
GET /playbook/compliance-report → PCI-DSS compliance mapping
GET /playbook/active-threats    → Live IOC feed
```

## Local Setup
```bash
git clone https://github.com/Meliodas-001/aegis-finsec
cd aegis-finsec
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
cp .env.example .env         # Fill in your keys
python api/app.py
```

**Required environment variables (add to `.env`):**
```env
ELASTIC_URL=your_elastic_endpoint
ELASTIC_API_KEY=your_api_key
GCP_PROJECT_ID=your_project_id
NVD_API_KEY=your_nvd_key
```

## Hackathon
Built for the Google Cloud + Gemini Agent Hackathon — Elastic Track · Financial Services Theme.

## License
MIT