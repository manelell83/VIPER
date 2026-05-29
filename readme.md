# ViperV2 — Intelligent Network Security Assessment Platform

> **Final Year Project (PFA) — Cybersecurity Engineering 2026**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://reactjs.org)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)](https://python.org)

---

## Overview

**ViperV2** is a full-stack, real-time network security assessment platform built for authorized penetration testing environments, academic labs, and GNS3 simulations.

It automatically discovers hosts, scans services, correlates CVEs from the National Vulnerability Database (NVD), builds dynamic attack graphs, assesses exploitability, generates remediation plans, and produces professional PDF security reports — all in real time via WebSocket streaming.

> **Disclaimer:** This tool is strictly for authorized security assessments, academic research, and defensive purposes only.

---

## Features

| Module | Description |
|---|---|
| **Network Discovery** | ARP sweep + ping fallback, auto-subnet detection |
| **Port Scanning** | Nmap integration with OS & service version detection |
| **CVE Correlation** | Real-time NVD API lookup, risk scoring per host |
| **Attack Graph** | Dynamic NetworkX-powered attack path generation (up to 6 hops) |
| **Exploitability Engine** | CVSS-based scoring + 25 famous CVEs (EternalBlue, Log4Shell, BlueKeep...) |
| **Remediation Engine** | 18 port-specific templates + CVE patch recommendations |
| **Security Reports** | 11-section PDF with executive summary, attack paths, exploitability, score |
| **Real-time Events** | Live WebSocket streaming of all scan phases |
| **Cytoscape Topology** | Interactive network graph with severity-based node coloring |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Frontend (Vite)                    │
│  Dashboard · Topology · Vulnerabilities · Attack Graph       │
│  Exploitability · Security Report · History · Reports        │
└─────────────────┬───────────────────────────────────────────┘
                  │ HTTP /api  +  WebSocket /ws
┌─────────────────▼───────────────────────────────────────────┐
│                   FastAPI Backend (Python)                    │
│                                                              │
│  ARP Scanner · Port Scanner (nmap) · Vuln Scanner (NVD API) │
│  Attack Graph (NetworkX) · Exploitability · Remediation      │
│  PDF Reports (ReportLab) · WebSocket events                  │
│                                                              │
│              SQLite + SQLAlchemy ORM (9 tables)              │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Windows

```powershell
# Backend
cd backend
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

# Frontend (new terminal)
cd frontend && npm install && npm run dev
```

Open http://localhost:5173

### Linux / macOS

```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

cd frontend && npm install && npm run dev
```

### Docker

```bash
docker compose up --build
# Frontend → http://localhost:3000
# API Docs → http://localhost:8001/docs
```

---

## Configuration

Create `backend/.env`:

```env
NVD_API_KEY=your_key_here   # optional, increases NVD rate limit
DEBUG=false
MAX_ATTACK_PATHS=30
MAX_ATTACK_HOPS=6
```

---

## API Reference

- **Swagger UI:** http://localhost:8001/docs
- **WebSocket:** `ws://localhost:5173/ws/{scan_id}`

| Method | Endpoint | Description |
|---|---|---|
| POST | `/scan/network` | Start LAN scan |
| POST | `/scan/domain` | Start IP/domain scan |
| GET | `/topology/{scan_id}` | Cytoscape topology data |
| GET | `/vulnerabilities?scan_id=` | CVE list |
| GET | `/attack-graph/{scan_id}` | Attack graph + paths |
| GET | `/exploitability/security-summary?scan_id=` | Full security assessment |
| GET | `/reports/export/{scan_id}/pdf` | PDF report |

---

## GNS3 Integration

1. Add a **Cloud** node in GNS3 connected to your VMnet interface
2. Start ViperV2, select the VMnet adapter in **Network Scan**
3. All GNS3 nodes are discovered automatically via ARP/ping sweep
4. Full vulnerability + attack graph analysis runs on simulated infrastructure

Tested with VMware VMnet, VirtualBox Host-Only, and GNS3 multi-router labs.

---

## Project Structure

```
viperv2/
├── backend/
│   ├── app/
│   │   ├── api/routes/            # 7 route modules, 30+ endpoints
│   │   ├── scanners/              # ARP, port, scan orchestration
│   │   ├── vulnerability_scanner/ # NVD API, CVE scoring
│   │   ├── attack_graph/          # Graph builder, path engine
│   │   ├── exploitability/        # Maturity scoring, remediation
│   │   ├── models/                # ORM models
│   │   └── core/                  # Config, database
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/                 # 11 pages
│   │   ├── components/            # Layout, topology, attack, exploitability
│   │   ├── hooks/                 # useScan (WS state machine)
│   │   └── services/              # Axios API client, WS factory
│   └── vite.config.js
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
└── docker-compose.yml
```

---

## Academic Context

**Type:** Projet de Fin d'Année (PFA)  
**Domain:** Cybersecurity Engineering  
**Year:** 2025–2026  

Technologies demonstrated: React 18, FastAPI, SQLAlchemy, NetworkX, CVSS v3, WebSocket, Cytoscape.js, ReportLab, Docker, ARP/TCP/IP networking.

