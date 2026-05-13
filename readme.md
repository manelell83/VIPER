# ViperV2 — Intelligent Dynamic Network Scanner

# Final Year Cybersecurity Engineering Project

---

# Overview

This project is an intelligent automated penetration testing platform designed for cybersecurity engineering students.

The application dynamically discovers network devices, scans services and vulnerabilities, and generates a live topology of the infrastructure.

Unlike static scanners, this platform automatically detects the local subnet based on the selected network interface.

---

# Main Features

## Dynamic Local Network Discovery

- Automatic network interface detection
- Automatic subnet calculation
- Dynamic ARP discovery using Scapy
- Live host detection

## Port & Service Scanning

- Open port detection
- Service identification
- Version detection
- Basic OS fingerprinting

## Interactive Topology

- Real-time network graph
- Dynamic topology updates
- Zoom and pan support
- Live node rendering

## Multiple Scan Modes

### 1. Dynamic Local Scan
The system:
- detects interfaces
- calculates subnet automatically
- scans the local network dynamically

### 2. Domain/IP Scan
Manual target scanning:
- domain names
- IP addresses

---

# Technologies

## Backend

- Python
- FastAPI
- Scapy
- python-nmap
- NetworkX
- WebSockets
- SQLite

## Frontend

- React
- TailwindCSS
- Cytoscape.js

---

# Project Structure

```bash
project-root/
│
├── backend/
│   ├── app/
│   ├── scanners/
│   ├── topology/
│   ├── reports/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── package.json
│
├── docker/
│
├── docs/
│
└── README.md