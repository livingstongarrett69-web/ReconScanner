# Recon Scan Tool

**Recon Scan Tool v1.0.0**  
_Asynchronous Modular Reconnaissance & Attack Surface Mapping Framework_

Recon Scan Tool is a high-performance, modular reconnaissance framework for discovering network and web attack surfaces.

It combines:

- async staged scanning
- dependency-aware modules
- live dashboard UI
- structured findings pipeline
- correlation engine
- graph-based visualization
- persistent scan history

---

## 🚀 Features

### Core Engine
- Persistent scan state and resume capability
- Scan-ID-based artifact naming
- Async multi-target scanning
- Stage-based pipeline execution
- Dependency-aware module scheduling
- Scan profiles: `fast`, `normal`, `deep`, `web`, `cellular`
- Resume interrupted scans
- Module enable/disable filtering

### Intelligence Layer
- Structured findings system
- Correlation engine (multi-signal risk detection)
- Recent findings tracking
- Severity classification (`info` → `critical`)

### Output & Visualization
- Live Rich dashboard (primary UI)
- JSON, HTML, Markdown reports
- Graph export (JSON)
- Interactive graph viewer (HTML)
- Graph summary reports

### Persistence
- SQLite scan database
- Scan history index
- Per-target result storage

---

## 📡 Cellular Awareness (New)

### Why it matters

Cellular-connected devices are often:
- externally exposed
- weakly secured
- overlooked in traditional recon

This feature helps surface:
- hidden attack surface
- unmanaged network edges
- shadow IT infrastructure

Recon Scan Tool now includes **passive cellular device detection**.

### Detects:
- LTE / 4G / 5G routers
- Mobile hotspots
- Cellular gateways (CPE devices)
- SIM/APN management interfaces
- Cellular vendor fingerprints

### Modules Added:
- `cellular_detector` → identifies probable cellular devices
- `modem_panel_finder` → detects modem/admin panels
- `cellular_vendor_fingerprint` → identifies device vendor

### Correlation Engine Enhancements:
- Detects **cellular management exposure**
- Combines signals across:
  - HTTP responses
  - panel detection
  - vendor fingerprinting

---

## 🧩 Module Coverage

### Discovery
- Host discovery
- Subdomain enumeration
- Admin panel discovery

### DNS
- DNS resolution
- Reverse DNS

### Ports
- Port scanning

### Services
- Banner grabbing
- Service detection

### Web
- HTTP probing
- HTTP headers
- Title probing
- Title clustering
- Technology detection
- Web crawling
- Favicon hashing
- Modem/admin panel detection

### Fingerprinting
- OS fingerprinting
- TLS probing
- Cellular device detection
- Cellular vendor fingerprinting

### Vulnerability / Exposure
- Passive exposure checks
- Correlated risk findings

---

## 🧪 Project Value

This project demonstrates:

- Offensive security tool design
- Async systems architecture
- Modular plugin frameworks
- Real-world recon workflows
- Data correlation and analysis
- Attack surface mapping concepts

## ⚙️ Requirements

- Python 3.10+
- Recommended: virtual environment

Install dependencies:

```bash
pip install -r requirements.txt
