# Recon Scan Tool

**Recon Scan Tool** is an asynchronous modular reconnaissance framework for network and web attack-surface discovery.

It combines:
- staged async execution
- dependency-aware modules
- live dashboard output
- findings correlation
- graph generation
- report generation
- scan persistence and history

## Features

- Async multi-target scanning
- Profiles: `fast`, `normal`, `deep`, `web`
- Dependency-aware module scheduling
- Live Rich dashboard
- JSON, HTML, and Markdown reports
- Graph export and browser graph viewer
- SQLite scan history
- Resume support
- Module enable/disable filtering
- Report index and scan history
- Correlated risk findings

## Included modules

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

### Fingerprinting
- OS fingerprinting
- TLS probing

### Vulnerability / Exposure
- Passive exposure checks
- Correlated risk findings

## Requirements

- Python 3.10+
- Recommended: virtual environment

Install dependencies:

```bash
pip install -r requirements.txt