# Changelog

All notable changes to this project will be documented in this file.

---

## [1.0.0] - 2026-04-01

### 🚀 Major Release

This release marks the first stable version of Recon Scan Tool.

---

### ⚙️ Core Engine

- Async multi-target scanning engine
- Stage-based pipeline execution:
  - DISCOVERY → DNS → PORT → SERVICE → WEB → FINGERPRINT → VULNERABILITY
- Dependency-aware module execution
- Concurrency scheduler (target + module level)
- Scan profiles:
  - `fast`, `normal`, `deep`, `web`, `cellular`
- Resume support via persistent state
- Module filtering (`--enable`, `--disable`)

---

### 🧠 Intelligence Layer

- Centralized findings system
- Severity classification:
  - info, low, medium, high, critical
- Correlation engine:
  - multi-signal risk detection
  - service + exposure correlation
  - cellular detection correlation

---

### 📡 Cellular Awareness (NEW)

- Passive detection of:
  - LTE / 4G / 5G routers
  - Mobile hotspots
  - Cellular gateways
  - SIM/APN management interfaces

#### New Modules
- `cellular_detector`
- `modem_panel_finder`
- `cellular_vendor_fingerprint`

#### Correlated Findings
- Cellular management exposure
- Vendor + device signal fusion

---

### 🧩 Modules

#### Discovery
- host_discovery
- subdomain_enum
- admin_panel_finder

#### DNS
- dns_resolver
- reverse_dns

#### Ports
- port_scanner

#### Services
- banner_grabber
- service_detector

#### Web
- http_probe
- http_headers
- title_probe
- title_cluster
- tech_detect
- web_crawler
- favicon_hash
- modem_panel_finder

#### Fingerprint
- os_fingerprint
- tls_probe
- cellular_detector
- cellular_vendor_fingerprint

#### Vulnerability / Exposure
- exposure_checks
- correlation engine findings

---

### 📊 UI & Output

- Live Rich dashboard (primary UI)
- JSON report
- HTML report (severity badges, top findings, collapsible sections)
- Markdown report
- Graph export (JSON)
- Graph visualization (HTML)
- Graph summary (text)

---

### 💾 Persistence

- SQLite database:
  - scans
  - findings
  - target results
- Report index (`reports/index.json`)
- Resume state (`scan_state.json`)

---

### 📈 Improvements

- Scan-ID-based artifact naming
- Cleaner terminal UX (dashboard-only output)
- Structured findings pipeline
- Modular architecture alignment with real-world tools

---

### 🐛 Fixes

- Async execution issues
- Plugin loader validation
- Logger method gaps
- Import path issues
- Resume handling inconsistencies

---

## [0.x.x] - Pre-release

- Initial architecture
- Early module development
- Engine refactors
- Logging + reporting foundation
