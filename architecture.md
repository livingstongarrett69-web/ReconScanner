# Architecture Overview

Recon Scan Tool is built as a modular, async reconnaissance pipeline.

## High-Level Flow

---

## Core Components

### Engine (`core/engine.py`)
- orchestrates scan lifecycle
- manages concurrency
- executes modules per stage
- handles resume state
- triggers reporting + persistence

---

### Pipeline (`core/pipeline.py`)
Defines execution order:

- DISCOVERY
- DNS
- PORT_SCAN
- SERVICE
- WEB
- FINGERPRINT
- VULNERABILITY

---

### Modules (`modules/`)
- async
- self-contained
- dependency-aware
- produce structured findings

---

### Findings System
- centralized via `ScanContext`
- normalized structure:
  - category
  - target
  - summary
  - severity
  - data

---

### Correlation Engine
Combines signals into higher-value findings:
- admin panel + weak headers
- exposed services combinations
- cellular detection signals

---

### Persistence Layer
- SQLite database
- JSON/HTML/Markdown reports
- graph export

---

### Web UI
- FastAPI backend
- Jinja templates
- scan browsing + findings exploration
