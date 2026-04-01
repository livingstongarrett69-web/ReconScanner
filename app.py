import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from core.database import ReconDatabase


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

app = FastAPI(title="Recon Scan Tool UI")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
db = ReconDatabase()


def report_path(scan_id: str, suffix: str) -> Path:
    return REPORTS_DIR / f"{scan_id}{suffix}"


@app.get("/")
async def home(request: Request):
    scans = db.list_scans(limit=100)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scans": scans,
        },
    )


@app.get("/scan/{scan_id}")
async def scan_detail(request: Request, scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.get_findings(scan_id, limit=500)
    target_results = db.get_target_results(scan_id, limit=500)

    graph_json = report_path(scan_id, "_graph.json")
    graph_html = report_path(scan_id, "_graph.html")
    html_report = report_path(scan_id, ".html")
    md_report = report_path(scan_id, ".md")
    json_report = report_path(scan_id, ".json")

    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "scan": scan,
            "findings": findings,
            "target_results": target_results,
            "artifacts": {
                "json_report": json_report.name if json_report.exists() else None,
                "html_report": html_report.name if html_report.exists() else None,
                "md_report": md_report.name if md_report.exists() else None,
                "graph_json": graph_json.name if graph_json.exists() else None,
                "graph_html": graph_html.name if graph_html.exists() else None,
            },
        },
    )


@app.get("/api/scans")
async def api_scans():
    return JSONResponse(db.list_scans(limit=100))


@app.get("/api/scan/{scan_id}")
async def api_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return JSONResponse({
        "scan": scan,
        "findings": db.get_findings(scan_id, limit=1000),
        "target_results": db.get_target_results(scan_id, limit=1000),
    })


@app.get("/reports/{filename}")
async def serve_report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path)