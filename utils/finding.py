def build_finding(category, target, summary, severity="info", data=None):
    return {
        "category": category,
        "target": target,
        "summary": summary,
        "severity": severity,
        "data": data or {},
    }