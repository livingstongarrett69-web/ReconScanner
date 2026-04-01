from core.context import ScanContext


def test_context_findings():

    ctx = ScanContext()

    ctx.add_finding("open_port", {
        "target": "1.1.1.1",
        "summary": "Port 80 open",
        "data": {"port": 80}
    })

    assert ctx.open_ports == 1