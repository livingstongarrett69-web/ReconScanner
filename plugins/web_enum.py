try:
    import requests

    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def run(ip):
    if not AVAILABLE:
        return "[SKIPPED] web_enum plugin missing 'requests' library"

    # normal plugin code here
    return f"Web info for {ip}"