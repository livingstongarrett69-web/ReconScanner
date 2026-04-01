try:
    import dns

    AVAILABLE = True
except ImportError:
    AVAILABLE = False


def run(ip):
    if not AVAILABLE:
        return "[SKIPPED] dns_enum plugin missing 'dnspython' library"

    # normal plugin code here
    return f"DNS info for {ip}"
