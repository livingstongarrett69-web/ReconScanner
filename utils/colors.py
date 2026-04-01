class Colors:

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"


def info(msg):
    print(f"{Colors.CYAN}[INFO]{Colors.END} {msg}")


def success(msg):
    print(f"{Colors.GREEN}[OK]{Colors.END} {msg}")


def warn(msg):
    print(f"{Colors.WARNING}[WARN]{Colors.END} {msg}")


def error(msg):
    print(f"{Colors.FAIL}[ERROR]{Colors.END} {msg}")