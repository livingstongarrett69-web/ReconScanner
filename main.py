import argparse
import asyncio
import threading

from core.database import ReconDatabase
from core.engine import ScanEngine
from ui.dashboard import ScanDashboard
from utils.target_parser import parse_targets
from utils.version import banner


async def main():
    print(banner())

    parser = argparse.ArgumentParser(
        description="Recon Scan Tool - asynchronous modular reconnaissance framework"
    )

    parser.add_argument(
        "-t",
        "--target",
        help="IP address, hostname, or CIDR range to scan"
    )

    parser.add_argument(
        "--profile",
        default="normal",
        choices=["fast", "normal", "deep", "web"],
        help="Scan profile to use"
    )

    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available modules and exit"
    )

    parser.add_argument(
        "--list-scans",
        action="store_true",
        help="List recent scans from the SQLite history database and exit"
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the last saved scan state"
    )

    parser.add_argument(
        "--enable",
        help="Comma-separated module names to enable"
    )

    parser.add_argument(
        "--disable",
        help="Comma-separated module names to disable"
    )

    args = parser.parse_args()

    if args.list_scans:
        db = ReconDatabase()
        for row in db.list_scans():
            print(row)
        return

    engine = ScanEngine(profile=args.profile)

    if args.list_modules:
        modules = engine.loader.load_modules()
        for module in modules:
            print(
                f"{module.name:22} "
                f"stage={module.stage:14} "
                f"enabled={getattr(module, 'enabled', True)}"
            )
        return

    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    targets = parse_targets(args.target)

    enable_set = set(x.strip() for x in args.enable.split(",")) if args.enable else None
    disable_set = set(x.strip() for x in args.disable.split(",")) if args.disable else set()

    engine.set_module_filters(enable=enable_set, disable=disable_set)

    dashboard = ScanDashboard(engine.ctx)
    dashboard_thread = threading.Thread(target=dashboard.run, daemon=True)
    dashboard_thread.start()

    await engine.run(targets, resume=args.resume)

    parser.add_argument(
        "--profile",
        default="normal",
        choices=["fast", "normal", "deep", "web", "cellular"],
        help="Scan profile to use"
    )


if __name__ == "__main__":
    asyncio.run(main())