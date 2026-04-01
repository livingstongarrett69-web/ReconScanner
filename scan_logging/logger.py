import logging
import os
from datetime import datetime


class ScanLogger:
    def __init__(self):
        os.makedirs("logs", exist_ok=True)

        logfile = os.path.join(
            "logs",
            f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

        self.logger = logging.getLogger("scanner")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        handler = logging.FileHandler(logfile, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def scan_start(self, scan_id, targets):
        self.logger.info(f"[SCAN_START] id={scan_id} targets={len(targets)}")

    def target_start(self, target):
        self.logger.info(f"[TARGET_START] {target}")

    def target_finish(self, target):
        self.logger.info(f"[TARGET_FINISH] {target}")

    def module_start(self, target, module, stage):
        self.logger.info(f"[MODULE_START] target={target} module={module} stage={stage}")

    def module_result(self, target, module, result, duration=None):
        if duration is None:
            self.logger.info(f"[MODULE_RESULT] target={target} module={module} result={result}")
        else:
            self.logger.info(
                f"[MODULE_RESULT] target={target} module={module} duration={duration}s result={result}"
            )

    def module_error(self, target, module, error):
        self.logger.error(f"[MODULE_ERROR] target={target} module={module} error={error}")

    def scan_summary(self, ctx):
        self.logger.info(
            f"[SUMMARY] targets={ctx.targets_done}/{ctx.targets_total} "
            f"modules={ctx.modules_run} errors={ctx.errors} "
            f"open_ports={ctx.open_ports} web_services={ctx.web_services} "
            f"vulnerabilities={ctx.vulnerabilities} subdomains={ctx.subdomains} "
            f"elapsed={ctx.elapsed}s rate={ctx.targets_per_second}/s"
        )