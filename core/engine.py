import asyncio
import time

from core.context import ScanContext
from core.correlation import CorrelationEngine
from core.database import ReconDatabase
from core.dependency_graph import DependencyGraph
from core.pipeline import STAGES
from core.plugin_loader import PluginLoader
from core.resume import ScanResume
from core.scheduler import Scheduler
from core.settings import PROFILES
from graph.export_graph import export_graph
from graph.graph_view import GraphView
from reporting.graph_report import GraphReporter
from reporting.html_report import HTMLReporter
from reporting.markdown_report import MarkdownReporter
from reporting.report_index import ReportIndex
from reporting.reporter import Reporter
from scan_logging.logger import ScanLogger


class ScanEngine:
    def __init__(self, profile="normal"):
        self.settings = PROFILES.get(profile, PROFILES["normal"])
        self.ctx = ScanContext(profile)
        self.logger = ScanLogger()
        self.loader = PluginLoader()
        self.scheduler = Scheduler(
            target_limit=self.settings["target_concurrency"],
            module_limit=self.settings["module_concurrency"],
        )
        self.correlation = CorrelationEngine()
        self.database = ReconDatabase()

        self.resume = ScanResume()
        self.enable_filter = None
        self.disable_filter = set()

    def set_module_filters(self, enable=None, disable=None):
        self.enable_filter = enable
        self.disable_filter = disable or set()

    def module_allowed(self, module):
        if self.enable_filter is not None and module.name not in self.enable_filter:
            return False
        if module.name in self.disable_filter:
            return False
        return getattr(module, "enabled", True)

    def dependencies_met(self, module, context):
        deps = getattr(module, "dependencies", [])
        if not all(dep in context for dep in deps):
            return False

        required_keys = getattr(module, "required_context_keys", [])
        if not all(context.get(key) for key in required_keys):
            return False

        return True

    def record_recent_finding(self, target, module_name, result):
        if result in (None, [], {}, False):
            return

        self.ctx.recent_findings.append({
            "target": target,
            "module": module_name,
            "summary": str(result)[:140],
        })

    def get_completed_targets_from_state(self):
        state = self.resume.load_state()
        if not state:
            return set()

        results = state.get("results", {})
        if isinstance(results, dict):
            return set(results.keys())

        return set()

    async def _execute_module(self, module, target, context, result_store):
        started = time.time()

        try:
            self.logger.module_start(target, module.name, module.stage)

            await module.setup(context)
            result = await module.run(target, context)
            await module.cleanup(context)

            context[module.name] = result
            result_store[module.name] = result
            self.ctx.modules_run += 1

            duration = round(time.time() - started, 2)

            if result not in (None, [], {}, False):
                self.logger.module_result(target, module.name, result, duration=duration)
                self.record_recent_finding(target, module.name, result)

        except Exception as e:
            self.ctx.errors += 1
            self.logger.module_error(target, module.name, e)

    async def run_module(self, module, target, context, result_store):
        return await self.scheduler.run_module(
            self._execute_module(module, target, context, result_store)
        )

    async def scan_target(self, target, modules_by_stage):
        async def _scan():
            self.logger.target_start(target)

            context = {
                "ctx": self.ctx,
                "target": target,
                "scan_ports": self.settings["ports"],
                "http_timeout": self.settings.get("http_timeout", 5),
                "crawl_depth": self.settings.get("crawl_depth", 1),
            }

            result_store = {}

            for stage in STAGES:
                stage_modules = modules_by_stage.get(stage, [])
                if not stage_modules:
                    continue

                tasks = []
                for module in stage_modules:
                    if not self.module_allowed(module):
                        continue
                    if not self.dependencies_met(module, context):
                        continue

                    tasks.append(self.run_module(module, target, context, result_store))

                if tasks:
                    await asyncio.gather(*tasks)

            self.ctx.targets_done += 1
            self.ctx.results[target] = result_store

            self.resume.save_state(self.ctx)
            self.logger.target_finish(target)

            return {"target": target, "results": result_store}

        return await self.scheduler.run_target(_scan())

    async def run(self, targets, resume=False):
        modules = self.loader.load_modules()
        modules.sort(key=lambda m: (m.stage, m.name))

        modules_by_stage = {stage: [] for stage in STAGES}
        dependency_graph = DependencyGraph()

        for module in modules:
            modules_by_stage[module.stage].append(module)
            dependency_graph.add_module(module)

        if resume:
            completed_targets = self.get_completed_targets_from_state()
            targets = [t for t in targets if t not in completed_targets]

        self.ctx.targets_total = len(targets)
        self.logger.scan_start(self.ctx.scan_id, targets)

        tasks = [self.scan_target(target, modules_by_stage) for target in targets]
        results = await asyncio.gather(*tasks)

        derived_findings = self.correlation.correlate(self.ctx)

        self.ctx.scan_complete = True
        self.logger.scan_summary(self.ctx)

        json_report = Reporter().save_json(self.ctx)
        html_report = HTMLReporter().save_html(self.ctx)
        markdown_report = MarkdownReporter().save_markdown(self.ctx)

        graph_file = export_graph(self.ctx.graph)
        graph_view = GraphView().save_html(self.ctx.graph.as_dict())
        graph_summary = GraphReporter().save_text(self.ctx.graph.as_dict())

        index_file = ReportIndex().append(
            self.ctx,
            json_report=json_report,
            html_report=html_report,
        )

        self.database.save_scan(self.ctx)

        return {
            "results": results,
            "derived_findings": derived_findings,
            "dependency_graph": dependency_graph.as_dict(),
            "loaded_modules": self.loader.loaded,
            "failed_modules": self.loader.failed,
            "json_report": json_report,
            "html_report": html_report,
            "markdown_report": markdown_report,
            "graph_file": graph_file,
            "graph_view": graph_view,
            "graph_summary": graph_summary,
            "index_file": index_file,
            "database": self.database.db_path,
        }