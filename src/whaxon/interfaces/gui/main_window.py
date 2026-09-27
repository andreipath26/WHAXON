"""Main PySide6 window — catalog, target, live output."""
from __future__ import annotations

import asyncio

from PySide6.QtCore import Qt, QObject, QSignalBlocker, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from whaxon.core import Core
from whaxon.core.scope import OutOfScopeError
from whaxon.core.events import (
    JobFailed,
    JobFinished,
    JobOutput,
    JobStarted,
    ToolDiscovered,
)

BRAND = "WHAXON"
TOOL_ROLE = Qt.ItemDataRole.UserRole + 1


class Bridge(QObject):
    """Marshals core bus events into Qt signals (thread-safe)."""

    tool_discovered = Signal(str, str, str)
    job_started = Signal(str, str, str)
    job_output = Signal(str, str, str)
    job_finished = Signal(str, int, float)
    job_failed = Signal(str, str)


class MainWindow(QMainWindow):
    def __init__(self, core: Core) -> None:
        super().__init__()
        self.core = core
        self.current_job_id: str | None = None
        self.tools: dict[str, object] = {}

        self.setWindowTitle(BRAND)
        self.resize(1300, 780)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter()
        layout.addWidget(splitter)

        # --- Left: tool tree ---
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Tool Catalog")
        left_layout.addWidget(self.tree, 3)
        left_layout.addWidget(QLabel("History"))
        self.history = QListWidget()
        self.history.setFixedHeight(180)
        self.history.itemDoubleClicked.connect(self._on_history_clicked)
        self.history.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history.customContextMenuRequested.connect(self._on_history_menu)
        left_layout.addWidget(self.history, 0)
        splitter.addWidget(left)

        # --- Right: target + output ---
        right = QWidget()
        rlayout = QVBoxLayout(right)
        rlayout.setContentsMargins(6, 6, 6, 6)

        self.selected_label = QLabel("selected: (none)")
        rlayout.addWidget(self.selected_label)

        row = QWidget()
        rrow = QHBoxLayout(row)
        rrow.setContentsMargins(0, 0, 0, 0)
        rrow.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("host or URL, e.g. 127.0.0.1")
        self.target_input.returnPressed.connect(self._run_selected)
        rrow.addWidget(self.target_input)
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText("extra args (optional)")
        self.extra_input.returnPressed.connect(self._run_selected)
        rrow.addWidget(self.extra_input)
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText("extra args (optional)")
        self.extra_input.returnPressed.connect(self._run_selected)
        rrow.addWidget(self.extra_input)
        self.run_button = QPushButton("Run")
        self.run_button.clicked.connect(self._run_selected)
        rrow.addWidget(self.run_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_job)
        rrow.addWidget(self.cancel_button)
        rlayout.addWidget(row)

        rlayout.addWidget(QLabel("Output:"))
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.StyleHint.TypeWriter)
        self.output.setFont(mono)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        rlayout.addWidget(self.output)

        splitter.addWidget(right)
        splitter.setSizes([400, 900])

        self.statusBar().showMessage("ready")

        # --- Core event bridge ---
        self.bridge = Bridge()
        self.bridge.tool_discovered.connect(self._on_tool_discovered)
        self.bridge.job_started.connect(self._on_job_started)
        self.bridge.job_output.connect(self._on_job_output)
        self.bridge.job_finished.connect(self._on_job_finished)
        self.bridge.job_failed.connect(self._on_job_failed)

        core.bus.subscribe(ToolDiscovered, lambda e: self.bridge.tool_discovered.emit(e.tool_id, e.name, e.category))
        core.bus.subscribe(JobStarted, lambda e: self.bridge.job_started.emit(e.job_id, e.tool_id, e.target))
        core.bus.subscribe(JobOutput, lambda e: self.bridge.job_output.emit(e.job_id, e.stream, e.line))
        core.bus.subscribe(JobFinished, lambda e: self.bridge.job_finished.emit(e.job_id, e.exit_code, e.duration_s))
        core.bus.subscribe(JobFailed, lambda e: self.bridge.job_failed.emit(e.job_id, e.error))

        self._populate_catalog()
        self.tree.currentItemChanged.connect(self._on_tool_changed)

    # ------------------------------------------------------------------


    def _on_history_menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu, QInputDialog
        item = self.history.itemAt(pos)
        if item is None:
            return
        job_id = item.data(Qt.ItemDataRole.UserRole)
        if not job_id:
            return
        menu = QMenu(self)
        act_report = menu.addAction("Save report (Markdown)\u2026")
        act_html = menu.addAction("Save report (HTML)\u2026")
        menu.addSeparator()
        act_note = menu.addAction("Add note\u2026")
        chosen = menu.exec(self.history.mapToGlobal(pos))
        if chosen == act_report:
            self._save_report(job_id, html=False)
        elif chosen == act_html:
            self._save_report(job_id, html=True)
        elif chosen == act_note:
            text, ok = QInputDialog.getMultiLineText(self, "Add note", f"Note for {job_id}:")
            if ok and text.strip():
                self.core.store.add_evidence(job_id, "note", "note", note=text.strip())
                self.statusBar().showMessage(f"note added to {job_id}")

    def _save_report(self, job_id: str, html: bool = False) -> None:
        from PySide6.QtWidgets import QFileDialog
        from pathlib import Path as _P
        from whaxon.core.report import render_markdown, render_html
        job = self.core.store.get(job_id)
        if job is None:
            return
        findings = self.core.store.get_findings(job_id) or []
        text = render_html(job, findings) if html else render_markdown(job, findings)
        ext = "html" if html else "md"
        default = str(_P.home() / f"whaxon-report-{job_id}.{ext}")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save report", default,
            "HTML (*.html);;Markdown (*.md)" if html else "Markdown (*.md);;HTML (*.html)",
        )
        if not path:
            return
        _P(path).write_text(text, encoding="utf-8")
        self.statusBar().showMessage(f"saved {path}")

    def _refresh_history(self) -> None:
        try:
            self.history.clear()
            for j in self.core.store.history(limit=30):
                dur = j.get("duration_s") or 0
                item = QListWidgetItem(f"{j.get('tool','')} -> {j.get('target','')}  ({dur:.1f}s)")
                item.setData(Qt.ItemDataRole.UserRole, j.get("id"))
                self.history.addItem(item)
        except Exception:
            pass

    def _on_history_clicked(self, item) -> None:
        job_id = item.data(Qt.ItemDataRole.UserRole)
        if not job_id:
            return
        job = self.core.store.get(job_id)
        if job is None:
            return
        self.output.clear()
        self.output.appendPlainText(f"history: {job_id} - {job['tool']} -> {job['target']}")
        for line in job.get("lines", []):
            prefix = "[err] " if line["stream"] == "stderr" else ""
            self.output.appendPlainText(f"{prefix}{line['text']}")
        self.statusBar().showMessage(f"viewing {job_id}")

    def _populate_catalog(self) -> None:
        self.tree.clear()
        self.tools.clear()
        categories: dict[str, list] = {}
        for tool in self.core.catalog.list():
            categories.setdefault(tool.category, []).append(tool)
        for cat, cat_tools in sorted(categories.items()):
            cat_item = QTreeWidgetItem([cat])
            self.tree.addTopLevelItem(cat_item)
            for tool in cat_tools:
                item = QTreeWidgetItem(cat_item, [tool.name])
                item.setData(0, TOOL_ROLE, tool.id)
                self.tools[tool.id] = tool
            cat_item.setExpanded(True)
        self.statusBar().showMessage(f"ready \u2014 {len(self.tools)} tools loaded")

    def _on_tool_changed(self, current, previous) -> None:
        if current is None:
            return
        tid = current.data(0, TOOL_ROLE)
        if tid and tid in self.tools:
            t = self.tools[tid]
            self.selected_label.setText(f"selected: {t.name} \u2192 {t.binary}")
            self.target_input.setFocus()

    def _on_tool_discovered(self, tid: str, name: str, cat: str) -> None:
        self._populate_catalog()

    def _on_job_started(self, job_id: str, tool_id: str, target: str) -> None:
        self.current_job_id = job_id
        self.cancel_button.setEnabled(True)
        self.output.appendPlainText(f"> job {job_id} started \u2014 {tool_id} \u2192 {target}")
        self.statusBar().showMessage(f"running {job_id}\u2026")

    def _on_job_output(self, job_id: str, stream: str, line: str) -> None:
        prefix = "[err] " if stream == "stderr" else ""
        self.output.appendPlainText(f"{prefix}{line}")

    def _on_job_finished(self, job_id: str, exit_code: int, duration_s: float) -> None:
        self._refresh_history()
        self.output.appendPlainText(f"< job {job_id} finished \u2014 exit={exit_code} in {duration_s:.2f}s")
        self.current_job_id = None
        self.cancel_button.setEnabled(False)
        self.statusBar().showMessage(f"done \u2014 exit {exit_code}")

    def _on_job_failed(self, job_id: str, error: str) -> None:
        self.output.appendPlainText(f"! job {job_id} failed \u2014 {error}")
        self.current_job_id = None
        self.cancel_button.setEnabled(False)
        self.statusBar().showMessage(f"failed \u2014 {error}")

    def _run_selected(self) -> None:
        if self.current_job_id:
            self.statusBar().showMessage("a job is already running")
            return
        item = self.tree.currentItem()
        if item is None:
            self.statusBar().showMessage("select a tool first")
            return
        tid = item.data(0, TOOL_ROLE)
        if not tid or tid not in self.tools:
            self.statusBar().showMessage("select a tool first")
            return
        tool = self.tools[tid]
        target = self.target_input.text().strip()
        extra_args = self.extra_input.text().strip()
        if not target:
            self.statusBar().showMessage("enter a target first")
            return
        self.output.appendPlainText(f"$ {tool.binary} {target} {extra_args}".rstrip())
        asyncio.create_task(self._run_tool(tool.id, target, extra_args))

    async def _run_tool(self, tool_id: str, target: str, extra_args: str = "") -> None:
        try:
            await self.core.runner.run_tool(tool_id=tool_id, target=target, extra_args=extra_args, timeout_s=300)
        except OutOfScopeError as e:
            if not self._confirm_out_of_scope(tool_id, target, e):
                self.output.appendPlainText(f"cancelled: {target} is out of scope")
                self.statusBar().showMessage("cancelled \u2014 target out of scope")
                return
            self._log_override(target, tool_id)
            self.output.appendPlainText(f"override logged \u2014 running {tool_id}")
            try:
                await self.core.runner.run_tool(
                    tool_id=tool_id, target=target, extra_args=extra_args,
                    timeout_s=300, allow_out_of_scope=True,
                )
            except Exception as e2:
                self.output.appendPlainText(f"error after override: {e2}")
                self.statusBar().showMessage(f"error: {e2}")
        except Exception as e:
            self.output.appendPlainText(f"error: {e}")
            self.statusBar().showMessage(f"error: {e}")

    def _confirm_out_of_scope(self, tool_id: str, target: str, error) -> bool:
        from PySide6.QtWidgets import QMessageBox
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Out of scope")
        box.setText(f"{target} does not match any in-scope rule.")
        box.setInformativeText(
            f"Reason: {error.reason}\nRule: {error.matched_rule or '(none)'}\n"
            f"Tool: {tool_id}\n\n"
            "Overrides are logged. Only proceed if you have written authorization."
        )
        run_anyway = box.addButton("Run anyway (log this)", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        return box.clickedButton() == run_anyway

    def _log_override(self, target: str, tool_id: str) -> None:
        from datetime import datetime, timezone
        from pathlib import Path as _P
        log_path = _P(self.core.data_dir) / "scope_overrides.log"
        try:
            ts = datetime.now(timezone.utc).isoformat()
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"{ts}\t{tool_id}\t{target}\n")
        except OSError:
            pass

    def _cancel_job(self) -> None:
        if not self.current_job_id:
            self.statusBar().showMessage("nothing to cancel")
            return
        asyncio.create_task(self.core.runner.cancel(self.current_job_id))
