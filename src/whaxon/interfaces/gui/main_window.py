"""Main PySide6 window — catalog, target, live output."""
from __future__ import annotations

import asyncio

from PySide6.QtCore import Qt, QObject, QSignalBlocker, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Tool Catalog")
        splitter.addWidget(self.tree)

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
        except Exception as e:
            self.output.appendPlainText(f"error: {e}")
            self.statusBar().showMessage(f"error: {e}")

    def _cancel_job(self) -> None:
        if not self.current_job_id:
            self.statusBar().showMessage("nothing to cancel")
            return
        asyncio.create_task(self.core.runner.cancel(self.current_job_id))
