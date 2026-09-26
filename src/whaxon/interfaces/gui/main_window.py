"""Main PySide6 window. Placeholder until Phase 4 fleshes it out."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QMainWindow, QPlainTextEdit, QSplitter, QTableWidget, QTableWidgetItem,
)

from whaxon.core import Core
from whaxon.core.events import JobOutput, ToolDiscovered

BRAND = "BACKFORGE"


class MainWindow(QMainWindow):
    def __init__(self, core: Core) -> None:
        super().__init__()
        self.core = core
        self.setWindowTitle(BRAND)
        self.resize(1200, 720)

        self.catalog = QTableWidget(0, 3)
        self.catalog.setHorizontalHeaderLabels(["ID", "Name", "Category"])
        self.output = QPlainTextEdit(readOnly=True)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.catalog)
        splitter.addWidget(self.output)
        splitter.setSizes([400, 800])
        self.setCentralWidget(splitter)

        # Menu
        file_menu = self.menuBar().addMenu("&File")
        quit_act = QAction("&Quit", self)
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        self._populate()
        core.bus.subscribe(ToolDiscovered, self._on_tool)
        core.bus.subscribe(JobOutput, self._on_output)

    def _populate(self) -> None:
        self.catalog.setRowCount(0)
        for tool in self.core.catalog.list():
            self._add_row(tool.id, tool.name, tool.category)

    def _add_row(self, tid: str, name: str, cat: str) -> None:
        r = self.catalog.rowCount()
        self.catalog.insertRow(r)
        for c, val in enumerate((tid, name, cat)):
            self.catalog.setItem(r, c, QTableWidgetItem(val))

    def _on_tool(self, evt: ToolDiscovered) -> None:
        self._add_row(evt.tool_id, evt.name, evt.category)

    def _on_output(self, evt: JobOutput) -> None:
        self.output.appendPlainText(f"[{evt.job_id}] {evt.line}")
