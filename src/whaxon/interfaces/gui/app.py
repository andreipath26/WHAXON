"""WHAXON desktop GUI — thin shell around the web interface.

The GUI hosts the same UI that `whaxon web` serves, in a QWebEngineView.
Every improvement to the web UI appears here for free.
"""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QStackedWidget,
)

from whaxon.interfaces.gui.embed import URL, EmbeddedServer


class MainWindow(QMainWindow):
    def __init__(self, server: EmbeddedServer) -> None:
        super().__init__()
        self.server = server
        self.setWindowTitle("WHAXON")
        self.resize(1400, 900)

        # central: stacked (webview when ready, status label otherwise)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.status = QLabel("starting WHAXON server ...")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.setStyleSheet("font-size: 14px; color: #a3a3a3; padding: 40px;")
        self.stack.addWidget(self.status)

        self.web = QWebEngineView()
        self.stack.addWidget(self.web)

        # menu
        menu = self.menuBar().addMenu("&WHAXON")
        a_start = QAction("Start server", self)
        a_start.triggered.connect(self._start_server)
        a_stop = QAction("Stop server", self)
        a_stop.triggered.connect(self._stop_server)
        a_open = QAction("Open in browser", self)
        a_open.triggered.connect(self._open_external)
        a_reload = QAction("Reload", self)
        a_reload.setShortcut("Ctrl+R")
        a_reload.triggered.connect(self._reload)
        a_quit = QAction("Quit", self)
        a_quit.setShortcut("Ctrl+Q")
        a_quit.triggered.connect(self.close)
        for a in (a_start, a_stop, a_open, a_reload):
            menu.addAction(a)
        menu.addSeparator()
        menu.addAction(a_quit)

        # periodic health poll
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(3000)

    def start_and_load(self) -> None:
        QTimer.singleShot(50, self._start_server)

    def _start_server(self) -> None:
        if self.server.is_running():
            self._load()
            return
        self.status.setText("starting WHAXON server ...")
        self.stack.setCurrentIndex(0)
        ok = self.server.start()
        if ok:
            self._load()
        else:
            self.status.setText(
                "failed to start WHAXON server.\n"
                "check data/whaxon.log or run `whaxon serve` manually."
            )

    def _stop_server(self) -> None:
        self.server.stop()
        self.status.setText("server stopped.")
        self.stack.setCurrentIndex(0)

    def _load(self) -> None:
        self.web.load(QUrl(URL))
        self.stack.setCurrentIndex(1)

    def _reload(self) -> None:
        if self.server.is_running():
            self._load()
        else:
            self._start_server()

    def _open_external(self) -> None:
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl(URL))

    def _poll(self) -> None:
        alive = self.server.is_running()
        if alive and self.stack.currentIndex() == 0:
            self._load()
        elif not alive and self.stack.currentIndex() == 1:
            self.status.setText("server lost. restart via WHAXON → Start server.")
            self.stack.setCurrentIndex(0)

    def closeEvent(self, event) -> None:
        try:
            self.server.stop()
        except Exception:
            pass
        event.accept()


def main(args: list[str] | None = None) -> None:
    app = QApplication.instance() or QApplication([])
    server = EmbeddedServer()
    win = MainWindow(server)
    win.show()
    win.start_and_load()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
