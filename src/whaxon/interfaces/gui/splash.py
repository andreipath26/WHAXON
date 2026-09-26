"""PySide6 splash screen."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QSplashScreen

MAX_SPLASH_SECONDS = 3.0


def make_splash(logo_path: Path, brand: str, max_seconds: float) -> QSplashScreen:
    """
    Build a splash from the logo. If the logo is missing, draws a text-only splash.
    Must be called AFTER QApplication exists (Qt requirement for QPixmap).
    """
    if logo_path.exists():
        pix = QPixmap(str(logo_path))
        pix = pix.scaled(480, 480, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    else:
        pix = QPixmap(480, 200)
        pix.fill(QColor("#1e1e1e"))
        painter = QPainter(pix)
        painter.setPen(QColor("#ff8c42"))
        f = QFont(); f.setPointSize(32); f.setBold(True)
        painter.setFont(f)
        painter.drawText(pix.rect(), Qt.AlignCenter, brand)
        painter.end()

    splash = QSplashScreen(pix, Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setWindowTitle(brand)
    splash.show()

    # Safety net: kill splash if init hangs.
    QTimer.singleShot(int(max_seconds * 1000) + 1000, splash.close)
    return splash
