@echo off
set "BASE=%~dp0"
if exist "%BASE%runtime\python.exe" (
  "%BASE%runtime\python.exe" "%BASE%app\secure_lab.py"
) else (
  py -3 "%BASE%app\secure_lab.py"
)
