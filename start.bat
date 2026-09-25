@echo off
chcp 65001 >nul
title OSINT-Lookup
python "%~dp0osint.py" %*
if "%~1"=="" pause
