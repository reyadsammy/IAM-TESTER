@echo off
title IAM Security Tester
cd /d "%~dp0"
call venv\Scripts\activate
streamlit run dashboard.py
pause
