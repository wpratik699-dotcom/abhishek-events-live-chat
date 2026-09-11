@echo off
cd /d "%~dp0"
title Abhishek Events Live Chat
echo.
echo ==========================================
echo   Abhishek Events Live Chat
echo ==========================================
echo.
echo Installing packages (first run only)...
call npm install
if errorlevel 1 (
  echo.
  echo Package installation failed.
  echo Please send me a screenshot of this window.
  pause
  exit /b 1
)
echo.
echo Starting server...
call npm start
pause
