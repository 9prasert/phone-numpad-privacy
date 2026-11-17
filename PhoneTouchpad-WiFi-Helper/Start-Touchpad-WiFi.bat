@echo off
rem Phone Touchpad - Wi-Fi helper. Keep the window that opens running while you use the phone as a touchpad.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0PhoneTouchpad-WiFi.ps1"
