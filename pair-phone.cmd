@echo off
rem Shows a one-time pairing QR (valid 10 min). The WALLACE Agent must be running.
set EXE=%LOCALAPPDATA%\Programs\WALLACE Agent\WallaceAgent.exe
if not exist "%EXE%" set EXE=C:\Program Files\WALLACE Agent\WallaceAgent.exe
if not exist "%EXE%" set EXE=%~dp0publish\WallaceAgent.exe
"%EXE%" --pair %*
