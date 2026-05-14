@echo off
setlocal enabledelayedexpansion
echo.
echo  query-sanitizer-mcp -- Windows setup
echo  =====================================
echo.

set SCRIPT_DIR=%~dp0
set VENV=%SCRIPT_DIR%.venv

:: ── 1. Find Python 3.10+ ────────────────────────────────────────────────────
set PYTHON=
for %%P in (python python3) do (
    where %%P >nul 2>&1
    if !errorlevel! == 0 (
        for /f "tokens=*" %%V in ('%%P -c "import sys;v=sys.version_info;print(1 if (v.major,v.minor)>=(3,10) else 0)" 2^>nul') do (
            if "%%V"=="1" (
                set PYTHON=%%P
                goto :found_python
            )
        )
    )
)
echo [ERROR] Python 3.10+ not found.
echo         Download: https://www.python.org/downloads/windows/
echo         Check "Add python.exe to PATH" during install.
exit /b 1

:found_python
for /f "tokens=*" %%V in ('!PYTHON! --version') do echo [OK] %%V

:: ── 2. Create virtual environment ───────────────────────────────────────────
if not exist "%VENV%\Scripts\activate.bat" (
    !PYTHON! -m venv "%VENV%"
    echo [OK] Virtual environment created at .venv
) else (
    echo [OK] Virtual environment already exists
)

:: ── 3. Install fastmcp (always required) ────────────────────────────────────
"%VENV%\Scripts\pip.exe" install --quiet --upgrade pip
"%VENV%\Scripts\pip.exe" install --quiet "fastmcp>=2.0"
echo [OK] fastmcp installed

:: ── 4. Optional: GLiNER NER layer (~500 MB download, ~800 MB RAM) ────────────
echo.
set /p INSTALL_NER=Install GLiNER NER layer? Catches people/orgs/locations. [Y/n]:
if "!INSTALL_NER!"=="" set INSTALL_NER=Y
if /i "!INSTALL_NER!"=="Y" (
    "%VENV%\Scripts\pip.exe" install --quiet "gliner>=0.2.0"
    echo [OK] GLiNER installed
    set GLINER_LINE=        "SANITIZER_GLINER_MODEL": "urchade/gliner_small-v2.1",
) else (
    echo [SKIP] GLiNER skipped -- regex-only detection active
    set GLINER_LINE=
)

:: ── 5. Write config_hint.txt (avoid cmd.exe echo formatting issues) ──────────
set PY_EXE=%VENV%\Scripts\python.exe
set SERVER_PY=%SCRIPT_DIR%server.py

(
    echo {
    echo   "mcpServers": {
    echo     "query-sanitizer": {
    echo       "command": "%PY_EXE:\=\\%",
    echo       "args": ["%SERVER_PY:\=\\%"],
    echo       "env": {
    echo         "SANITIZER_MODEL_URL": "http://localhost:11434/v1/chat/completions",
    echo         "SANITIZER_MODEL_NAME": "qwen2.5:1.5b",
    echo         "SANITIZER_SESSION_CACHE_MAX": "200"
    if defined GLINER_LINE (
        echo         ,"SANITIZER_GLINER_MODEL": "urchade/gliner_small-v2.1"
    )
    echo       }
    echo     }
    echo   }
    echo }
) > "%SCRIPT_DIR%config_hint.txt"

echo.
echo  Config written to: config_hint.txt
echo  Merge its contents into: %%APPDATA%%\Claude\settings.json
echo.
echo  Next steps:
echo    1. Install Ollama:  https://ollama.com/download/windows
echo    2. Pull the model:  ollama pull qwen2.5:1.5b
echo    3. Start Ollama:    ollama serve
echo    4. Merge config_hint.txt into your Claude Code settings.json
echo.
endlocal
