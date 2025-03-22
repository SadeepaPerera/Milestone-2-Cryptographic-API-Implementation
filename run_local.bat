@echo off
REM Activate your virtual environment or conda environment
call venv\Scripts\activate

REM Run the app
uvicorn main:app --host 0.0.0.0 --port 8001

REM Optional: Pause to see any output before the window closes
pause
