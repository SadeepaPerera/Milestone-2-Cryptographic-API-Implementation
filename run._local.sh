#!/bin/bash

# Activate your virtual environment or conda environment
source venv/bin/activate

# Run the app
uvicorn main:app --host 0.0.0.0 --port 8001

# Optional: Pause to see any output before closing
read -p "Press Enter to continue..."