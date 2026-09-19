import sys
import os
from pathlib import Path

# Add backend directory to sys.path for Vercel Serverless
root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"
sys.path.insert(0, str(backend_dir))

from app.main import app

# Vercel serverless ASGI handler
handler = app
