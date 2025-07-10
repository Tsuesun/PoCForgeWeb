# PoCForge Web

A web frontend for PoCForge - transforms CVE fix commits into practical PoC demonstrations.

## Quick Start

### Backend
```bash
cd backend
uv sync
uv run python main.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173` and the backend will be available at `http://localhost:8000`.

## Usage

1. Enter a CVE ID (e.g., CVE-2023-1234)
2. Click "Analyze CVE"
3. View the generated PoC and vulnerability analysis

## Current Status

This is a proof-of-concept with mock data. To integrate with actual PoCForge:

1. Install PoCForge in the backend directory
2. Update the subprocess call in `backend/main.py` to use the real PoCForge CLI
3. Adjust the response parsing based on PoCForge's actual JSON output format