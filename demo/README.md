# PFG Demo — Live Vulnerability Detection

Real-time visualization of GNN-based authorization vulnerability detection.

## Architecture

```
┌──────────────┐     WebSocket      ┌──────────────┐
│   Next.js    │ ◄────────────────► │   FastAPI    │
│   Frontend   │                    │   Backend    │
│   :3000      │                    │   :8000      │
└──────────────┘                    └──────┬───────┘
                                           │
                                    ┌──────▼───────┐
                                    │  PFG Engine  │
                                    │  + GNN Model │
                                    └──────────────┘
```

## Quick Start

### Backend

```bash
cd demo/backend
# From project root with venv active:
python -m uvicorn demo.backend.main:app --reload --port 8000
# Or directly:
python main.py
```

### Frontend

```bash
cd demo/frontend
npm install
npm run dev
```

Visit http://localhost:3000

## Features

- **Landing page**: Grid of pre-loaded Django codebases with known CVEs
- **Analysis page**: 3-panel layout
  - Left: Real-time progress log (PFG construction → GNN inference → validation)
  - Center: Interactive force-directed graph visualization of the Program Flow Graph
  - Right: Findings panel with severity-ranked vulnerability alerts

## Demo Codebases

| App             | Endpoints | Description                                          |
| --------------- | --------- | ---------------------------------------------------- |
| django-mdeditor | 5         | Quick demo — finds IDOR in ~2s                       |
| wger            | 1088      | Fitness tracker — multiple IDOR/permission issues    |
| sentry          | 273       | Error monitoring — org-level access control          |
| nautobot        | 1716      | Network automation — complex RBAC (impressive graph) |
| weblate         | ~450      | Translation platform — project permissions           |
| pretix          | ~620      | Event ticketing — organizer isolation                |

## How It Works

1. User selects a codebase from the landing page
2. Frontend opens WebSocket connection to backend
3. Backend builds the Program Flow Graph (PFG) from source code
4. Graph data streams to frontend for real-time visualization
5. GNN model scores each endpoint for vulnerability likelihood
6. Structural validator confirms/rejects GNN predictions
7. Final findings displayed with severity and route information
