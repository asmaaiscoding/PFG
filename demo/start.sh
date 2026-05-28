#!/bin/bash
# PFG Demo — Launch Script
# Starts both backend and frontend servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🚀 Starting PFG Demo..."
echo "   Project root: $PROJECT_ROOT"
echo ""

# Check Python environment
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    echo "❌ Python venv not found. Run: python -m venv .venv && pip install -e ."
    exit 1
fi

# Check node_modules
if [ ! -d "$SCRIPT_DIR/frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd "$SCRIPT_DIR/frontend" && npm install
fi

# Start backend
echo "🐍 Starting FastAPI backend on :8000..."
cd "$PROJECT_ROOT"
source .venv/bin/activate
python -m uvicorn demo.backend.main:app --port 8000 --reload &
BACKEND_PID=$!

# Start frontend
echo "⚛️  Starting Next.js frontend on :3000..."
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✅ Demo running!"
echo "   Frontend: http://localhost:3000"
echo "   Backend:  http://localhost:8000"
echo "   API docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop both servers."

# Cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

wait
