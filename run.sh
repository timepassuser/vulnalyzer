#!/usr/bin/env bash
# Vulnalyzer — start the backend API + serve the frontend
#
# Usage:
#   ./run.sh              (port 8000)
#   ./run.sh --port 9000

set -e
cd "$(dirname "$0")"

PORT=${PORT:-8000}
for arg in "$@"; do
  case $arg in --port) shift; PORT=$1; shift;; esac
done

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║          Vulnalyzer API              ║"
echo "  ╠══════════════════════════════════════╣"
echo "  ║  API  →  http://localhost:$PORT/api  ║"
echo "  ║  UI   →  http://localhost:$PORT/     ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

uvicorn vulnalyzer.api.app:app --reload --port "$PORT"
read -p "Press enter to exit..."
