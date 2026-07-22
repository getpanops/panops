#!/usr/bin/env bash
# Run PanOps test suite from local Docker against a port-forwarded cluster.
#
# Usage:
#   ./run_local.sh                        # runs all tests
#   ./run_local.sh test_00_connectivity   # runs one module
#   ./run_local.sh -k test_llama          # pytest -k filter
#
# Prerequisites (run in separate terminals before this):
#   kubectl port-forward -n panops svc/panops-assembler 8080:8080
#   kubectl port-forward -n clickhouse svc/clickhouse 8123:8123
#   kubectl port-forward -n panops svc/panops-llama-server 8081:8080
#
# Secrets:
#   export CH_PASSWORD=$(kubectl get secret -n clickhouse clickhouse-credentials \
#     -o jsonpath='{.data.password}' | base64 -d)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="panops-testharness:local"

echo "→ Building test image..."
docker build -t "$IMAGE" "$SCRIPT_DIR"

echo "→ Running tests (external mode — using port-forwards)..."
docker run --rm \
  --network host \
  -e ASSEMBLER_URL="${ASSEMBLER_URL:-http://localhost:8080}" \
  -e CH_URL="${CH_URL:-http://localhost:8123}" \
  -e CH_USER="${CH_USER:-default}" \
  -e CH_PASSWORD="${CH_PASSWORD:-}" \
  -e LLAMA_URL="${LLAMA_URL:-http://localhost:8081}" \
  -e TEST_TIMEOUT="${TEST_TIMEOUT:-60}" \
  "$IMAGE" pytest -v --tb=short --timeout=150 "$@"
