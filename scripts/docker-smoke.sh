#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  docker compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose config >/dev/null
docker compose up --build -d
for url in http://127.0.0.1:8000/health http://127.0.0.1:3000; do
  for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error "$url" >/dev/null; then
      break
    fi
    if [ "$attempt" = 30 ]; then
      echo "Service did not become ready: $url" >&2
      docker compose logs >&2
      exit 1
    fi
    sleep 2
  done
done

echo "Docker smoke test passed: API and web are reachable."
