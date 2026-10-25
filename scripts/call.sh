#!/usr/bin/env bash
# Calls a running node the way the panel does (mTLS + RS256 JWT) using the files made by
# gen-test-secret.sh.
#
#   scripts/call.sh GET  /node/xray/healthcheck
#   scripts/call.sh POST /node/stats/get-users-stats '{"reset":false}'
#
# Env: DEV_DIR (default ./.dev), NODE_PORT (default 2222)
set -euo pipefail
D="${DEV_DIR:-.dev}"; PORT="${NODE_PORT:-2222}"
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
H=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
P=$(printf '{"sub":"panel","exp":%s}' "$(( $(date +%s) + 3600 ))" | b64)
S=$(printf '%s.%s' "$H" "$P" | openssl dgst -sha256 -sign "$D/jwt.key" | b64)

args=(-sS -m 60 --noproxy '*' --tlsv1.3 --cacert "$D/ca.crt" --cert "$D/client.crt" --key "$D/client.key"
      --resolve "localhost:$PORT:127.0.0.1" -H "Authorization: Bearer $H.$P.$S" -X "$1" "https://localhost:$PORT$2"
      -w "\n[HTTP %{http_code}]\n")
[ -n "${3:-}" ] && args+=(-H "Content-Type: application/json" -d "$3")
exec curl "${args[@]}"
