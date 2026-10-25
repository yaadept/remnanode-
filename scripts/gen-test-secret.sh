#!/usr/bin/env bash
# Generates a throwaway CA, node + client certificates and a JWT key pair, and writes a
# SECRET_KEY the node accepts. For local testing only: the real one comes from the panel.
#
#   scripts/gen-test-secret.sh [out-dir]       # default: ./.dev
set -euo pipefail
OUT="${1:-.dev}"
mkdir -p "$OUT" && cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj "/CN=test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue() { # name, extendedKeyUsage, extra ext lines
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  printf "extendedKeyUsage=%s\n%s\n" "$2" "${3:-}" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 30 -extfile "$1.ext" 2>/dev/null
}
issue node serverAuth "subjectAltName=DNS:localhost,IP:127.0.0.1"
issue client clientAuth

openssl genrsa -out jwt.key 2048 2>/dev/null
openssl rsa -in jwt.key -pubout -out jwt.pub 2>/dev/null

python3 - <<'PY'
import base64, json
r = lambda f: open(f).read()
payload = {"caCertPem": r("ca.crt"), "jwtPublicKey": r("jwt.pub"), "nodeCertPem": r("node.crt"), "nodeKeyPem": r("node.key")}
open("secret_key", "w").write(base64.b64encode(json.dumps(payload).encode()).decode())
PY
echo "SECRET_KEY written to $OUT/secret_key"
