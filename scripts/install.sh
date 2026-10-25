#!/usr/bin/env bash
# Replaces a running official Remnawave node container with this Rust node, keeping its
# SECRET_KEY / port / options. The old container is kept (stopped, renamed) for rollback.
#
#   ./scripts/install.sh              install / upgrade
#   ./scripts/install.sh --rollback   put the old node back
#
# Without a running `remnawave-node` container, pass SECRET_KEY (and optionally NODE_PORT)
# as environment variables.
set -euo pipefail

NAME="${NODE_CONTAINER:-remnawave-node}"
OLD="${NAME}-old"
IMAGE="remnawave-node-rust:local"
REPO_URL="${REPO_URL:-https://github.com/yaadept/remnanode-.git}"
REPO_BRANCH="${REPO_BRANCH:-claude/delai-04v0ho}"
INSTALL_DIR="${INSTALL_DIR:-/opt/remnanode-rust}"
# options carried over from the old container when set there
CARRY=(NODE_PORT SECRET_KEY DISABLE_HASHED_SET_CHECK NFTABLES_LOGGING NFTABLES_ACCEPT_REPLY_TRAFFIC SNI_VERIFICATION)

die() { echo "ERROR: $*" >&2; exit 1; }
exists() { docker inspect "$1" >/dev/null 2>&1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = true ]; }

command -v docker >/dev/null || die "docker is not installed"

if [ "${1:-}" = "--rollback" ]; then
  exists "$OLD" || die "no $OLD container to roll back to"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rename "$OLD" "$NAME"
  docker update --restart=always "$NAME" >/dev/null
  docker start "$NAME" >/dev/null
  echo "Rolled back: the previous node is running again."
  exit 0
fi

# 1. settings: from the running container, else from the environment
declare -A ENVV=()
if exists "$NAME"; then
  while IFS='=' read -r k v; do
    for c in "${CARRY[@]}"; do [ "$k" = "$c" ] && ENVV[$k]="$v"; done
  done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME")
  echo "Read settings from the existing '$NAME' container."
fi
for c in "${CARRY[@]}"; do
  [ -n "${!c:-}" ] && ENVV[$c]="${!c}"
done
[ -n "${ENVV[SECRET_KEY]:-}" ] || die "SECRET_KEY not found: no '$NAME' container, and SECRET_KEY is not set"
ENVV[NODE_PORT]="${ENVV[NODE_PORT]:-2222}"

# 2. source: use this checkout if the script runs from one, else clone
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -f "$HERE/../Dockerfile" ]; then
  SRC="$(cd "$HERE/.." && pwd)"
else
  command -v git >/dev/null || die "git is not installed"
  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$REPO_BRANCH" && git -C "$INSTALL_DIR" checkout -q -B "$REPO_BRANCH" FETCH_HEAD
  else
    git clone --depth 1 -b "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
  SRC="$INSTALL_DIR"
fi

# 3. build first, so the old node keeps serving during the (long) compile
echo "Building the image (several minutes on a small server)..."
docker build -t "$IMAGE" "$SRC"

# 4. swap
if exists "$NAME"; then
  exists "$OLD" && docker rm -f "$OLD" >/dev/null
  docker stop "$NAME" >/dev/null
  docker rename "$NAME" "$OLD"
  docker update --restart=no "$OLD" >/dev/null
fi

args=(-d --name "$NAME" --restart always --network host --cap-add NET_ADMIN)
for k in "${!ENVV[@]}"; do args+=(-e "$k=${ENVV[$k]}"); done
docker run "${args[@]}" "$IMAGE" >/dev/null

# 5. verify; undo on failure
ok=false
for _ in $(seq 1 15); do
  sleep 1
  running "$NAME" || break
  if docker logs "$NAME" 2>&1 | grep -q "listening on port"; then ok=true; break; fi
done
if [ "$ok" != true ]; then
  echo "The new node did not start. Its log:" >&2
  docker logs --tail 40 "$NAME" >&2 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if exists "$OLD"; then
    docker rename "$OLD" "$NAME"; docker update --restart=always "$NAME" >/dev/null; docker start "$NAME" >/dev/null
    echo "Rolled back to the previous node." >&2
  fi
  exit 1
fi

cat <<MSG

Done. The Rust node is running on port ${ENVV[NODE_PORT]}; the panel will reconnect on its own.
  logs:      docker logs -f $NAME
  rollback:  $0 --rollback
  cleanup:   docker rm $OLD     (once you are happy with the new node)
MSG
