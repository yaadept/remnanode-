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
REGISTRY_IMAGE="${REGISTRY_IMAGE:-ghcr.io/yaadept/remnawave-node-rust}"
REPO_URL="${REPO_URL:-https://github.com/yaadept/remnanode-.git}"
REPO_BRANCH="${REPO_BRANCH:-claude/delai-04v0ho}"
INSTALL_DIR="${INSTALL_DIR:-/opt/remnanode-rust}"
# options carried over from the old container when set there
CARRY=(NODE_PORT SECRET_KEY DISABLE_HASHED_SET_CHECK NFTABLES_LOGGING NFTABLES_ACCEPT_REPLY_TRAFFIC SNI_VERIFICATION)

die() { echo "ERROR: $*" >&2; exit 1; }
exists() { docker inspect "$1" >/dev/null 2>&1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = true ]; }

command -v docker >/dev/null || die "docker is not installed"

# Finds the existing official node: by image (remnawave/node) or by having SECRET_KEY set.
detect_old() {
  local id img name
  for id in $(docker ps -a -q); do
    img=$(docker inspect -f '{{.Config.Image}}' "$id")
    name=$(docker inspect -f '{{.Name}}' "$id"); name=${name#/}
    [[ "$name" == *-old || "$name" == *-prev ]] && continue
    if [[ "$img" == *remnawave/node* ]] ||
       docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" | grep -q '^SECRET_KEY='; then
      echo "$name"
    fi
  done
}

if [ "${1:-}" != "--rollback" ] && ! exists "$NAME"; then
  mapfile -t FOUND < <(detect_old)
  if [ "${#FOUND[@]}" -eq 1 ]; then
    NAME="${FOUND[0]}"; OLD="${NAME}-old"
    echo "Found the existing node container: '$NAME'."
  elif [ "${#FOUND[@]}" -gt 1 ]; then
    echo "Several candidate containers found: ${FOUND[*]}" >&2
    die "re-run with NODE_CONTAINER=<name of your node container>"
  fi
fi

if [ "${1:-}" = "--rollback" ]; then
  if ! exists "$OLD"; then
    # the node had a different name: look for the single "<name>-old" container
    mapfile -t OLDS < <(docker ps -a --format '{{.Names}}' | grep -- '-old$' || true)
    [ "${#OLDS[@]}" -eq 1 ] || die "no $OLD container to roll back to (set NODE_CONTAINER=<name> if yours is named differently)"
    OLD="${OLDS[0]}"; NAME="${OLD%-old}"
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rename "$OLD" "$NAME"
  docker update --restart=always "$NAME" >/dev/null
  docker start "$NAME" >/dev/null
  echo "Rolled back: the previous node is running again."
  exit 0
fi

# Backup name: an official node is kept as <name>-old; when this Rust node is already
# installed (an upgrade), the previous Rust container goes to <name>-prev and <name>-old
# (the official node) stays untouched.
BACKUP="$OLD"
if exists "$NAME"; then
  case "$(docker inspect -f '{{.Config.Image}}' "$NAME")" in
    *remnawave-node-rust*) BACKUP="${NAME}-prev" ;;
  esac
fi

# 1. settings: from the running container, else from the environment
declare -A ENVV=()
if exists "$NAME"; then
  while IFS='=' read -r k v; do
    # compose files often have SECRET_KEY="..." which keeps the quotes in the container env
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    for c in "${CARRY[@]}"; do [ "$k" = "$c" ] && ENVV[$k]="$v"; done
  done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME")
  echo "Read settings from the existing '$NAME' container."
fi
for c in "${CARRY[@]}"; do
  [ -n "${!c:-}" ] && ENVV[$c]="${!c}"
done
if [ -z "${ENVV[SECRET_KEY]:-}" ]; then
  echo "Containers on this host:" >&2
  docker ps -a --format '  {{.Names}}  ({{.Image}})' >&2 || true
  die "no node container found and SECRET_KEY is not set. Re-run with NODE_CONTAINER=<name> or SECRET_KEY=<key>"
fi
ENVV[NODE_PORT]="${ENVV[NODE_PORT]:-2222}"

# 2. get the image: pull the prebuilt one from GHCR, else build it from source
TAG="${IMAGE_TAG:-${REPO_BRANCH//\//-}}"
echo "Pulling $REGISTRY_IMAGE:$TAG ..."
if docker pull "$REGISTRY_IMAGE:$TAG" >/dev/null 2>&1; then
  docker tag "$REGISTRY_IMAGE:$TAG" "$IMAGE"
  echo "Pulled the prebuilt image."
else
  echo "No prebuilt image available (not published yet or the package is private); building from source."
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
  # 3. build before touching the old node, so it keeps serving during the (long) compile
  echo "Building the image (several minutes on a small server)..."
  docker build -t "$IMAGE" "$SRC"
fi

# 4. swap
if exists "$NAME"; then
  exists "$BACKUP" && docker rm -f "$BACKUP" >/dev/null
  docker stop "$NAME" >/dev/null
  docker rename "$NAME" "$BACKUP"
  docker update --restart=no "$BACKUP" >/dev/null
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
  if exists "$BACKUP"; then
    docker rename "$BACKUP" "$NAME"; docker update --restart=always "$NAME" >/dev/null; docker start "$NAME" >/dev/null
    echo "Rolled back to the previous node." >&2
  fi
  exit 1
fi

cat <<MSG

Done. The Rust node is running on port ${ENVV[NODE_PORT]}; the panel will reconnect on its own.
  logs:      docker logs -f $NAME
  rollback:  $0 --rollback
  cleanup:   docker rm $BACKUP     (once you are happy with the new node)
MSG
