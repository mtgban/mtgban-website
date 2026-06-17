#!/usr/bin/env bash
#
# One-time droplet setup for the blue-green deploy. Idempotent — safe to re-run.
#
# Run as the deploy user (koda), NOT with sudo — it calls sudo itself for the
# privileged bits:
#     ./deploy/bootstrap.sh
#
# It sets up: the two per-port checkouts, the systemd template unit, the
# secrets env file (placeholders), the scoped sudoers rule, the nginx upstream
# include, and the boot instance on 8081. It does NOT edit your nginx server
# block, fill in real secrets, or provision the GitHub deploy key — those are
# printed as manual follow-ups at the end.

set -euo pipefail

# --- config (override via env if needed) -----------------------------------
PORTS=(8081 8082)
BOOT_PORT=8081                                   # the instance enabled at boot
CFG=${CFG:-b2://mtgban-config/magic/config-beta.json}
ENV_FILE=${ENV_FILE:-/etc/mtgban.env}
UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/conf.d/mtgban_upstream.conf}
SUDOERS_FILE=${SUDOERS_FILE:-/etc/sudoers.d/mtgban-deploy}
READY_TIMEOUT=${READY_TIMEOUT:-180}
export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"
# ---------------------------------------------------------------------------

# Resolve paths from this script's location: control repo is the parent of
# deploy/, and the per-port checkouts are siblings of the control repo.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
SRC_DIR=$(dirname "$REPO_DIR")
REPO_NAME=$(basename "$REPO_DIR")               # e.g. mtgban-website
CO_PREFIX="$SRC_DIR/${REPO_NAME}-"              # -> .../mtgban-website-8081

if [ "$(id -u)" = 0 ]; then
    echo "!! run as the deploy user (e.g. koda), not root — the script uses sudo itself" >&2
    exit 1
fi
command -v go        >/dev/null || { echo "!! go not found in PATH ($PATH)" >&2; exit 1; }
SYSTEMCTL=$(command -v systemctl)
NGINX=$(command -v nginx || echo /usr/sbin/nginx)
DEPLOY_USER=$(id -un)
ORIGIN=$(git -C "$REPO_DIR" remote get-url origin)

echo "==> control repo : $REPO_DIR"
echo "==> origin        : $ORIGIN"
echo "==> checkouts     : ${CO_PREFIX}{$(IFS=,; echo "${PORTS[*]}")}"
echo

# 1. Per-port checkouts (clone if missing).
for port in "${PORTS[@]}"; do
    co="${CO_PREFIX}${port}"
    if [ -d "$co/.git" ]; then
        echo "==> [$port] checkout exists: $co"
    else
        echo "==> [$port] cloning -> $co"
        git clone "$ORIGIN" "$co"
    fi
    mkdir -p "$co/logs"
done

# 2. systemd template unit.
echo "==> installing systemd unit -> /etc/systemd/system/mtgban@.service"
sudo cp "$REPO_DIR/deploy/mtgban@.service" /etc/systemd/system/mtgban@.service
sudo "$SYSTEMCTL" daemon-reload

# 3. Secrets env file (placeholders only — never overwrite real values).
if [ -f "$ENV_FILE" ]; then
    echo "==> secrets file exists, leaving untouched: $ENV_FILE"
else
    echo "==> creating placeholder secrets file: $ENV_FILE  (FILL IN REAL VALUES)"
    sudo tee "$ENV_FILE" >/dev/null <<'EOF'
BAN_SECRET=XXX
BAN_CONFIG_KEY=XXX
BAN_CONFIG_SECRET=XXX
EOF
    sudo chmod 600 "$ENV_FILE"
    sudo chown root:root "$ENV_FILE"
fi

# 4. Scoped passwordless sudoers for the deploy commands (one clean line).
echo "==> writing sudoers -> $SUDOERS_FILE"
cmds=""
for verb in restart stop enable disable; do
    for port in "${PORTS[@]}"; do
        cmds+="${cmds:+, }$SYSTEMCTL $verb mtgban@${port}.service"
    done
done
cmds+=", $SYSTEMCTL reload nginx, $NGINX -t"
echo "$DEPLOY_USER ALL=(root) NOPASSWD: $cmds" | sudo tee "$SUDOERS_FILE" >/dev/null
sudo chmod 440 "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE"

# 5. nginx upstream include (create if missing; point at the boot port).
if [ -f "$UPSTREAM_CONF" ]; then
    echo "==> upstream include exists, leaving untouched: $UPSTREAM_CONF"
else
    echo "==> creating upstream include -> $UPSTREAM_CONF (-> $BOOT_PORT)"
    echo "upstream mtgban { server 127.0.0.1:${BOOT_PORT}; }" | sudo tee "$UPSTREAM_CONF" >/dev/null
    sudo chown "$DEPLOY_USER:$DEPLOY_USER" "$UPSTREAM_CONF"
fi

# 6. Build both checkouts.
for port in "${PORTS[@]}"; do
    echo "==> [$port] building"
    ( cd "${CO_PREFIX}${port}" && go build -o mtgban-website . )
done

# 7. Bring up the boot instance and wait for it to go healthy.
echo "==> enabling + starting mtgban@${BOOT_PORT}"
sudo "$SYSTEMCTL" enable --now "mtgban@${BOOT_PORT}"
echo "==> waiting for :${BOOT_PORT}/healthz (up to ${READY_TIMEOUT}s)"
ready=0
for ((i=0; i<READY_TIMEOUT; i++)); do
    if curl -fs "http://127.0.0.1:${BOOT_PORT}/healthz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
done
[ "$ready" = 1 ] && echo "==> mtgban@${BOOT_PORT} healthy" \
                 || echo "!! mtgban@${BOOT_PORT} not healthy yet — check: journalctl -u mtgban@${BOOT_PORT} -n 40"

cat <<EOF

================================================================
Bootstrap done. Remaining MANUAL steps:

  1. Put real values in $ENV_FILE (if it still has XXX), then:
       sudo systemctl restart mtgban@${BOOT_PORT}

  2. Point nginx at the upstream — in your server block set:
       proxy_pass http://mtgban;        # was http://localhost:8080
     then:  sudo nginx -t && sudo systemctl reload nginx

  3. Retire any old single-instance unit if present:
       sudo systemctl disable --now mtgban.service

  4. GitHub deploy key + secrets (DROPLET_HOST / DROPLET_SSH_USER /
     DROPLET_SSH_KEY) — see deploy/README.md.

Then push a vX.Y.Z (or beta-X.Y.Z) tag to trigger a deploy.
================================================================
EOF
