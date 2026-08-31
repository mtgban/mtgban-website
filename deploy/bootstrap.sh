#!/usr/bin/env bash
#
# One-time droplet setup for the blue-green deploy. Idempotent — safe to re-run.
#
# Run as the deploy user (koda), NOT with sudo — it calls sudo itself for the
# privileged bits:
#     ./deploy/bootstrap.sh                 # magic
#     GAME=yugioh ./deploy/bootstrap.sh     # any other game
#
# One game per droplet, so every host uses the same ports, checkouts, unit and
# upstream. GAME settles which config the unit starts the binary with, and that
# is the only thing about a host that its game decides — which is why deploy.sh
# needs no game at all.
#
# It sets up: the two per-port checkouts, the systemd template unit, the
# secrets env file (placeholders), the scoped sudoers rule, the nginx upstream
# include, and the boot instance on this game's first port. It does NOT edit
# your nginx server block, fill in real secrets, or provision the GitHub deploy
# key — those are printed as manual follow-ups at the end.

set -euo pipefail

# --- config (override via env if needed) -----------------------------------
GAME=${GAME:-magic}
PORTS=(8081 8082)
BOOT_PORT=${PORTS[0]}                            # the instance enabled at boot
UNIT=${UNIT:-mtgban}                             # systemd template: ${UNIT}@<port>
UPSTREAM_NAME=${UPSTREAM_NAME:-mtgban}           # what the server block proxy_passes to
UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/conf.d/mtgban_upstream.conf}
SUDOERS_FILE=${SUDOERS_FILE:-/etc/sudoers.d/mtgban-deploy}
UNIT_FILE=${UNIT_FILE:-/etc/systemd/system/${UNIT}@.service}
ENV_FILE=${ENV_FILE:-/etc/mtgban.env}
READY_TIMEOUT=${READY_TIMEOUT:-300}
# The one name a game decides. Every game reads its own config from the bucket
# under its own name, so all a droplet holds is the key to that bucket.
CFG=${CFG:-b2://mtgban-config/${GAME}/config.json}
export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"
# ---------------------------------------------------------------------------

# Resolve paths from this script's location: control repo is the parent of
# deploy/, and the per-port checkouts are siblings of the control repo.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
SRC_DIR=$(dirname "$REPO_DIR")
REPO_NAME=$(basename "$REPO_DIR")               # e.g. mtgban-website
CO_PREFIX=${CO_PREFIX:-$SRC_DIR/${REPO_NAME}-}  # -> .../mtgban-website-8081

if [ "$(id -u)" = 0 ]; then
    echo "!! run as the deploy user (e.g. koda), not root — the script uses sudo itself" >&2
    exit 1
fi

# 0. Prerequisites. Installing only what is missing keeps a re-run quiet, and
#    keeps this script the single answer to "what does a fresh droplet need".
ensure_packages() {
    local missing=() pkg
    for pkg in git nginx build-essential curl; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -eq 0 ]; then
        echo "==> packages       : present"
        return
    fi
    echo "==> installing packages: ${missing[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${missing[@]}"
}

# The Go the module asks for, from go.dev rather than apt: the distro packages
# trail the toolchain by whole releases, and this repo builds with what go.mod
# names. An already-installed Go that is new enough is left alone, so this only
# downloads on a fresh host or a version bump.
ensure_go() {
    local want have arch tarball
    want=go$(awk '/^go [0-9]/{print $2; exit}' "$REPO_DIR/go.mod")
    have=$(command -v go >/dev/null 2>&1 && go env GOVERSION || echo go0)
    if [ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" = "$want" ]; then
        echo "==> go             : $have (needs $want)"
        return
    fi

    arch=$(dpkg --print-architecture)
    tarball="${want}.linux-${arch}.tar.gz"
    echo "==> installing $want ($arch), replacing ${have#go0}"
    curl -fsSL -o "/tmp/${tarball}" "https://go.dev/dl/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    # Onto the default PATH, so a plain `ssh droplet go version` works. deploy.sh
    # exports the path too, but only for itself.
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
}

ensure_packages
ensure_go
command -v go        >/dev/null || { echo "!! go still not found in PATH ($PATH)" >&2; exit 1; }
SYSTEMCTL=$(command -v systemctl)
NGINX=$(command -v nginx || echo /usr/sbin/nginx)
DEPLOY_USER=$(id -un)
ORIGIN=$(git -C "$REPO_DIR" remote get-url origin)

echo "==> game          : $GAME  (unit ${UNIT}@, upstream $UPSTREAM_NAME)"
echo "==> control repo  : $REPO_DIR"
echo "==> origin        : $ORIGIN"
echo "==> config        : $CFG"
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

# 2. systemd template unit, rendered for this host. Substituting rather than
#    copying is what lets one template serve every game - the -cfg is the whole
#    of the difference - and what keeps the deploy user out of the repo.
echo "==> installing systemd unit -> $UNIT_FILE"
sed -e "s|@GAME@|${GAME}|" \
    -e "s|@USER@|${DEPLOY_USER}|g" \
    -e "s|@CO_PREFIX@|${CO_PREFIX}|g" \
    -e "s|@CFG@|${CFG}|" \
    "$REPO_DIR/deploy/mtgban.service.in" | sudo tee "$UNIT_FILE" >/dev/null
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
        # No .service suffix — must match exactly how deploy.sh invokes sudo.
        cmds+="${cmds:+, }$SYSTEMCTL $verb ${UNIT}@${port}"
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
    echo "upstream ${UPSTREAM_NAME} { server 127.0.0.1:${BOOT_PORT}; }" | sudo tee "$UPSTREAM_CONF" >/dev/null
    sudo chown "$DEPLOY_USER:$DEPLOY_USER" "$UPSTREAM_CONF"
fi

# 6. Build both checkouts.
for port in "${PORTS[@]}"; do
    echo "==> [$port] building"
    ( cd "${CO_PREFIX}${port}" && go build -o mtgban-website . )
done

# 7. Bring up the boot instance and wait for it to go healthy.
echo "==> enabling + starting ${UNIT}@${BOOT_PORT}"
sudo "$SYSTEMCTL" enable --now "${UNIT}@${BOOT_PORT}"
echo "==> waiting for :${BOOT_PORT}/healthz (up to ${READY_TIMEOUT}s)"
ready=0
for ((i=0; i<READY_TIMEOUT; i++)); do
    if curl -fs "http://127.0.0.1:${BOOT_PORT}/healthz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
done
if [ "$ready" = 1 ]; then
    echo "==> ${UNIT}@${BOOT_PORT} healthy"
else
    # The usual cause by far, on a droplet cloud-init has just prepared: the
    # instance cannot fetch its config without the bucket key, so it exits and
    # systemd restarts it forever. Say that outright rather than handing over
    # a log to read, and fall back to the log for anything else.
    echo "!! ${UNIT}@${BOOT_PORT} never answered /healthz in ${READY_TIMEOUT}s"
    if sudo grep -q '=XXX' "$ENV_FILE" 2>/dev/null; then
        echo "!! $ENV_FILE still holds placeholders, which is reason enough"
    else
        echo "!! last 40 log lines:"
        sudo journalctl -q -u "${UNIT}@${BOOT_PORT}" -n 40 --no-pager | sed 's/^/     /'
    fi
fi

# Printed on both paths: the steps below are what is left either way, and the
# first of them is what an unhealthy instance is usually waiting for.
cat <<EOF

================================================================
Remaining MANUAL steps:

  1. Put real values in $ENV_FILE (if it still has XXX), then:
       sudo systemctl restart ${UNIT}@${BOOT_PORT}

  2. Point nginx at the upstream — in this host's server block set:
       proxy_pass http://${UPSTREAM_NAME};
     then:  sudo nginx -t && sudo systemctl reload nginx

  3. Retire any old single-instance unit if present:
       sudo systemctl disable --now mtgban.service

  4. GitHub deploy key + secrets (DROPLET_HOST / DROPLET_SSH_USER /
     DROPLET_SSH_KEY) — see deploy/README.md.

Then push a tag to trigger a deploy. The workflow runs:
     deploy/deploy.sh <ref>
================================================================
EOF

# A host whose instance never came up is not set up, whatever else succeeded.
# Said last and with the exit code, so a caller - or a person scrolling past
# the steps above - cannot read this run as having worked.
if [ "$ready" != 1 ]; then
    echo
    echo "!! bootstrap FAILED: ${UNIT}@${BOOT_PORT} is not serving"
    exit 1
fi

echo
echo "==> bootstrap complete: ${UNIT}@${BOOT_PORT} is serving"
