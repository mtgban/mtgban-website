#!/usr/bin/env bash
#
# Zero-downtime blue-green deploy for mtgban-website on the droplet.
#
# Each port runs from its OWN checkout (mtgban-website-8081 / -8082) so that
# building new code and assets never mutates files under the live instance
# (templates are cached at boot, but /css /js /img are served from disk at
# request time — a shared checkout would 404 hashed assets mid-deploy).
#
# Invoked over SSH by the GitHub Actions workflow (which has already checked
# out <ref> in the control repo so this is the right script version):
#     deploy.sh <git-ref>
#
# git checkout --force only resets TRACKED files, so each checkout's untracked
# datastore + logs survive across deploys.

set -euo pipefail

# --- config ----------------------------------------------------------------
CO_PREFIX=/home/koda/src/mtgban-website-      # per-port checkouts: ${CO_PREFIX}8081 / ...8082
UPSTREAM_CONF=/etc/nginx/conf.d/mtgban_upstream.conf   # chown'd to koda, see README
DRAIN_SECONDS=5        # let nginx finish routing to the new port before stopping old
READY_TIMEOUT=180      # max seconds to wait for the new instance's datastore

# Go isn't on the non-interactive SSH PATH by default; adjust to `which go`.
export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"
# ---------------------------------------------------------------------------

REF="${1:-}"
[ -n "$REF" ] || { echo "usage: deploy.sh <git-ref>"; exit 2; }
echo "==> deploying ref: $REF"

# 1. Determine the current live port, flip to the idle one.
CUR=$(grep -oE '127\.0\.0\.1:[0-9]+' "$UPSTREAM_CONF" | cut -d: -f2)
if [ "$CUR" = "8081" ]; then NEW=8082; else NEW=8081; fi
NEW_CO="${CO_PREFIX}${NEW}"
echo "==> current=$CUR  new=$NEW  checkout=$NEW_CO"
[ -d "$NEW_CO/.git" ] || { echo "!! $NEW_CO is not a git checkout — run the one-time setup"; exit 1; }

# 2. Update the idle checkout to the requested ref and build it there.
#    Fetch the specific ref and check out FETCH_HEAD so this is correct for both
#    tags and branches — a plain `git checkout <branch>` after fetch would use
#    the stale local branch, since fetch doesn't move local branch refs.
git -C "$NEW_CO" fetch --force --prune --tags origin "$REF"
git -C "$NEW_CO" checkout --force FETCH_HEAD
echo "==> $NEW_CO at $(git -C "$NEW_CO" rev-parse --short HEAD)"
mkdir -p "$NEW_CO/logs"
echo "==> building -> $NEW_CO/mtgban-website"
( cd "$NEW_CO" && go build -o mtgban-website . )

# 3. (Re)start the new instance on the idle port. Use restart, not start, so a
#    lingering instance from a prior partial deploy is replaced with the freshly
#    built binary rather than left running as a no-op serving stale code.
echo "==> restarting mtgban@$NEW"
sudo systemctl restart "mtgban@${NEW}"

# 4. Wait for its datastore + scrapers to load (/healthz returns 200).
#    Distinct ports, so curling :$NEW hits the new instance directly.
echo "==> waiting for :$NEW/healthz (up to ${READY_TIMEOUT}s)"
ready=0
for ((i=0; i<READY_TIMEOUT; i++)); do
    if curl -fs "http://127.0.0.1:${NEW}/healthz" >/dev/null 2>&1; then ready=1; break; fi
    if ! systemctl is-active --quiet "mtgban@${NEW}"; then
        echo "!! mtgban@${NEW} died on startup:"
        journalctl -u "mtgban@${NEW}" -n 40 --no-pager
        exit 1
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "!! timeout waiting for :$NEW/healthz — rolling back"
    sudo systemctl stop "mtgban@${NEW}"
    exit 1
fi
echo "==> new instance ready"

# 5. Flip nginx to the new port (graceful reload — no dropped connections).
echo "==> flipping nginx to :$NEW"
printf 'upstream mtgban { server 127.0.0.1:%s; }\n' "$NEW" > "$UPSTREAM_CONF"
if ! sudo nginx -t; then
    echo "!! nginx -t failed — rolling back upstream + new instance"
    printf 'upstream mtgban { server 127.0.0.1:%s; }\n' "$CUR" > "$UPSTREAM_CONF"
    sudo systemctl stop "mtgban@${NEW}"
    exit 1
fi
sudo systemctl reload nginx

# 6. Keep boot autostart in sync with the live instance.
echo "==> boot autostart: enable $NEW, disable $CUR"
sudo systemctl enable  "mtgban@${NEW}"
sudo systemctl disable "mtgban@${CUR}" || true

# 7. Drain, then stop the old instance (SIGTERM -> srv.Shutdown()).
echo "==> draining ${DRAIN_SECONDS}s, then stopping mtgban@$CUR"
sleep "$DRAIN_SECONDS"
sudo systemctl stop "mtgban@${CUR}" || true

echo "==> deploy complete ($CUR -> $NEW) @ $REF"
