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
# Overridable so the script can be exercised off the droplet; the defaults are
# the droplet's real paths.
CO_PREFIX=${CO_PREFIX:-/home/koda/src/mtgban-website-}   # per-port checkouts: ${CO_PREFIX}8081 / ...8082
UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/conf.d/mtgban_upstream.conf}   # chown'd to koda, see README
DRAIN_SECONDS=${DRAIN_SECONDS:-5}        # let nginx finish routing to the new port before stopping old
READY_TIMEOUT=${READY_TIMEOUT:-300}      # max seconds to wait for the new instance's datastore
SETTLE_SECONDS=${SETTLE_SECONDS:-20}     # watch the new instance after the flip, while the old one can still take over

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
CUR_CO="${CO_PREFIX}${CUR}"
# What is serving right now, which is what a failure falls back to. Printed on
# every path, so the log always names the release the site is left running.
LIVE_REF=$(git -C "$CUR_CO" describe --tags --always 2>/dev/null || echo unknown)
echo "==> current=$CUR ($LIVE_REF)  new=$NEW  checkout=$NEW_CO"
[ -d "$NEW_CO/.git" ] || { echo "!! $NEW_CO is not a git checkout — run the one-time setup"; exit 1; }

# Undo whatever this run changed and leave the previous release serving. Safe to
# call at any point: each line states what should be true, not what to undo, so
# it does not matter how far the deploy got before it failed.
FLIPPED=0
rollback() {
    echo "!! rolling back to :$CUR ($LIVE_REF)"
    if [ "$FLIPPED" = 1 ]; then
        printf 'upstream mtgban { server 127.0.0.1:%s; }\n' "$CUR" > "$UPSTREAM_CONF"
        sudo nginx -t && sudo systemctl reload nginx
    fi
    # The old instance is normally still running — it is only stopped once the
    # new one has proven itself — but start it anyway, in case the failure came
    # after that point.
    sudo systemctl start   "mtgban@${CUR}" || true
    sudo systemctl enable  "mtgban@${CUR}" || true
    sudo systemctl disable "mtgban@${NEW}" || true
    sudo systemctl stop    "mtgban@${NEW}" || true
    echo "!! serving :$CUR ($LIVE_REF); $NEW_CO left at the failed ref for inspection"
}

# Any failure — a build error, a systemctl that refuses, a health check this
# script gives up on — lands here rather than leaving the deploy half applied.
# On EXIT rather than ERR: ERR does not fire for an explicit `exit`, which is
# how every check below reports itself, so an ERR trap would quietly skip them.
trap 'rc=$?; trap - EXIT; [ "$rc" -eq 0 ] || rollback; exit $rc' EXIT

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
        echo "!! mtgban@${NEW} died on startup — last 60 log lines:"
        journalctl -q -u "mtgban@${NEW}" -n 60 --no-pager
        exit 1   # the ERR trap rolls back
    fi
    # Heartbeat: surface the instance's own progress (datastore/scraper load,
    # "healthz: not ready (uuids=… sellers=… vendors=…)") in the Action log
    # every 15s so a slow boot is diagnosable without SSHing into the box.
    if (( i > 0 && i % 15 == 0 )); then
        echo "==> still waiting (${i}/${READY_TIMEOUT}s) — latest instance logs:"
        journalctl -q -u "mtgban@${NEW}" -n 4 --no-pager | sed 's/^/     /'
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "!! timeout waiting for :$NEW/healthz after ${READY_TIMEOUT}s — last 60 log lines:"
    journalctl -q -u "mtgban@${NEW}" -n 60 --no-pager
    exit 1
fi
echo "==> new instance ready"

# 5. Flip nginx to the new port (graceful reload — no dropped connections).
echo "==> flipping nginx to :$NEW"
FLIPPED=1
printf 'upstream mtgban { server 127.0.0.1:%s; }\n' "$NEW" > "$UPSTREAM_CONF"
sudo nginx -t
sudo systemctl reload nginx

# 6. Watch the new instance while the old one is still there to take over.
#    Passing /healthz once only says it started; a release that dies on its
#    first real traffic — a database it cannot reach, a panic on a live
#    request — fails here instead, where the old instance is a reload away.
echo "==> settling ${SETTLE_SECONDS}s on :$NEW before retiring :$CUR"
for ((i=0; i<SETTLE_SECONDS; i++)); do
    if ! systemctl is-active --quiet "mtgban@${NEW}" || \
       ! curl -fs "http://127.0.0.1:${NEW}/healthz" >/dev/null 2>&1; then
        echo "!! :$NEW stopped answering ${i}s after the flip — last 60 log lines:"
        journalctl -q -u "mtgban@${NEW}" -n 60 --no-pager
        exit 1
    fi
    sleep 1
done

# 7. Keep boot autostart in sync with the live instance. Only now, so a reboot
#    during a failed deploy comes back on the release that was working.
echo "==> boot autostart: enable $NEW, disable $CUR"
sudo systemctl enable  "mtgban@${NEW}"
sudo systemctl disable "mtgban@${CUR}" || true

# 8. Drain, then stop the old instance (SIGTERM -> srv.Shutdown()). Past here a
#    rollback means deploying the previous tag, so the trap comes off.
trap - EXIT
echo "==> draining ${DRAIN_SECONDS}s, then stopping mtgban@$CUR"
sleep "$DRAIN_SECONDS"
sudo systemctl stop "mtgban@${CUR}" || true

echo "==> deploy complete ($CUR $LIVE_REF -> $NEW $REF)"
