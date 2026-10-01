#!/usr/bin/env bash
#
# Cycles this host's live mtgban instance through its own blue-green
# deploy.sh, at its current ref (no code change), but only when needrestart
# actually flags the unit as running against stale, upgraded libraries.
#
# needrestart.conf is list-only (bootstrap.sh) specifically so nothing ever
# restarts a live instance out from under real traffic on its own - but left
# at only that, an instance would run stale libraries indefinitely, until
# the next real code deploy happened to come along. This is what closes that
# gap without reintroducing the risk list-only exists to remove: a real
# restart drops in-flight requests, but deploy.sh's blue-green flip does
# not - build the idle checkout, wait for /healthz, flip nginx, drain the
# old one - so cycling through it is safe to run unattended, on a schedule,
# unlike a raw `systemctl restart`.
#
# Invoked by <UNIT>-self-cycle.timer, hourly, as root - see bootstrap.sh.
# needrestart -b needs root to see every unit's process, not just ones the
# deploy user owns: confirmed live, as the deploy user it prints only the
# NEEDRESTART-VER line and nothing else, so a non-root run of this script
# would silently never fire. Root needs no sudoers rule to become another
# user, so the two parts that must run as the deploy user - reading a git
# checkout root does not own (git's own dubious-ownership guard) and
# deploy.sh itself, whose internal sudo calls are scoped to that user
# specifically - drop to it via a plain `sudo -u`, not a grant of any kind.
set -euo pipefail

UNIT=${UNIT:-mtgban}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
DEPLOY_USER=${DEPLOY_USER:-$(stat -c '%U' "$REPO_DIR")}

if ! needrestart -b 2>/dev/null | grep -q "^NEEDRESTART-SVC: ${UNIT}@"; then
    exit 0
fi

# deploy.sh reads the live ref once it holds the deploy lock, so a deploy
# running now is waited for, not undone.
echo "==> needrestart flags ${UNIT}@ - cycling at the live ref"
exec sudo -u "$DEPLOY_USER" -H "$SCRIPT_DIR/deploy.sh" --live
