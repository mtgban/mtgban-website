#!/usr/bin/env bash
#
# Everything the droplet needs from the distro to serve the site. Run it on a
# fresh host before anything else, or on an existing one to pick up a package
# added to the list:
#
#     ./deploy/host-packages.sh
#
# Works as the deploy user, which is how bootstrap.sh calls it, or as root,
# which is how cloud-init does. Idempotent: only what is missing is installed,
# so a re-run says so and does nothing.
#
# The Go toolchain is deliberately not here. It comes from go.dev rather than
# apt, at the version go.mod names, which is bootstrap.sh's business because
# bootstrap.sh is the one that has the repo to read it from.

set -euo pipefail

PACKAGES=(
    git                              # the per-port checkouts, and deploy.sh's fetch
    curl                             # health checks, and fetching the Go tarball
    build-essential                  # the toolchain's C dependencies
    nginx                            # what the internet actually reaches
    certbot                          # TLS certificates, renewed by its own timer
    python3-certbot-nginx            # so certbot can edit and reload nginx itself
    libnginx-mod-http-brotli-filter  # brotli for what nginx compresses per request
    libnginx-mod-http-brotli-static  # and for the .br files it serves as they are
)

SUDO=sudo
if [ "$(id -u)" = 0 ]; then
    SUDO=
fi

missing=()
for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        missing+=("$pkg")
    fi
done

if [ ${#missing[@]} -eq 0 ]; then
    echo "==> packages       : present"
    exit 0
fi

echo "==> installing packages: ${missing[*]}"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y "${missing[@]}"

