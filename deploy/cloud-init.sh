#!/bin/bash
#
# Droplet user-data: paste into the "User data" box when creating the droplet
# in the DigitalOcean control panel, or pass with `doctl compute droplet create
# --user-data-file deploy/cloud-init.sh`. Runs once, as root, on first boot.
#
# Set GAME below to the site this droplet will serve first. Adding a second
# site later is a bootstrap.sh run, not another droplet.
#
# It prepares the host — deploy user, packages, Go, the control repo, an empty
# secrets file — and stops there. It deliberately does NOT fill in secrets or
# start anything: user-data is readable for the life of the droplet by anything
# that can reach the metadata service at 169.254.169.254, so a key pasted here
# is a key published to every process on the box. Fill /etc/mtgban.env over ssh
# instead, then run bootstrap.sh, which is the one command left to run.
#
# Progress lands in /var/log/cloud-init-output.log, and the remaining steps in
# the login banner.

set -euxo pipefail

GAME=yugioh
DEPLOY_USER=koda
ORIGIN=https://github.com/mtgban/mtgban-website.git

SRC_DIR="/home/${DEPLOY_USER}/src"
REPO_DIR="${SRC_DIR}/mtgban-website"

# 1. Deploy user, with the keys DO injected for root, so the same key that
#    opens the console session opens this account.
if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" "$DEPLOY_USER"
fi
usermod -aG sudo "$DEPLOY_USER"
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/${DEPLOY_USER}/.ssh"
if [ -f /root/.ssh/authorized_keys ]; then
    install -m 600 -o "$DEPLOY_USER" -g "$DEPLOY_USER" \
        /root/.ssh/authorized_keys "/home/${DEPLOY_USER}/.ssh/authorized_keys"
fi

# bootstrap.sh sudoes for the privileged parts and is meant to be run without a
# terminal to type a password into. The scoped, passwordless rule it installs
# for the deploy commands replaces this one; until then it needs a way in.
echo "${DEPLOY_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-${DEPLOY_USER}-bootstrap
chmod 440 /etc/sudoers.d/99-${DEPLOY_USER}-bootstrap

# 2. Packages. bootstrap.sh installs these too, but doing it here means the
#    slow part is over before anyone logs in.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y git nginx build-essential curl

# 3. The control repo, which carries bootstrap.sh and everything it reads.
install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$SRC_DIR"
if [ ! -d "$REPO_DIR/.git" ]; then
    sudo -u "$DEPLOY_USER" git clone "$ORIGIN" "$REPO_DIR"
fi

# 4. The Go the module asks for, by the same rule bootstrap.sh applies, so its
#    own check finds a new-enough toolchain and skips the download.
GO_WANT=go$(awk '/^go [0-9]/{print $2; exit}' "$REPO_DIR/go.mod")
GO_ARCH=$(dpkg --print-architecture)
curl -fsSL -o "/tmp/${GO_WANT}.linux-${GO_ARCH}.tar.gz" \
    "https://go.dev/dl/${GO_WANT}.linux-${GO_ARCH}.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "/tmp/${GO_WANT}.linux-${GO_ARCH}.tar.gz"
rm -f "/tmp/${GO_WANT}.linux-${GO_ARCH}.tar.gz"
ln -sf /usr/local/go/bin/go /usr/local/bin/go

# 5. Secrets file, empty. Root-owned and unreadable by the deploy user, which
#    is what systemd's EnvironmentFile wants and what keeps the values off the
#    account that ssh reaches.
if [ ! -f /etc/mtgban.env ]; then
    cat > /etc/mtgban.env <<'EOF'
BAN_SECRET=XXX
BAN_CONFIG_KEY=XXX
BAN_CONFIG_SECRET=XXX
EOF
    chmod 600 /etc/mtgban.env
    chown root:root /etc/mtgban.env
fi

# 6. Say what is left, where whoever logs in will see it.
cat > /etc/motd <<EOF

  This droplet was prepared for: ${GAME}
  Two steps remain, both as ${DEPLOY_USER}:

    1. sudo nano /etc/mtgban.env        # replace the three XXX values
    2. cd ${REPO_DIR} && GAME=${GAME} ./deploy/bootstrap.sh

  bootstrap.sh prints what is left after that: the nginx server block, the
  certificate, and the GitHub secrets the deploy workflow needs.

EOF

echo "cloud-init done for ${GAME}; see /etc/motd"
