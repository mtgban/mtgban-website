# Droplet zero-downtime deploy

Pushing a semver tag (`vX.Y.Z` or `beta-X.Y.Z`) triggers
`.github/workflows/magic-deploy.yml`, which SSHes into the droplet and runs
`deploy/deploy.sh`. The script builds the tag in the **idle** port's checkout,
starts it, waits for `/healthz`, flips nginx to it, then drains and stops the
old instance. nginx always points at `127.0.0.1` via the `mtgban` upstream;
only the port behind it changes.

## Layout

Each port runs from its **own** checkout, so building new code/assets never
mutates files under the live instance (templates are cached at boot, but
`/css` `/js` `/img` are served from disk per-request — a shared checkout would
404 hashed assets mid-deploy):

```
/home/koda/src/mtgban-website/        control repo — runs deploy.sh, nothing serves from here
/home/koda/src/mtgban-website-8081/   runtime checkout for mtgban@8081 (own binary, datastore, logs)
/home/koda/src/mtgban-website-8082/   runtime checkout for mtgban@8082
```

`git checkout --force` resets only tracked files, so each checkout's untracked
datastore + logs persist across deploys.

## More than one site on a droplet

A droplet can serve several games at once. `deploy/games.sh` is the one place
that says who owns what — a port pair, a checkout prefix, a systemd unit, an
nginx upstream — and both scripts read it, so adding a game is one line there:

```
magic          8081/8082   mtgban@          upstream mtgban
beta           8083/8084   mtgban-beta@     upstream mtgban_beta
yugioh         8091/8092   mtgban-yugioh@   upstream mtgban_yugioh
lorcana        8093/8094   ...
```

Every command takes the site as an environment variable, defaulting to magic:

```bash
GAME=yugioh ./deploy/bootstrap.sh      # once per game, on the droplet
GAME=yugioh deploy/deploy.sh <ref>     # what the workflow runs
```

It is an environment variable rather than an argument so that a caller passing
only a ref cannot have the ref read as a game name, or the reverse. A `GAME`
that names no allocation is refused rather than guessed at.

Magic keeps every name it was set up with before any of this existed —
`mtgban-website-<port>`, the bare `mtgban@` unit, `upstream mtgban` — so its
droplet needs no migration. The sites share one `/etc/mtgban.env`, since they
read one config bucket between them; everything else is per-site, including the
sudoers rule, which would otherwise be overwritten by the next game bootstrapped.

## Provisioning a new droplet

`deploy/cloud-init.sh` goes in the **User data** box when creating the droplet
(or `doctl compute droplet create --user-data-file deploy/cloud-init.sh`). Set
`GAME` on the second line first. It runs once as root and prepares the host:
deploy user with the keys DO injected, packages, the Go toolchain, the control
repo, and an empty `/etc/mtgban.env`.

It stops before secrets on purpose. User data stays readable for the life of
the droplet through the metadata service at `169.254.169.254`, so anything
pasted there is readable by every process on the box. The login banner names
the two steps left: fill in `/etc/mtgban.env`, then run `bootstrap.sh`.

## One-time droplet setup

The quick path: run **`./deploy/bootstrap.sh`** from the control repo (as the
deploy user, not root). It's idempotent and handles the packages (git, nginx,
build-essential, curl), the Go toolchain go.mod asks for, the checkouts,
systemd unit, placeholder secrets file, sudoers rule, nginx upstream include,
and the boot instance — then prints the manual follow-ups (real secrets, the
nginx server block edit, retiring any old unit, GitHub deploy key/secrets).

So a fresh droplet needs nothing installed beforehand: clone the repo and run
it. An existing host keeps whatever it already has — packages already present
are left alone, and a Go newer than go.mod's is not downgraded.

The steps below document what it does, for reference or manual setup.

### 1. Install the template unit, remove the old single unit

`deploy/mtgban.service.in` is a template, not a unit: `bootstrap.sh` fills in
the site's user, checkout prefix and config path and installs the result as
`mtgban@.service` (magic) or `mtgban-<game>@.service`. To do it by hand:

```bash
cd /home/koda/src/mtgban-website
sed -e 's|@GAME@|magic|' -e 's|@USER@|koda|g' \
    -e 's|@CO_PREFIX@|/home/koda/src/mtgban-website-|g' \
    -e 's|@CFG@|b2://mtgban-config/magic/config.json|' \
    deploy/mtgban.service.in | sudo tee /etc/systemd/system/mtgban@.service
sudo systemctl daemon-reload

# retire the old single-instance unit
sudo systemctl disable --now mtgban.service || true
```

### 2. Create the secrets env file (NOT in git)

The unit reads `BAN_SECRET` and the B2 config credentials from
`/etc/mtgban.env` via `EnvironmentFile=`. This file lives only on the droplet,
owned by root and mode 600 — it is never committed. Fill in the real values:

```bash
sudo tee /etc/mtgban.env >/dev/null <<'EOF'
BAN_SECRET=XXX
BAN_CONFIG_KEY=XXX
BAN_CONFIG_SECRET=XXX
EOF
sudo chmod 600 /etc/mtgban.env
sudo chown root:root /etc/mtgban.env
```

Format is plain `KEY=value` (no surrounding quotes — values are literal, not
shell-expanded). Both instances read the same file.

### 3. Create the two per-port checkouts and start 8081

Clone the repo once per port alongside the control repo, build, and start 8081
as the boot instance:

```bash
cd /home/koda/src
ORIGIN=$(git -C mtgban-website remote get-url origin)
git clone "$ORIGIN" mtgban-website-8081
git clone "$ORIGIN" mtgban-website-8082

# If the datastore is a LOCAL file (check `journalctl -u mtgban@8081 | grep
# 'Loading datastore from'` — bare filename = local, b2://|https:// = remote),
# copy it into each checkout so the first boot doesn't have to refetch. Skip
# this if the datastore is remote. Adjust the filename to your config's
# datastore_path. It's untracked, so it survives future `git checkout`s.
# cp mtgban-website/AllPrintings.json.xz mtgban-website-8081/
# cp mtgban-website/AllPrintings.json.xz mtgban-website-8082/

# Build and start the boot instance.
( cd mtgban-website-8081 && go build -o mtgban-website . )
sudo systemctl enable --now mtgban@8081

# datastore loads ~40s after start; poll until 200:
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/healthz
```

### 4. nginx upstream + server block

Create the upstream include and make it writable by `koda` (the deploy script
rewrites just this file, no sudo needed for the write):

```bash
echo 'upstream mtgban { server 127.0.0.1:8081; }' | sudo tee /etc/nginx/conf.d/mtgban_upstream.conf
sudo chown koda:koda /etc/nginx/conf.d/mtgban_upstream.conf
```

Point the site at the upstream — in the `xxx.mtgban.com` server block:

```nginx
location / {
    proxy_pass http://mtgban;          # was http://localhost:8080
    proxy_read_timeout 300;
    proxy_connect_timeout 300;
    proxy_send_timeout 300;

    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
}
```

Then `sudo nginx -t && sudo systemctl reload nginx`.

### 5. Passwordless sudo for the deploy commands

`deploy.sh` needs to start/stop/enable/disable the two instances and reload
nginx without a password. Confirm the systemctl path first (`which systemctl`,
usually `/usr/bin/systemctl`), then:

```bash
sudo tee /etc/sudoers.d/mtgban-deploy >/dev/null <<'EOF'
koda ALL=(root) NOPASSWD: /usr/bin/systemctl restart mtgban@8081, \
    /usr/bin/systemctl restart mtgban@8082, \
    /usr/bin/systemctl stop mtgban@8081, \
    /usr/bin/systemctl stop mtgban@8082, \
    /usr/bin/systemctl enable mtgban@8081, \
    /usr/bin/systemctl enable mtgban@8082, \
    /usr/bin/systemctl disable mtgban@8081, \
    /usr/bin/systemctl disable mtgban@8082, \
    /usr/bin/systemctl reload nginx, \
    /usr/sbin/nginx -t
EOF
sudo visudo -cf /etc/sudoers.d/mtgban-deploy   # validate
```

### 6. Deploy SSH key for GitHub Actions

On the droplet, create a dedicated keypair and authorize it for `koda`:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/gh_deploy -N '' -C 'github-actions-deploy'
cat ~/.ssh/gh_deploy.pub >> ~/.ssh/authorized_keys
cat ~/.ssh/gh_deploy        # private key -> GitHub secret DROPLET_SSH_KEY
```

### 7. GitHub repo secrets

```bash
gh secret set DROPLET_HOST     --body "<droplet-ip>"
gh secret set DROPLET_SSH_USER --body "koda"
gh secret set DROPLET_SSH_KEY  < ~/.ssh/gh_deploy   # the private key from step 5
```

## Deploying

```bash
git tag v1.2.3
git push origin v1.2.3
```

The workflow runs `deploy.sh v1.2.3` on the droplet. You can also trigger a
manual run (any ref) from the Actions tab via `workflow_dispatch`.

## Rollback

**A failed deploy rolls itself back.** Whatever goes wrong — the build, a
startup that never reaches `/healthz`, an instance that dies in the first
seconds of real traffic — the script restores the nginx upstream, restarts and
re-enables the previous instance, stops the new one, and exits non-zero. The
site is left on the release that was working, and the log says which one that
is. The idle checkout is deliberately left at the failed ref so it can be
inspected; the next deploy overwrites it.

Two things make that possible: the old instance is not stopped until the new
one has served for `SETTLE_SECONDS` past the flip, and boot autostart is not
moved until then either, so a reboot mid-failure comes back on the good
release.

**To roll back a deploy that succeeded** — one that passed its checks and only
looked wrong later — re-deploy the previous tag: `git push origin v1.2.2` (or
run the workflow manually with that ref). The script builds and flips to
whatever ref it is given, so rolling back is the same path as rolling forward.
