# Moving a droplet to another region

The Magic droplet runs in **SFO3**, beside the archive and newspaper
databases. A droplet in another region pays the distance on every query:
from NYC1 a database round trip was 68-76 ms, from SFO3 it is under 1 ms.
Postgres answers a chart query in 1-3 ms, so across the country nearly all
of a query's cost is the wire, and opening a connection (TCP, TLS, SCRAM:
4-6 round trips) costs a quarter-second.

**Move the app, not the database.** The app is rebuilt from this repo on
every deploy; the archive is a ~1.3-billion-row table on a droplet's disk.
If the databases have to be the ones that move, see the appendix.

The route below copies the droplet whole through a snapshot, so everything
git does not hold comes with it: the nginx server block, the Let's Encrypt
certificate and its renewal config, `/etc/mtgban.env`, the sudoers rule,
the systemd units and timers, the deploy key and both per-port checkouts.
Building a fresh host with `deploy/bootstrap.sh` (`deploy/README.md`) also
works, but then each of those has to be carried over by hand, and the
certificate has to be issued by DNS-01 before the cutover.

## Before you start

- [ ] Note the droplet's size, VPC and SSH key, so the copy matches:
      ```bash
      doctl compute droplet list --format ID,Name,Region,SizeSlug,PublicIPv4,VPCUUID
      doctl vpcs list --format ID,Name,Region
      doctl compute ssh-key list
      ```
      Pick the target region's VPC that the databases' VPC is peered with
      (`doctl vpcs peerings list`); in SFO3 that is
      `mtgban-card-prices-sfo03-vpc`, shared with `pokemon` and `yugioh`.
- [ ] Note which A records point at the droplet; `mtgban.com` and
      `ban.cards` both carry some:
      ```bash
      doctl compute domain records list <domain> --format ID,Type,Name,Data,TTL
      ```
- [ ] Check what else runs there (`systemctl list-units --type=service
      --state=running`, `crontab -l` for root and the deploy user): the
      snapshot carries it, but anything that must not run twice has to be
      kept off on one side.

Lowering the DNS TTL first is optional. Both hosts serve the same site, so a
long TTL only lengthens the overlap; with the 3600 s TTL the old host went
quiet about an hour after the records changed.

## 1. Snapshot and transfer

```bash
doctl compute droplet-action snapshot <droplet-id> --snapshot-name <name> --wait
doctl compute image-action transfer <image-id> --region sfo3 --wait
```

A live snapshot is fine: the host keeps nothing a request writes. The
transfer of a ~23 GB image takes a few minutes.

## 2. Create the copy with the app held off

The copy boots with the old host's units enabled, so it would start the app,
and with it a second Discord bot on the same token, which answers every
command twice. Hold the app off at boot with this user data:

```yaml
#cloud-config
bootcmd:
  - [ sh, -c, "systemctl disable mtgban@8081 mtgban@8082 || true; systemctl stop mtgban@8081 mtgban@8082 || true" ]
```

```bash
doctl compute droplet create <name> --region sfo3 --size <size> \
    --image <image-id> --vpc-uuid <vpc-id> --ssh-keys <key-id> \
    --enable-monitoring --user-data-file clone-user-data.yaml --wait
```

Also `systemctl disable --now mtgban-self-cycle.timer` on the copy, since it
runs `deploy.sh --live` and would start the app again.

The databases accept the new address as they are: their `pg_hba.conf` and
firewalls name no app IP.

## 3. Upgrade the release, if it is due

The copy is the moment for it, while no traffic depends on the host:

```bash
systemd-run --unit=release-upgrade --setenv=DEBIAN_FRONTEND=noninteractive \
    /bin/sh -c "do-release-upgrade -f DistUpgradeViewNonInteractive > /root/release-upgrade.log 2>&1"
```

Run it under `systemd-run`: sshd restarts partway through and takes an
interactive session with it. Reboot when it finishes, then **re-run
`deploy/host-packages.sh`**: the upgrade's cleanup removes `build-essential`,
`pkg-config` and `libcrypt-dev` as unneeded, and without them the next
deploy cannot build. Check that a `go build` passes in a checkout as the
deploy user before going further.

## 4. Verify before any traffic moves

Start the app on whichever port `/etc/nginx/conf.d/mtgban_upstream.conf`
names (`systemctl start mtgban@<port>`) and wait for `/healthz`. Then
compare the two hosts through the real hostname, bypassing DNS:

```bash
for p in / "/search?q=Lightning+Bolt" /newspaper /graded /api-plans; do
  for ip in <old-ip> <new-ip>; do
    curl -s --resolve mtgban.com:443:$ip -o /dev/null -H 'Accept-Encoding: br' \
      -w "$p $ip code=%{http_code} bytes=%{size_download} verify=%{ssl_verify_result}\n" \
      "https://mtgban.com$p"
  done
done
```

The same status and size on both, and `verify=0`, mean the page, the
certificate and nginx came across. Sales velocity and popular searches load
from warm-up jobs a few minutes after start; a difference there that clears
on its own is that. Stop the app again until the cutover.

## 5. Cut over

1. Start the app for good on the new host:
   ```bash
   systemctl enable --now mtgban@<port> mtgban-self-cycle.timer
   ```
2. Point GitHub Actions at it, or the next tag deploys to the old host. The
   checkout has several remotes, so name the repository:
   ```bash
   gh secret set DROPLET_HOST -R mtgban/mtgban-website --body "<new-ip>"
   ```
   The deploy key came with the snapshot, so `DROPLET_SSH_KEY` stays.
3. Move the A records:
   ```bash
   doctl compute domain records update <domain> --record-id <id> --record-data <new-ip>
   ```
4. Stop the old host's app and self-cycle timer, so only one Discord bot
   answers; nginx there keeps proxying for whoever still resolves the old
   address until the TTL runs out:
   ```bash
   systemctl disable --now mtgban@8081 mtgban@8082 mtgban-self-cycle.timer
   ```
   Then wait, watching `/var/log/nginx/access.log` on both, until the old
   host gets no requests.
5. Once DNS points at the new host, `certbot renew --dry-run` there must
   succeed: renewal is HTTP-01, which validates against whichever host the
   name resolves to.
6. Power the old droplet off (`doctl compute droplet-action shutdown <id>
   --wait`) and leave it for a day. It is the rollback.

## 6. Point the app at the databases over the VPC

The databases answer the app on their public addresses as well, and in one
region that already costs under a millisecond. The private addresses keep
the traffic off the public internet: set them in `infrastructure.json`
(`sql_config`, `user_state_config`, `observability_config`,
`new_newspaper_sql_config`) and in any game config that sets its own. Keep
`sslmode=require`.

## Rollback

Power the old droplet on, enable its app and timer, point the A records and
`DROPLET_HOST` back at it, and disable the app on the new host. Nothing on
either host is authoritative, so a rollback loses nothing but the time.

## Decommission

After a day of clean logs: destroy the old droplet. The snapshot from step 1
keeps its state if anything turns out to be missing; delete it when that is
no longer a worry.

---

## Appendix A: the other deployments

`pokemon` and `yugioh` run on droplets of their own and move the same way,
with `DROPLET_HOST_<GAME>` in place of `DROPLET_HOST` at cutover. Every other
game deploys as an App Platform app driven by `doctl` (`fleshandblood`,
`gundam`, `lorcana`, `onepiece`, `palworld`, `riftbound`), and an App
Platform app carries no state at all.

Find out where each one actually is before moving anything:

```bash
doctl compute droplet list --format Name,Region
doctl apps list --format ID,Spec.Name,DefaultIngress
doctl apps spec get <app-id> | grep -i '^region:'
```

App Platform fixes region at creation, so a move is: fetch the spec, edit
`region:` to `sfo3`, create a **new** app from it, verify it, move the domain,
delete the old one.

```bash
doctl apps spec get <app-id> > app.yaml
# edit region: in app.yaml
doctl apps create --spec app.yaml --wait
```

## Appendix B: if the databases move instead

More work, and it is the direction with the data in it. Two options:

**Snapshot and rebuild.** Power off, snapshot, transfer the snapshot,
build a droplet from it, repoint `infrastructure.json` and any config that
sets its own databases. Downtime is the transfer, which at this table's size
is not minutes.

**Replicate and promote.** Stand up a Postgres in the new region, set up
streaming replication, let it catch up, then stop writes, promote the
replica, and repoint them the same way. Minutes of downtime instead of hours,
at the cost of a more delicate procedure. Remember the *three* databases
(`card_prices`, `userstate`, `observability`) plus the separate newspaper
host: each needs the same treatment, and the ingest that runs beside the
archive needs to move with it or reach it across the country instead.
