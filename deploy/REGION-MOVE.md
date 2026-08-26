# Moving the droplet to the database's region

The app runs in **NYC1**; the archive and newspaper databases run in **SFO3**.
Every query the app makes crosses the country and back.

Measured from one client, so the absolute numbers include that client's own
distance — it is the *difference* that matters:

```
mtgban.com          118 ms
archive database    168 ms
newspaper database  168 ms
```

Call the app→database round trip **50-70 ms**. Postgres answers a chart query
in 1-3 ms, so ~98% of what a query costs is the wire. Opening a *new*
connection is worse: TCP, then TLS, then SCRAM auth is 4-6 round trips, or a
quarter-second before a single byte of data moves.

Co-locating removes all of it. It is worth more than every query optimisation
in the archive put together, and it is why `max_idle_conns` matters so much
today: an idle connection that gets closed costs a quarter-second to replace.

**Move the app, not the database.** The app is stateless - it is rebuilt from
this repo on every deploy - while the archive is a ~1.3-billion-row table on a
droplet's disk. Same win, a fraction of the work. If the databases have to be
the ones that move (say most traffic is East Coast and the extra ~50 ms to the
front end is unacceptable), see the appendix.

## Before you start

- [ ] Drop the DNS TTL for the hostnames to 60s, **at least a day ahead**, so
      the cutover is quick and the rollback is quicker.
- [ ] Note the current droplet's size and image, so the new one matches.
- [ ] Confirm what else runs on the app droplet: `systemctl list-units --type=service --state=running`,
      and `crontab -l` for both the deploy user and root. Anything found here
      has to move too, or be deliberately left behind.
- [ ] Have the real `/etc/mtgban.env` and the per-checkout `config.json` to
      hand. Neither is in git; both are needed on the new host.

## 1. Provision the new droplet in SFO3

Same size and image as the current one. Console, or:

```bash
doctl compute droplet create mtgban-sfo3 \
    --region sfo3 --size <same-as-now> --image <same-as-now> \
    --ssh-keys <your-key-id> --enable-private-networking --wait
```

Private networking matters: once the app and the databases share a region they
can talk over the VPC instead of the public internet. Step 5 uses that.

## 2. Clone and bootstrap

Create the deploy user with the same name as the old host (`koda`, per
`deploy/README.md`) so the systemd unit paths and sudoers rule apply unchanged.
Then:

```bash
mkdir -p /home/koda/src && cd /home/koda/src
git clone <origin> mtgban-website
cd mtgban-website
./deploy/bootstrap.sh          # as the deploy user, NOT root — it sudoes itself
```

That is the whole of the host setup: it installs the packages and the Go
toolchain go.mod asks for, creates both per-port checkouts, installs the
systemd unit and the scoped sudoers rule, writes the nginx upstream include,
and starts the boot instance. Idempotent, so a re-run after fixing something is
safe.

## 3. Carry over what git does not

From the **old** droplet:

```bash
# secrets (root-owned, mode 600)
sudo cat /etc/mtgban.env                    # copy into the same path on the new host

# per-checkout config — contains database credentials
scp mtgban-website-8081/config.json  new-host:/home/koda/src/mtgban-website-8081/
scp mtgban-website-8082/config.json  new-host:/home/koda/src/mtgban-website-8082/
```

If the datastore is a local file rather than `b2://` or `https://`, copy it into
both checkouts as well, or the first boot spends minutes fetching it:

```bash
journalctl -u mtgban@8081 | grep 'Loading datastore from'   # bare filename = local
```

## 4. nginx and TLS

Recreate the server block from the old host (`/etc/nginx/sites-available/`),
keeping the `proxy_pass http://mtgban;` upstream from `deploy/README.md`. Issue
certificates **before** the DNS cutover using the DNS-01 challenge, so the new
host has a valid certificate while traffic still points at the old one:

```bash
sudo certbot certonly --dns-<provider> -d mtgban.com -d www.mtgban.com
```

HTTP-01 cannot work here — it validates against whichever host DNS currently
points at, which is still the old one.

## 5. Point the app at the databases over the VPC

Now that the app is in SFO3, use the databases' **private** addresses in each
`config.json` (`sql_config`, `user_state_config`, `observability_config`,
`new_newspaper_sql_config`). Public IPs would route out and back for no reason.

Keep `sslmode=require`. Then take the moment to fix the pool sizes, which were
tuned around a slow link:

```json
"max_open_conns": 5,
"max_idle_conns": 5,
"conn_max_lifetime_seconds": 1800
```

Idle equal to open, always: a closed connection now costs microseconds to
replace rather than a quarter-second, but there is still no reason to churn.

## 6. Verify before any traffic moves

Test the new host directly, bypassing DNS:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/healthz     # on the host
curl -s --resolve mtgban.com:443:<new-ip> -o /dev/null \
     -w 'ttfb=%{time_starttransfer}\n' https://mtgban.com/search?chart=ban:13456&sig=<sig>
```

The chart page is the measurement that says whether the move worked. Before it,
server-side time was **~550 ms** (TTFB minus TLS minus one RTT). Co-located it
should land in the tens of milliseconds. If it does not, the databases are not
being reached over the VPC — check step 5 before going further.

Also confirm: `/healthz` 200, a search returns results, the newspaper renders
(it is a *different* database, in the same region), and the offline endpoints
answer if that deployment serves them.

## 7. Cut over

1. Point GitHub Actions at the new host, or the next tag deploys to the old one:
   ```bash
   gh secret set DROPLET_HOST     --body "<new-ip>"
   gh secret set DROPLET_SSH_KEY  < ~/.ssh/gh_deploy      # the new host's key
   ```
2. Update the DNS A records to the new IP.
3. Watch both hosts' logs until the old one goes quiet:
   ```bash
   journalctl -u 'mtgban@*' -f
   ```
4. Leave the old droplet **running but unreferenced** for at least 24h. It is
   the rollback.

## Rollback

Point DNS back at the old IP and restore `DROPLET_HOST`. That is the whole
procedure, which is why the old host stays up and why the TTL comes down first.

Nothing on the new host is authoritative — no state is written there that the
old host would miss — so a rollback loses nothing but the time.

## Decommission

After a day of clean logs and healthy charts: snapshot the old droplet, then
destroy it. Remove its IP from any allowlists, including the database's
`pg_hba.conf` or firewall rules if they name it.

---

## Appendix A: the other six deployments

Magic is the only droplet. Every other deployment is an App Platform app driven
by `doctl` — `beta`, `fleshandblood`, `lorcana`, `onepiece`, `riftbound`,
`yugioh` — so the same question applies six more times, and they are the easier
half: an App Platform app carries no state at all.

Find out where each one actually is before moving anything:

```bash
doctl apps list --format ID,Spec.Name,DefaultIngress
doctl apps spec get <app-id> | grep -i '^region:'
```

App Platform fixes region at creation too, so a move is: fetch the spec, edit
`region:` to `sfo3`, create a **new** app from it, verify it, move the domain,
delete the old one.

```bash
doctl apps spec get <app-id> > /tmp/app.yaml
# edit region: in /tmp/app.yaml
doctl apps create --spec /tmp/app.yaml --wait
```

Each one needs its own `config.json` equivalent — these apps read their config
from the app spec's env vars, so the database host swap from step 5 has to
happen in the spec, not in a file on disk.

An app already in SFO3 is fine as it is; check before assuming.

## Appendix B: if the databases move instead

More work, and it is the direction with the data in it. Two options:

**Snapshot and rebuild.** Power off, snapshot, transfer the snapshot to NYC1,
build a droplet from it, repoint every `config.json`. Downtime is the transfer,
which at this table's size is not minutes.

**Replicate and promote.** Stand up a Postgres in NYC1, set up streaming
replication from SFO3, let it catch up, then stop writes, promote the replica,
and repoint the configs. Minutes of downtime instead of hours, at the cost of a
more delicate procedure. Remember the *three* databases (`card_prices`,
`userstate`, `observability`) plus the separate newspaper host — each needs the
same treatment, and the ingest that runs beside the archive needs to move with
it or reach it across the country instead.
