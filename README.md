# mtgban-website

The server behind [mtgban.com](https://mtgban.com) and its sister sites:
card price aggregation for Magic, Lorcana, One Piece, Yu-Gi-Oh, Riftbound,
Flesh and Blood, Pokemon, Gundam and Palworld, one Go binary per game.

```bash
go build -o mtgban-website .
./mtgban-website -dev -cfg config.json
go test ./...          # needs allprintings5.json in the repo root
```

- `AGENTS.md`: build, run, test, conventions and the invariants to keep.
- `SPECIFICATION.md`: the architecture in detail.
- `deploy/README.md`: how the droplets are set up and deployed.
- `docs/`: design notes, and `docs/adr/` for the decisions behind them.
- `todo/`: plans not yet done, `todo/refactor.md` first.

## Alert mail

Price alerts can deliver by email as well as Discord DM. The sender address
is `mail.from` in the config (`ConfigType.Mail`), defaulting to `MTGBAN
<no-reply@mtgban.com>`; a value `net/mail` cannot parse is logged and fatal
at startup outside `-dev`.

Two env vars control delivery: `RESEND_API_KEY`, the Resend API key for
sending mail, and `RESEND_WEBHOOK_SECRET`, the `whsec_...` signing secret
Resend gives a webhook endpoint (absent, the webhook answers every request
503). Production needs the key, or email stays unavailable: the email
endpoints answer 503 and email alerts stay active, failing each run on
the jobs dashboard. In `-dev` an absent key prints mail to stdout instead,
and `-alerts-send` still gates real delivery on both channels. The
`mail.from` domain must be verified in Resend; until it is, every send
fails and is retried. Register the webhook in Resend at
`https://<site>/alerts/mail-events` for the `email.bounced` and
`email.complained` events.

The ACL property `AlertChannels` is a comma list of `discord`, `email`
naming the delivery channels a tier may use; a tier with `Alerts: true` and
no `AlertChannels` property gets `discord` only, for compatibility with a
cookie signed before the property existed. To give a tier no channels at
all, set `AlertChannels` to the literal string `none`, never an empty
string: signing keeps empty values, but verification drops them, which
breaks every signed page for that tier.
