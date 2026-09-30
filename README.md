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
