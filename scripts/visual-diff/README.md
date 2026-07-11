# Offline shell visual parity harness

Compares the first result (header + body) of /search and /offline for one
fixture query and reports the pixel diff. Manual run, not CI.

## Setup (once)

    cd scripts/visual-diff
    bun install
    bunx playwright install chromium

## Run

Start the dev server with scrapers loaded, then:

    BASE_URL=http://localhost:8080 FIXTURE="sol ring s:C21" bun run diff

- In DevMode with SigCheck off no cookie is needed (offlineModeAllowed
  dev bypass). Against a signed instance, pass a session cookie:
  MTGBAN_COOKIE=<value of your MTGBAN cookie>.
- The fixture set must be inside the synced editions selection.
- First run syncs offline data in the throwaway browser profile; allow a
  few minutes.

## Reading the result

Pass: under 2 percent differing pixels. Expected residual diff sources:
store names render dim/unlinked offline, quick icons and treatment badges
are online-only. Inspect diff.png when over threshold: block-shaped
regions mean a real markup or layout divergence, thin text strokes are
the accepted deltas above.
