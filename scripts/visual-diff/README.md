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

- In DevMode with SigCheck off the API bypasses auth (offlineModeAllowed),
  but the client opt-in still reads the MTGBAN cookie, so pass the
  minimal unsigned one: MTGBAN_COOKIE="T2ZmbGluZU1vZGU9dHJ1ZQ%3D%3D"
  (base64 of OfflineMode=true). Against a signed instance, pass the
  value of your real MTGBAN session cookie instead.
- The fixture set must be inside the synced editions selection. In a
  fresh profile no selection means all editions; pass EDITIONS="C21"
  (comma-separated set codes) to keep the first sync small and fast.
- First run syncs offline data in the throwaway browser profile; allow a
  few minutes.
- If chromium launch times out under bun (seen on Windows), run the same
  command with node instead: node diff.js.

## Reading the result

Pass: under 2 percent differing pixels. Expected residual diff sources:
store names render dim/unlinked offline, quick icons and treatment badges
are online-only. Inspect diff.png when over threshold: block-shaped
regions mean a real markup or layout divergence, thin text strokes are
the accepted deltas above.
