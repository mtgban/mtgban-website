---
name: mtgban-device-check
description: Check mtgban.com (live, or a local -dev build) on real phone and tablet browsers - iPhone and iPad Safari in the iOS Simulator, Chrome on an Android emulator - plus a measured layout sweep of every page at every device width in the browser pane. Use when asked to test the site on iPhone, iPad, iPad mini, Android, mobile or tablet; to retest after a deploy "across platforms"; to check what Safari's status bar or Chrome's toolbar shows; to find pages that overflow, clip, pan sideways or zoom on focus; or to prove a CSS fix on the real page before it deploys. Covers which tool answers which question, the probe that turns a page into numbers, driving Safari and Android Chrome (including running JS inside Android Chrome), the false positives each tool produces, how to prove a fix before deploy, and how to show results.
---

# mtgban device check

The method lives in
[`docs/agents/device-check/README.md`](../../../docs/agents/device-check/README.md),
with `pane.md`, `ios.md`, `android.md` and the scripts beside it. Read that
file now and follow it. This repo keeps one copy of the method there rather
than a duplicate here, so every agent working in it reads the same document.
