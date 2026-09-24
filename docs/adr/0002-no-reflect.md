# ADR-0002: No reflect

**Status:** Accepted
**Date:** 2026-09-24
**Deciders:** Vittorio Giovara
**Change:** PR #573

## Context

`reflect` answers at run time what the types would otherwise answer at
compile time, and it fails at run time too: a wrong guess is a panic in a
request, not a build error.

The one use outside the tests shows the cost. The Cardmarket-id index
(`internal/mkmidparser`) compared the sellers it was built from with
`reflect.ValueOf(...).Pointer()`, because `==` on two `mtgban.Seller`
interfaces panics when the value inside is a struct holding a map. The
reflection kept the panic away. It also hid which concrete type the code
relied on, and kept the replaced sellers alive. #571 replaced it with a type
assertion to `*mtgban.BaseSeller`, the type every loaded scraper is, and
weak pointers. The result is shorter, exact, and checked by the compiler.

The rest were tests: 18 calls to `reflect.DeepEqual` in 6 files. Each one
compared a slice, a map or a struct whose type the test already knew.

Go no longer needs reflection for any of that. Generics, type switches and
assertions, and the `slices`, `maps` and `cmp` packages cover what it is
usually reached for.

## Decision

1. **No Go file in this module imports `reflect`,** tests included.
2. **CI enforces it.** `.revive.toml` turns on revive's `imports-blocklist`
   rule for `reflect`. The `style` job runs revive with `-set_exit_status`,
   so an import fails the PR.
3. **Tests compare with the type's own equality.** Use `slices.Equal` or
   `maps.Equal` where the elements are comparable. Where they are not, use
   `slices.EqualFunc` or `maps.EqualFunc` with a comparison written for the
   type. A comparison that names every field of a type gets an unkeyed
   literal of that type beside it, which stops compiling when the type gains
   a field (`internal/offline/format_test.go`). Where every field of a type
   is exported and encoded, comparing the JSON encodings is the same check.
   A question about a type's shape rather than its values goes to
   `go/types`, which reads it the way a linter does.
4. **A library whose job is reflection is the same thing one import away.**
   That covers deep copy, deep equality and struct mapping. If one is
   proposed, add it to the blocklist rather than importing it.
5. **Reflection the standard library does on our behalf is fine:**
   `encoding/json`, `html/template`, `fmt`, `errors.As`. The rule is about the
   code written here.

## Options considered

### A: Convention only, in AGENTS.md

Nothing stops an import except a reviewer noticing it. **Rejected.**

### B: revive's imports-blocklist (chosen)

No new tooling: CI already runs the pinned revive on every PR and on
`master`. The failure names the file and the import.

### C: A Go test that walks the module's imports

It would run under `go test`, but it does what the linter already does, in
code that has to be maintained itself. **Rejected.**

### D: depguard, through golangci-lint

The repo does not use golangci-lint, and adding a linter for one import is
more than the rule needs. **Rejected.**

## Consequences

- An exception needs a new ADR that supersedes this one, not a
  `revive:disable` comment.
- A test's comparison can be looser than `reflect.DeepEqual` was:
  `slices.Equal` and `maps.Equal` treat a nil slice or map as equal to an
  empty one. Where that difference matters, test it directly.
- go-mtgban follows it too: mtgban/go-mtgban#765 takes its tests off
  `reflect` and adds the same rule to its `.revive.toml`.
