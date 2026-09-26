# omnuv-protocol

The versioned wire contract between **Omnuv Core** and an **Omnuv Provider
Agent**. It describes resource semantics and nothing else: no pricing, no
provider ranking, no scheduling policy. Both sides depend on this crate and
neither imports the other's source.

That separation is the point. A provider runs software that can create virtual
machines, attach their GPUs and configure their networking, and they should be
able to read it. This crate is the boundary that makes the rest of the agent
publishable.

Provider-local identifiers — hypervisor node names, PCI addresses, machine ids —
cross this boundary only as opaque strings. Core stores them so an agent can
recover state after a restart, and never parses or branches on their contents.

## Using it

```toml
[dependencies]
omnuv-protocol = { git = "https://github.com/rsafehelm/omnuv-protocol", tag = "v0.22.0" }
```

The **tag** is the release a consumer pins (`v0.22.0` today); the crate's own
`version` in Cargo.toml moves separately and more slowly (`0.2.0` at
`v0.22.0`, a minor bump because the new `Unknown` variants break an exhaustive
match). Pin the tag. `PROTOCOL_VERSION` is a third number, the wire's.

## Versioning

`PROTOCOL_VERSION` is bumped on any breaking change to the message shapes.
Additive fields carrying `#[serde(default)]` do not bump it, because an older
peer ignores them and a newer one fills them in.

A new **variant** is additive too, for the six enums a peer reports state in
(`InstanceState`, `WorkerState`, `WorkloadHealth`, `ModelStage`, `CheckResult`,
`ProbeOutcome`). Each has an `Unknown` marked `#[serde(other)]`, so an older
peer reads a variant it has never seen as `Unknown`, one row it does not
understand, and does not reject the whole report. `Unknown` is never sent:
it means "not understood", and a consumer must not conclude anything from it.
Any other enum still needs a `PROTOCOL_VERSION` bump for a new variant.

## Before a tag

This crate's own checks (build, test, clippy) run from omnuv, as
`deployment/onv check --only protocol`; nothing runs on GitHub since 26
September 2026. They build this crate alone, so the check that matters before
a tag is run by hand: both consumers built against the candidate, without
editing their manifests.

```text
P='patch."https://github.com/rsafehelm/omnuv-protocol".omnuv-protocol.path="'"$PWD"'"'
(cd ../omnuv          && cargo update -p omnuv-protocol --config "$P" &&
   SQLX_OFFLINE=true cargo test --workspace --no-run --config "$P"; git checkout Cargo.lock)
(cd ../omnuv-provider && cargo update -p omnuv-protocol --config "$P" &&
   cargo test --config "$P"; git checkout Cargo.lock)
```

**Read the output for `was not used in the crate graph`.** Cargo ignores a
`[patch]` whose version does not match the locked one, and then builds the
consumer against the old release: a check that passes having tested nothing
new. `cargo update` under the patch is what makes it apply after a version
bump; the warning is how to tell it did not. Found on 24 September 2026, the
first time the crate version moved.

An API change (a new variant, a retyped field) shows here as a consumer that
no longer compiles, and has to land in that consumer beside the tag bump.

`Cargo.lock` is not committed: this is a library, and each consumer's lock
decides the versions it builds with.

## Licence

GNU General Public License, version 3 or later, like the agent that depends on
it.

One consequence is worth stating plainly rather than leaving for somebody to
discover. Omnuv Core links this crate and is not open source. That is consistent
because the GPL's obligations attach to **conveying** a program, and Core is
never conveyed: it runs as a service on infrastructure the marketplace operates,
and nobody receives a copy of it. Running a program is not distributing it.

If Core were ever shipped to run on somebody else's hardware, that would be
distribution, and this licence would then require its source. That is a real
constraint on a future business decision, and it is written here so the decision
is made knowingly.
