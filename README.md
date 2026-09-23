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
omnuv-protocol = { git = "https://github.com/rsafehelm/omnuv-protocol", tag = "v0.21.0" }
```

The **tag** is the release a consumer pins (`v0.21.0` today); the crate's own
`version` in Cargo.toml moves separately and more slowly (`0.1.16` at
`v0.21.0`). Pin the tag. `PROTOCOL_VERSION` is a third number, the wire's.

## Versioning

`PROTOCOL_VERSION` is bumped on any breaking change to the message shapes.
Additive fields carrying `#[serde(default)]` do not bump it, because an older
peer ignores them and a newer one fills them in.

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
