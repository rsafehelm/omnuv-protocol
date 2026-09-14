# Golden payloads

What a **released** agent is entitled to receive, written from that release's
own declarations rather than generated from the current types. A golden file
that regenerates itself asserts nothing: it would follow a rename rather than
refuse it, which is the failure the whole directory exists to prevent.

One file per released protocol version still inside the supported range. When
`MINIMUM_PROTOCOL_VERSION` rises, the file for a withdrawn version is deleted in
the same change — the floor moving is what makes it stop being a promise.

| file | tag | protocol |
|---|---|---|
| `desired-state-protocol-5.json` | `v0.12.0` | 5 |
| `desired-state-protocol-6.json` | `v0.13.2` | 6 |

Each was read out of `git show <tag>:src/lib.rs` and hand-written, keys included
because that release names them, not because the current one does.
