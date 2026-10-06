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
| `desired-state-protocol-5.json` | `v0.12.0` (same `DesiredState` as `v0.11.0`, the last tag a protocol-5 agent pinned, omnuv-provider 83646ed) | 5 |
| `desired-state-protocol-6.json` | `v0.13.2` | 6 |

Each was read out of `git show <tag>:src/lib.rs` and hand-written, keys included
because that release names them, not because the current one does.

## `v0.27/` and `v0.28/`: every message, both directions (v0.28.0)

The files above are desired state only, Core to agent. These two directories
hold every message v0.28.0 touched, in the direction each is written:

| directory | what it holds | written from |
|---|---|---|
| `v0.27/` | what v0.27 peers send today | the in-crate types (`desired-state`, `inventory`, `status`, `heartbeat`) as the **v0.27.0 crate itself** serializes them, plus Core's `"built": true` on a worker; the rest as their writers write them: the handshake from the agent's `json!` (keys sorted), its answer and the scrub exchange from Core's structs, the scrub report from `onv-scrub.c`'s `fprintf` |
| `v0.28/` | the same messages with every v0.28.0 field present, and `names.json`, the headers, routes and capabilities as Core and the agent spell them | hand-edited from `v0.27/`; `settings_hash` computed outside Rust |

`tests/v0_28.rs` reads both: every `v0.27/` payload reads and writes back
unchanged; the v0.27.0 crate, a dev-dependency pinned to the released tag,
reads every `v0.28/` payload as it read the `v0.27/` one; and every file in
either directory is claimed by a test.
