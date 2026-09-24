//! L2 — the contract, exercised rather than described.
//!
//! Omnuv's testing plan (kept with Core, not published) asks for three things here, and
//! the boundary has had none of them since the split: round-trip, version
//! negotiation, and **the last released agent against current Core**. That last
//! one is not a nicety. On 13 September a rename of two desired-state names was
//! tagged twice and would have failed to deserialize on every provider at once
//! on deploy, because `serde(alias)` lets a *new* peer read an *old* payload and
//! does nothing for the reverse — which is the direction Core writes.
//!
//! So the tests are asymmetric on purpose, and the asymmetry follows who
//! writes:
//!
//! ```text
//! Core writes, agent reads   desired state, the catalogue — a rename here
//!                            breaks every agent that has not upgraded
//! agent writes, Core reads   inventory, status — a rename here breaks Core
//!                            for one provider at a time
//! ```
//!
//! The golden files under `tests/golden/` are payloads as a released agent
//! expects to receive them. They are **not** regenerated from the current types:
//! a golden file that updates itself asserts nothing.

use omnuv_protocol::*;

/// Every wire type survives a round trip. The cheap half, and it catches a
/// `rename` that disagrees with an `alias` on the same field — which is
/// invisible by inspection and total on the wire.
#[test]
fn wire_types_round_trip() {
    let state = DesiredState {
        protocol_version: PROTOCOL_VERSION,
        version: 41,
        unchanged: false,
        inference_workers: Vec::new(),
        images: Vec::new(),
        instances: vec![InstanceSpec {
            id: "11111111-1111-1111-1111-111111111111".into(),
            intent: Lifecycle::Running,
            name: "gpu-1".into(),
            vcpus: 4,
            memory_mib: 16384,
            disk_gib: 100,
            ..Default::default()
        }],
    };

    let json = serde_json::to_string(&state).expect("serialize");
    let back: DesiredState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.version, state.version);
    assert_eq!(back.instances.len(), 1);
    assert_eq!(back.instances[0].intent, Lifecycle::Running);
    assert_eq!(back.instances[0].name, "gpu-1");
}

/// **The rename that nearly shipped.** `intent` is the name in Rust and
/// `lifecycle` is the name on the wire, and the second is the one that matters:
/// a protocol 5 agent looks for `lifecycle` and has never heard of `intent`.
/// Asserted on the bytes, because the type says nothing about which name went
/// out.
#[test]
fn desired_state_keeps_the_names_a_released_agent_reads() {
    // Every field named, no `..Default::default()`: `DesiredState` deliberately
    // does not derive it, so a field added to the wire breaks this test and
    // somebody has to decide whether it is additive. A struct-update syntax
    // here would let a new field arrive unexamined, which is the whole thing
    // this file is for.
    let state = DesiredState {
        protocol_version: PROTOCOL_VERSION,
        version: 0,
        unchanged: false,
        inference_workers: Vec::new(),
        images: Vec::new(),
        instances: vec![InstanceSpec {
            id: "22222222-2222-2222-2222-222222222222".into(),
            intent: Lifecycle::Absent,
            name: "gpu-2".into(),
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 40,
            ..Default::default()
        }],
    };
    let json = serde_json::to_value(&state).expect("serialize");
    let instance = &json["instances"][0];

    assert!(
        instance.get("lifecycle").is_some(),
        "the wire name is `lifecycle`; an agent that has not upgraded looks for \
         nothing else. Emitted: {instance}"
    );
    assert!(
        instance.get("intent").is_none(),
        "`intent` is the name in Rust only — emitting it as well would be a \
         second name for one field, which the next peer to read the payload has \
         to guess between"
    );
    assert_eq!(
        instance["lifecycle"], "deleted",
        "the withdrawn-machine value is `deleted` on the wire. A renamed *value* \
         is worse than a renamed field: it fails only for the rows that reach \
         that state, so a teardown breaks while everything else looks healthy"
    );
}

/// Golden payloads: what a released agent is entitled to receive, parsed by the
/// current types. Backward compatibility, which `serde(alias)` and
/// `serde(default)` are for.
#[test]
fn current_types_read_every_released_payload() {
    for (name, body) in golden() {
        let parsed: Result<DesiredState, _> = serde_json::from_str(&body);
        let state = parsed.unwrap_or_else(|e| panic!("{name} no longer parses: {e}"));
        assert_eq!(
            state.instances.len(),
            1,
            "{name} carries one machine and it must survive the parse"
        );
        assert_eq!(
            state.instances[0].intent,
            Lifecycle::Running,
            "{name}'s `lifecycle: running` must still read as Running"
        );
    }
}

/// And forward: every key a released payload carries is still a key the current
/// types **emit**. This is the direction `serde(alias)` does not cover and the
/// one that takes every provider down at once.
///
/// **At every depth, from the released payload itself.** This built its own
/// spec with `..Default::default()` and compared the top level and
/// `instances[0]` only, so a key dropped from a network attachment, a GPU or a
/// worker went unseen, and every field left to the default was never looked
/// at. Now each golden is parsed into today's types and written out again,
/// and every key that carried a value must still be there. A null is skipped:
/// a missing `Option` reads as `None` on the other side.
#[test]
fn current_core_still_emits_every_key_a_released_agent_reads() {
    fn missing(old: &serde_json::Value, now: &serde_json::Value, at: &str, out: &mut Vec<String>) {
        match (old, now) {
            (serde_json::Value::Object(o), serde_json::Value::Object(n)) => {
                for (k, v) in o {
                    if v.is_null() {
                        continue;
                    }
                    match n.get(k) {
                        Some(nv) => missing(v, nv, &format!("{at}.{k}"), out),
                        None => out.push(format!("{at}.{k}")),
                    }
                }
            }
            (serde_json::Value::Array(o), serde_json::Value::Array(n)) => {
                for (i, v) in o.iter().enumerate() {
                    match n.get(i) {
                        Some(nv) => missing(v, nv, &format!("{at}[{i}]"), out),
                        None => out.push(format!("{at}[{i}]")),
                    }
                }
            }
            _ => {}
        }
    }

    for (name, body) in golden() {
        let old: serde_json::Value = serde_json::from_str(&body).expect("golden is json");
        let parsed: DesiredState =
            serde_json::from_str(&body).expect("today's types read the release");
        let now = serde_json::to_value(parsed).expect("serialize");
        let mut gone = Vec::new();
        missing(&old, &now, "", &mut gone);
        assert!(
            gone.is_empty(),
            "{name} carries {gone:?} and current Core no longer emits them — an agent on \
             that version gets a payload it cannot parse, on its next poll, all of them at once"
        );
    }
}

/// Negotiation, as the rule rather than as a description of it.
#[test]
fn the_highest_version_both_speak_is_chosen() {
    assert_eq!(
        negotiate(&[MINIMUM_PROTOCOL_VERSION, PROTOCOL_VERSION]).unwrap(),
        PROTOCOL_VERSION,
        "an agent that already speaks the newest gets it"
    );
    assert_eq!(
        negotiate(&[MINIMUM_PROTOCOL_VERSION]).unwrap(),
        MINIMUM_PROTOCOL_VERSION,
        "one a version behind keeps working — that is what a range is for"
    );
    assert_eq!(
        negotiate(&[PROTOCOL_VERSION + 4, PROTOCOL_VERSION]).unwrap(),
        PROTOCOL_VERSION,
        "a peer ahead of us is met where we are, not refused"
    );
}

/// A version below the floor is withdrawn, not translated — and the refusal
/// carries the reason, because "upgrade required" alone reads as an outage and
/// an operator who reads it as one retries instead of upgrading.
#[test]
fn a_version_below_the_floor_is_refused_with_its_reason() {
    let refused = negotiate(&[MINIMUM_PROTOCOL_VERSION - 1]).expect_err("below the floor");
    assert_eq!(refused.minimum, MINIMUM_PROTOCOL_VERSION);
    assert_eq!(refused.maximum, PROTOCOL_VERSION);
    assert_eq!(refused.reason, MINIMUM_PROTOCOL_VERSION_REASON);
    assert!(
        !refused.to_string().is_empty() && refused.to_string().contains(refused.reason),
        "the reason travels in the message an operator actually sees"
    );

    assert!(
        negotiate(&[]).is_err(),
        "a peer offering nothing is refused"
    );
    assert!(
        negotiate(&[PROTOCOL_VERSION + 1]).is_err(),
        "a peer that speaks only a version we do not is refused rather than guessed at"
    );
}

/// The floor is below the ceiling, and both are stated. A range that inverts
/// refuses every peer, and would do it at the handshake where it reads as an
/// outage.
#[test]
fn the_supported_range_is_coherent() {
    // A `const` block, so an inverted range fails the build, not only this
    // test; clippy rejects a runtime assertion on constants for that reason.
    const {
        assert!(
            MINIMUM_PROTOCOL_VERSION <= PROTOCOL_VERSION,
            "the floor has been raised above the ceiling: every peer is refused"
        )
    };
    assert!(
        !MINIMUM_PROTOCOL_VERSION_REASON.is_empty(),
        "a floor with no stated reason is a refusal an operator cannot act on"
    );
}

/// Every golden file, with its name. Panics rather than returning an empty set:
/// *no files* and *no failures* must never look the same, and a contract test
/// that silently exercises nothing is the worst of the two.
fn golden() -> Vec<(String, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("tests/golden is readable") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        out.push((name, std::fs::read_to_string(&path).expect("golden file")));
    }
    assert!(
        !out.is_empty(),
        "tests/golden holds no payloads, so the released-agent tests asserted \
         nothing while reporting success"
    );
    out
}

/// The node a machine's cards are on (v0.18.0, 22 September 2026). A payload
/// from a Core that predates it reads as no node; one that names it keeps it;
/// and a machine with no cards sends no key, so a released agent's payload is
/// byte-for-byte what it was.
#[test]
fn the_gpu_node_is_additive_in_both_directions() {
    for (name, body) in golden() {
        let state: DesiredState = serde_json::from_str(&body).expect("a released payload");
        assert_eq!(
            state.instances[0].gpu_node, None,
            "{name} predates the node and must read as none"
        );
    }

    let with = InstanceSpec {
        gpu_local_ids: vec!["0000:01:00.0".into()],
        gpu_node: Some("nuc2".into()),
        ..Default::default()
    };
    let raw = serde_json::to_value(&with).expect("serialize");
    assert_eq!(raw["gpu_node"], "nuc2");
    let back: InstanceSpec = serde_json::from_value(raw).expect("round trip");
    assert_eq!(back.gpu_node.as_deref(), Some("nuc2"));

    let without = serde_json::to_value(InstanceSpec::default()).expect("serialize");
    assert!(
        without.get("gpu_node").is_none(),
        "a machine with no cards sends a new key"
    );
}
