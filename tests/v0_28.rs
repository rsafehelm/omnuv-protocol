//! **v0.28.0: the control plane typed, and every addition proved additive.**
//!
//! Two directories of golden payloads, both hand-written or produced by the
//! released code, never by the types under test:
//!
//! ```text
//! tests/golden/v0.27/   what v0.27 peers send today: the in-crate types as
//!                       the v0.27.0 crate itself serializes them, and the
//!                       out-of-crate messages as Core's structs and the
//!                       agent's json! write them (handshake, its answer,
//!                       leave, a refusal, the scrub exchange, the scrub
//!                       program's own report)
//! tests/golden/v0.28/   the same messages with every v0.28.0 field present,
//!                       and the header, route and capability names
//! ```
//!
//! What is proved, both directions:
//!
//! - every v0.27 payload reads into the v0.28 types and writes back as the
//!   same JSON, so a v0.28 peer leaves a v0.27 one nothing new to read;
//! - the v0.27.0 crate itself (a dev-dependency pinned to the released tag)
//!   reads every v0.28 payload, and writes what it wrote before;
//! - every v0.28 payload round-trips and carries each new field.
//!
//! "The same JSON" is equality of `serde_json::Value`: key order is not part
//! of JSON's meaning, and the agent's `json!` writes keys sorted while a
//! struct writes them in declaration order, so the two never shared an order.

use omnuv_protocol as now;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const V027: &[&str] = &[
    "desired-state.json",
    "handshake-accepted-plain.json",
    "handshake-accepted.json",
    "handshake.json",
    "heartbeat.json",
    "inventory.json",
    "leave.json",
    "refusal.json",
    "scrub-guest-report.json",
    "scrubs-answer.json",
    "scrubs-report.json",
    "scrubs-wants.json",
    "status.json",
];

const V028: &[&str] = &[
    "desired-state.json",
    "handshake-accepted.json",
    "handshake.json",
    "heartbeat.json",
    "inventory.json",
    "names.json",
    "refusal.json",
    "status.json",
];

fn golden(release: &str, name: &str) -> String {
    let path = format!("{}/tests/golden/{release}/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn value(body: &str) -> Value {
    serde_json::from_str(body).expect("a golden file is JSON")
}

/// Parses `body` as `T` and writes it back, asserting the JSON is unchanged.
fn same<T: Serialize + DeserializeOwned>(release: &str, name: &str) -> T {
    let body = golden(release, name);
    let typed: T = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{release}/{name} does not read: {e}"));
    let written = serde_json::to_value(&typed).expect("serialize");
    assert_eq!(written, value(&body), "{release}/{name} did not write back as it was read");
    typed
}

/// **No golden goes unchecked, and none is missing.** A file nobody reads
/// asserts nothing; a list naming a file that is gone tests less than it says.
#[test]
fn every_golden_file_is_claimed() {
    for (release, claimed) in [("v0.27", V027), ("v0.28", V028)] {
        let dir = format!("{}/tests/golden/{release}", env!("CARGO_MANIFEST_DIR"));
        let mut found: Vec<String> = std::fs::read_dir(&dir)
            .expect("golden directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        let mut claimed: Vec<String> = claimed.iter().map(|s| s.to_string()).collect();
        claimed.sort();
        assert_eq!(found, claimed, "tests/golden/{release} and this file's list disagree");
    }
}

/// **A v0.27 peer's payloads read unchanged, and write back as v0.27 bytes.**
/// With every new field absent, the v0.28 types write exactly what a v0.27
/// peer wrote, and each new field reads as "not said".
#[test]
fn v027_payloads_read_and_write_back_unchanged() {
    let d: now::DesiredState = same("v0.27", "desired-state.json");
    assert_eq!(d.agent_settings, None);
    assert_eq!(d.images[0].os_family, None);
    assert!(d.inference_workers[0].built, "Core's `built` beside the protocol's fields was not read");

    let i: now::InventoryReport = same("v0.27", "inventory.json");
    assert_eq!(i.held_images[0].node, None);

    let s: now::StatusReport = same("v0.27", "status.json");
    assert_eq!((s.instances[0].outcome, s.instances[0].residue.len()), (None, 0));
    assert_eq!((s.workers[0].outcome, s.workers[0].residue.len()), (None, 0));
    assert_eq!(s.checks[0].kind, now::CheckKind::Connectivity);

    let h: now::Heartbeat = same("v0.27", "heartbeat.json");
    assert_eq!((h.settings_hash, h.components.len(), h.workloadd_sha256), (None, 0, None));

    let hs: now::Handshake = same("v0.27", "handshake.json");
    assert!(!hs.refusal_codes);
    assert_eq!(hs.drivers.compute, ["proxmox"]);
    let a: now::HandshakeAccepted = same("v0.27", "handshake-accepted.json");
    assert_eq!(a.serves(now::ROUTE_SCRUBS), None, "a Core that predates `served` said something");
    assert_eq!(a.session.as_ref().map(|s| s.expose()), Some("8d1e2f3a-4b5c-4d6e-8f70-819a2b3c4d5e"));
    assert!(a.restore_mode);
    let plain: now::HandshakeAccepted = same("v0.27", "handshake-accepted-plain.json");
    assert_eq!((plain.session, plain.restore_mode, plain.report_interval_secs), (None, false, Some(30)));

    let l: now::Leave = same("v0.27", "leave.json");
    assert_eq!(l.reason.as_deref(), Some("host retired"));
    let r: now::RefusalBody = same("v0.27", "refusal.json");
    assert_eq!(r.code, None);

    let w: now::ScrubWants = same("v0.27", "scrubs-wants.json");
    assert_eq!((w.scrubs[0].attempt, w.scrubs[0].image.as_str()), (1, "scrub-nvidia"));
    let said: now::ScrubReport = same("v0.27", "scrubs-report.json");
    assert_eq!(said.scrubs[0].outcome, now::ScrubOutcome::Failed);
    let answer: now::ScrubAnswer = same("v0.27", "scrubs-answer.json");
    assert_eq!(answer.results[1].result, now::SCRUB_RESULT_HELD);
    let guest: now::ScrubGuestReport = same("v0.27", "scrub-guest-report.json");
    assert_eq!((guest.status.as_str(), guest.covered_mib, guest.verified), ("clean", 24320, true));
    assert_eq!(guest.persistent["serial"], "1324021012345");
}

/// **The released crate agrees with these goldens.** Each in-crate payload
/// under v0.27/ is read and written by the v0.27.0 crate itself, so the
/// goldens are that release's bytes and not a guess at them. `built` is the
/// one key it does not carry: Core wrote it beside the protocol's fields,
/// outside the v0.27 type.
#[test]
fn the_v027_crate_writes_its_goldens_as_they_are() {
    fn released<T: Serialize + DeserializeOwned>(name: &str) -> Value {
        let typed: T = serde_json::from_str(&golden("v0.27", name)).expect("v0.27.0 reads its own payload");
        serde_json::to_value(&typed).expect("serialize")
    }
    let mut desired = value(&golden("v0.27", "desired-state.json"));
    desired["inference_workers"][0].as_object_mut().unwrap().remove("built");
    assert_eq!(released::<v027::DesiredState>("desired-state.json"), desired);
    assert_eq!(released::<v027::InventoryReport>("inventory.json"), value(&golden("v0.27", "inventory.json")));
    assert_eq!(released::<v027::StatusReport>("status.json"), value(&golden("v0.27", "status.json")));
    assert_eq!(released::<v027::Heartbeat>("heartbeat.json"), value(&golden("v0.27", "heartbeat.json")));
}

/// **A v0.27.0 peer reads every v0.28 payload, and sees what it saw before.**
/// The interoperability test: the released crate, pinned by its tag, parses
/// each message a v0.28 peer writes with every new field present, and what it
/// makes of it equals what it makes of the v0.27 message.
#[test]
fn a_v027_peer_reads_every_v028_payload() {
    fn both<T: DeserializeOwned + PartialEq + std::fmt::Debug>(name: &str) {
        let new: T = serde_json::from_str(&golden("v0.28", name))
            .unwrap_or_else(|e| panic!("v0.27.0 refuses v0.28/{name}: {e}"));
        let old: T = serde_json::from_str(&golden("v0.27", name)).expect("v0.27.0 reads v0.27");
        assert_eq!(new, old, "v0.27.0 read v0.28/{name} as something other than v0.27/{name}");
    }
    both::<v027::DesiredState>("desired-state.json");
    both::<v027::InventoryReport>("inventory.json");
    both::<v027::StatusReport>("status.json");
    both::<v027::Heartbeat>("heartbeat.json");

    // Out of crate in v0.27: the readers were Core's structs and the agent's
    // field lookups, neither of which refuses an unknown key. Their keys are
    // all still here, with the values they had.
    for name in ["handshake.json", "handshake-accepted.json"] {
        let (old, new) = (value(&golden("v0.27", name)), value(&golden("v0.28", name)));
        for (k, v) in old.as_object().unwrap() {
            assert_eq!(new.get(k), Some(v), "v0.28/{name} changed `{k}`");
        }
    }
}

/// **Every v0.28 payload round-trips and carries each new field.**
#[test]
fn v028_payloads_carry_every_new_field() {
    let d: now::DesiredState = same("v0.28", "desired-state.json");
    let settings = d.agent_settings.clone().expect("agent_settings");
    assert_eq!(settings.heartbeat_interval_secs, Some(30));
    assert_eq!(settings.environment.as_deref(), Some("onv-prod"));
    assert_eq!(d.images[0].os_family, Some(now::OsFamily::Windows));
    assert!(d.inference_workers[0].built);

    let i: now::InventoryReport = same("v0.28", "inventory.json");
    assert_eq!(i.held_images[0].node.as_deref(), Some("pluto"));

    let s: now::StatusReport = same("v0.28", "status.json");
    assert_eq!(s.instances[0].outcome, Some(now::StatusOutcome::DeletedWithResidue));
    assert_eq!(s.instances[0].residue, ["local-lvm:vm-9101-disk-0", "local-lvm:vm-9101-cloudinit"]);
    assert_eq!(s.workers[0].outcome, Some(now::StatusOutcome::Lost));

    let h: now::Heartbeat = same("v0.28", "heartbeat.json");
    assert_eq!(h.components.len(), 3);
    assert_eq!(h.components[1].config_hash, None);
    assert_eq!(h.workloadd_sha256.as_deref().map(str::len), Some(64));

    let hs: now::Handshake = same("v0.28", "handshake.json");
    assert!(hs.refusal_codes);
    let a: now::HandshakeAccepted = same("v0.28", "handshake-accepted.json");
    assert_eq!(a.serves(now::ROUTE_SCRUBS), Some(true));
    assert_eq!(a.serves("/provider/v1/volumes"), Some(false));

    let r: now::RefusalBody = same("v0.28", "refusal.json");
    assert_eq!(r.code, Some(now::RefusalCode::AdmissionPending));
}

/// **With every new field cleared, a v0.28 message is the v0.27 one.** The
/// other half of "absent means absent": nothing a v0.28 peer writes for a
/// field it does not set reaches a v0.27 reader.
#[test]
fn new_fields_cleared_write_the_v027_bytes() {
    fn cleared<T: Serialize + DeserializeOwned>(name: &str, clear: impl FnOnce(&mut T)) {
        let mut typed: T = serde_json::from_str(&golden("v0.28", name)).expect("v0.28 reads");
        clear(&mut typed);
        assert_eq!(serde_json::to_value(&typed).unwrap(), value(&golden("v0.27", name)), "{name}");
    }
    cleared::<now::DesiredState>("desired-state.json", |d| {
        d.agent_settings = None;
        d.images[0].os_family = None;
    });
    cleared::<now::InventoryReport>("inventory.json", |i| i.held_images[0].node = None);
    cleared::<now::StatusReport>("status.json", |s| {
        (s.instances[0].outcome, s.instances[0].residue) = (None, Vec::new());
        s.workers[0].outcome = None;
    });
    cleared::<now::Heartbeat>("heartbeat.json", |h| {
        (h.settings_hash, h.workloadd_sha256) = (None, None);
        h.components.clear();
    });
    cleared::<now::Handshake>("handshake.json", |h| h.refusal_codes = false);
    cleared::<now::HandshakeAccepted>("handshake-accepted.json", |a| a.served.clear());

    let worker_not_built = {
        let mut d: now::DesiredState = serde_json::from_str(&golden("v0.27", "desired-state.json")).unwrap();
        d.inference_workers[0].built = false;
        serde_json::to_value(&d).unwrap()
    };
    assert!(
        worker_not_built["inference_workers"][0].get("built").is_none(),
        "a worker not built wrote the key, which no Core ever sent"
    );
}

/// **The names Core and the agent spell by hand today, held to one copy.**
/// The first hermetic test the session, lease, restore and report-interval
/// headers have had.
#[test]
fn the_names_are_the_ones_on_the_wire() {
    let names = value(&golden("v0.28", "names.json"));
    let h = &names["headers"];
    assert_eq!(now::HEADER_SESSION, h["session"]);
    assert_eq!(now::HEADER_RUN_LEASE, h["run_lease"]);
    assert_eq!(now::HEADER_RESTORE, h["restore"]);
    assert_eq!(now::HEADER_RESTORE_DETECTED, h["restore_detected"]);
    assert_eq!(now::HEADER_REPORT_INTERVAL, h["report_interval"]);
    let r = &names["routes"];
    assert_eq!(now::ROUTE_HANDSHAKE, r["handshake"]);
    assert_eq!(now::ROUTE_INVENTORY, r["inventory"]);
    assert_eq!(now::ROUTE_HEARTBEAT, r["heartbeat"]);
    assert_eq!(now::ROUTE_SESSION, r["session"]);
    assert_eq!(now::ROUTE_DESIRED_STATE, r["desired_state"]);
    assert_eq!(now::ROUTE_STATUS, r["status"]);
    assert_eq!(now::ROUTE_TUNNEL, r["tunnel"]);
    assert_eq!(now::ROUTE_SCRUBS, r["scrubs"]);
    assert_eq!(now::ROUTE_LEAVE, r["leave"]);
    assert_eq!(now::ROUTE_IMAGE_ARTEFACT, r["image_artefact"]);
    assert_eq!(now::QUERY_KNOWN, names["query_known"]);
    assert_eq!(now::desired_state_path(41), "/provider/v1/desired-state?known=41");
    assert_eq!(now::image_artefact_path("ubuntu-2604"), "/provider/v1/images/ubuntu-2604/artefact");
    assert_eq!(
        now::ROUTE_IMAGE_ARTEFACT.replace("{id}", "ubuntu-2604"),
        now::image_artefact_path("ubuntu-2604"),
        "the route Core declares and the path the agent fetches disagree"
    );
    let caps: Vec<&str> = names["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert_eq!(now::CAPABILITIES, caps.as_slice());
    // The agent advertises the same eight, in its own order.
    let advertised = value(&golden("v0.27", "handshake.json"));
    let mut agent: Vec<&str> = advertised["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    let mut known = now::CAPABILITIES.to_vec();
    agent.sort();
    known.sort();
    assert_eq!(agent, known, "the agent's capabilities and the contract's differ");
}

/// **One settings hash, computed alike on both sides.** The values are
/// computed outside Rust (FNV-1a 64 over Python's compact `json.dumps`) and
/// written here, so the function is held to a definition and not to itself.
#[test]
fn the_settings_hash_is_fnv1a_over_the_compact_json() {
    let d: now::DesiredState = serde_json::from_str(&golden("v0.28", "desired-state.json")).unwrap();
    let h: now::Heartbeat = serde_json::from_str(&golden("v0.28", "heartbeat.json")).unwrap();
    let sent = d.agent_settings.expect("settings");
    assert_eq!(sent.hash(), "44bdab13b1d22884");
    assert_eq!(h.settings_hash.as_deref(), Some(sent.hash().as_str()), "an agent that applied all of it");

    assert_eq!(now::AgentSettings::default().hash(), "08f44b07b5901a25", "nothing set hashes `{{}}`");
    let label = |e: &str| now::AgentSettings { environment: Some(e.into()), ..Default::default() };
    assert_eq!(label("onv-test").hash(), "a0aead9e00cef5c4");
    assert_eq!(label("a\"b\nc").hash(), "860a5edb91204b2e", "a label is escaped as JSON escapes it");
    let two = now::AgentSettings { heartbeat_interval_secs: Some(15), ..label("onv-test") };
    assert_eq!(two.hash(), "85e85c07e8c3167b");

    // A clamped value is a different hash: what the agent ran, not what it
    // was sent.
    let clamped = now::AgentSettings { tunnel_ping_secs: Some(20), ..sent.clone() };
    let over = now::AgentSettings { tunnel_ping_secs: Some(90), ..sent };
    assert_ne!(clamped.hash(), over.hash());
}

/// **One MAC derivation**, pinned to bytes the agent already ships: the
/// egress MAC in omnuv-provider's `tests/linux/full.network.yaml`, for that
/// fixture's machine id. The marketplace MAC was computed outside Rust.
#[test]
fn the_mac_is_the_one_both_sides_derive() {
    let id = "3f2a9c1b-04de-4a6f-9b1e-7c5d2e8f9a10";
    assert_eq!(now::egress_mac(id), "02:3C:EE:ED:56:5B");
    assert_eq!(now::marketplace_mac(id), "02:C9:95:EA:0C:84");
    assert_eq!(now::marketplace_mac("55555555-5555-5555-5555-555555555555"), "02:4E:C4:85:26:C1");
    assert_ne!(now::marketplace_mac(id), now::egress_mac(id), "a machine's two interfaces collided");
    assert_ne!(now::marketplace_mac(id), now::marketplace_mac("55555555-5555-5555-5555-555555555555"));
    for mac in [now::marketplace_mac(id), now::egress_mac(id)] {
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0b11, 0b10, "{mac} is not locally administered and unicast");
    }
}

/// **The meaning of an answer, per route.** Without a code, exactly the table
/// every agent has used since sessions; with one, the code decides, and an
/// admission refusal is never final on any route or status.
#[test]
fn an_answer_means_what_the_table_says() {
    use now::AnswerMeans::*;
    use now::RefusalCode as C;
    let hs = now::ROUTE_HANDSHAKE;
    let view = now::ROUTE_DESIRED_STATE;
    for (route, status, want) in [
        (hs, 401, Final),
        (hs, 426, Final),
        (hs, 409, Other),
        (hs, 403, Refused),
        (hs, 503, Unavailable),
        (view, 401, Refused),
        (view, 403, Refused),
        (view, 409, Final),
        (view, 426, Renegotiate),
        (view, 429, Unavailable),
        (view, 500, Unavailable),
        (view, 503, Unavailable),
        (view, 404, Other),
        (view, 400, Other),
    ] {
        assert_eq!(now::answer_means(route, status, None), want, "{route} {status}");
    }
    for route in [hs, view, now::ROUTE_HEARTBEAT, now::ROUTE_SCRUBS, now::ROUTE_TUNNEL] {
        for code in [C::AdmissionPending, C::AdmissionClosed, C::AdmissionFull] {
            for status in [401, 403, 409, 426] {
                assert_eq!(now::answer_means(route, status, Some(code)), Wait, "{route} {status} {code:?}");
            }
        }
        assert_eq!(now::answer_means(route, 503, Some(C::Retry)), Unavailable);
        assert_eq!(now::answer_means(route, 409, Some(C::Retry)), Unavailable, "retry is never final");
    }
    // The nearest things that must not read as admission: a 403 with no code
    // or another code is a refusal, as it always was.
    assert_eq!(now::answer_means(view, 403, None), Refused);
    assert_eq!(now::answer_means(view, 403, Some(C::CutOff)), Refused);
    assert_eq!(now::answer_means(view, 403, Some(C::Unknown)), Refused);
    assert_eq!(now::answer_means(hs, 409, Some(C::Held)), Wait);
    assert_eq!(now::answer_means(view, 409, Some(C::Superseded)), Final);
    // A query on the route is not part of it: the caller passes the path.
    assert_eq!(now::answer_means(&now::desired_state_path(3), 409, None), Final);
}

/// **A refusal body reads in every shape Core has written.** A code from a
/// person's console, or a newer Core, reads as `Unknown` and the body still
/// reads; a body with no code writes none.
#[test]
fn a_refusal_body_reads_every_shape() {
    let console: now::RefusalBody =
        serde_json::from_str(r#"{"error":"criteria unmet","code":"criteria_unmet","criteria":[]}"#).unwrap();
    assert_eq!(console.code, Some(now::RefusalCode::Unknown));
    let field: now::RefusalBody = serde_json::from_str(r#"{"error":"bad","code":"retry","field":"name"}"#).unwrap();
    assert_eq!((field.code, field.field.as_deref()), (Some(now::RefusalCode::Retry), Some("name")));
    let plain = now::RefusalBody { error: "unauthorized".into(), code: None, field: None };
    assert_eq!(serde_json::to_string(&plain).unwrap(), r#"{"error":"unauthorized"}"#);
    for (code, word) in [
        (now::RefusalCode::AdmissionPending, "admission_pending"),
        (now::RefusalCode::AdmissionClosed, "admission_closed"),
        (now::RefusalCode::AdmissionFull, "admission_full"),
        (now::RefusalCode::WithdrawnVersion, "withdrawn_version"),
        (now::RefusalCode::UnknownSession, "unknown_session"),
    ] {
        assert_eq!(serde_json::to_value(code).unwrap(), word);
    }
}

/// **The sentinel parser, positive and negative.** Each word is read where it
/// is meant and nowhere near it.
#[test]
fn the_words_are_read_exactly() {
    use now::StatusOutcome as O;
    let read = now::StatusOutcome::from_words;
    assert_eq!(read("deleted"), Some((O::Deleted, vec![])));
    assert_eq!(
        read("deleted; residue local-lvm:vm-123-disk-0 local-lvm:vm-123-cloudinit"),
        Some((O::DeletedWithResidue, vec!["local-lvm:vm-123-disk-0".into(), "local-lvm:vm-123-cloudinit".into()]))
    );
    assert_eq!(read("not proven gone: vm 9101 was destroyed on n1").map(|o| o.0), Some(O::NotProvenGone));
    assert_eq!(
        read("this machine is no longer on its provider and was not rebuilt, since a rebuild would be a new machine").map(|o| o.0),
        Some(O::Lost)
    );
    assert_eq!(
        read("this worker is no longer on its provider and was not built again: its create ran past its horizon").map(|o| o.0),
        Some(O::Lost)
    );
    assert_eq!(read("image ubuntu-26.04-nvidia is not offered by this provider").map(|o| o.0), Some(O::ImageNotOffered));

    for near in [
        "deleted ",
        "Deleted",
        "undeleted",
        "vm 123 deleted",
        "deleted; residues local-lvm:vm-1-disk-0",
        "proven gone: vm 9101",
        "it was not proven gone: vm 9101",
        "this machine is fine",
        "the machine is no longer on its provider",
        "fixture: the image is not offered here",
        "image ubuntu-26.04 is not offered by this provider yet",
        "",
    ] {
        assert_eq!(read(near), None, "{near:?} was read as an outcome");
    }
}

/// **A newer peer's variant is one row not understood, never a whole message
/// refused** — and v0.27.0 refused the whole message, which is what the
/// change is for.
#[test]
fn a_newer_variant_is_one_row_not_the_whole_message() {
    let mut view = value(&golden("v0.27", "desired-state.json"));
    let mut second = view["instances"][0].clone();
    second["id"] = "66666666-6666-6666-6666-666666666666".into();
    second["lifecycle"] = "paused".into();
    view["instances"].as_array_mut().unwrap().push(second);
    let read: now::DesiredState = serde_json::from_value(view.clone()).expect("a view with a newer destination");
    assert_eq!(read.instances[0].intent, now::Lifecycle::Running);
    assert_eq!(read.instances[1].intent, now::Lifecycle::Unknown);
    assert!(serde_json::from_value::<v027::DesiredState>(view).is_err(), "v0.27.0 read a destination it never knew");
    for (word, want) in [("deleted", now::Lifecycle::Absent), ("absent", now::Lifecycle::Absent), ("stopped", now::Lifecycle::Stopped)] {
        assert_eq!(serde_json::from_value::<now::Lifecycle>(word.into()).unwrap(), want, "{word}");
    }
    assert_eq!(serde_json::to_value(now::Lifecycle::Absent).unwrap(), "deleted", "the wire's word moved");

    let mut report = value(&golden("v0.27", "status.json"));
    report["checks"][0]["kind"] = "throughput".into();
    report["instances"][0]["outcome"] = "drained".into();
    let read: now::StatusReport = serde_json::from_value(report.clone()).expect("a report with newer kinds");
    assert_eq!(read.checks[0].kind, now::CheckKind::Unknown);
    assert_eq!(read.instances[0].outcome, Some(now::StatusOutcome::Unknown));
    let mut old = report.clone();
    old["instances"][0].as_object_mut().unwrap().remove("outcome");
    assert!(serde_json::from_value::<v027::StatusReport>(old).is_err(), "v0.27.0 read a check kind it never knew");

    let said: now::ScrubSaid =
        serde_json::from_str(r#"{"id":"s","attempt":1,"outcome":"partial","detail":{}}"#).expect("a newer scrub outcome");
    assert_eq!(said.outcome, now::ScrubOutcome::Unknown);
}

/// **The session is redacted in `Debug`, and travels in full.**
#[test]
fn the_session_never_prints() {
    let a: now::HandshakeAccepted = serde_json::from_str(&golden("v0.27", "handshake-accepted.json")).unwrap();
    let shown = format!("{a:?}");
    assert!(!shown.contains("8d1e2f3a"), "the session printed: {shown}");
    assert_eq!(serde_json::to_value(&a).unwrap()["session"], "8d1e2f3a-4b5c-4d6e-8f70-819a2b3c4d5e");
}

/// **The crate's MAC is the one Core's and the agent's copies derived**, for
/// every id: their copies multiplied by `0x1000_0000_01b3`, which is not the
/// FNV prime, and the difference lives only above the forty bits a MAC keeps.
/// The old copy, verbatim from Core's `workers.rs` and the agent's
/// `onv-generators`, against the crate's, over ten thousand ids of both
/// shapes and both interfaces.
#[test]
fn the_mac_is_the_one_the_old_copies_derived() {
    fn old_copy(bytes: &[u8]) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        format!(
            "02:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (h >> 32) as u8, (h >> 24) as u8, (h >> 16) as u8, (h >> 8) as u8, h as u8
        )
    }
    for n in 0..10_000u32 {
        let id = if n % 2 == 0 { format!("{n:08x}-5555-4555-8555-{n:012x}") } else { format!("m-{n}") };
        assert_eq!(now::marketplace_mac(&id), old_copy(id.as_bytes()), "{id}");
        let egress = [id.as_bytes(), b"onv-egress"].concat();
        assert_eq!(now::egress_mac(&id), old_copy(&egress), "{id} egress");
    }
}
