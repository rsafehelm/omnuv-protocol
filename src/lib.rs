//! Public, versioned contract between Omnuv Core and Omnuv Provider agents.
//!
//! This crate is PUBLIC. It must never depend on Omnuv Core or any other
//! private code, and must never carry marketplace decision logic: no pricing, no provider
//! ranking, no scheduling policy. It describes resource semantics only.
//!
//! Provider-local identifiers (Proxmox node names, PCI addresses, VMIDs) cross
//! this boundary only as opaque `local_id` strings. Core stores them so the
//! agent can correlate state after a restart; Core must never parse or branch
//! on their contents.

use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message shapes below.
/// **6 now; 5 was topology v2's completion (12 September 2026).**
///
/// Breaking twice, in two steps, and deliberately so.
///
/// **3** removed `DesiredState.gateways`, `StatusReport.gateways` and
/// `StatusReport.links`, along with the types behind them: v2 makes every buyer
/// machine an overlay peer, so there is no per-provider gateway to ask for, to
/// report on, or to measure links from.
///
/// **4** finishes the job one field down. `NetworkAttachment.gateway` named the
/// `.1` of the project network — the gateway's own address on the provider's
/// bridge — and with the gateway gone it named a machine that had been deleted.
/// Leaving it would have been worse than untidy: the driver wrote a route for
/// the whole project prefix through that address and pointed the guest's
/// `.internal` resolution at it, so a machine built under a v2 Core would have
/// resolved private names at a dead resolver and timed out, while every status
/// said `RUNNING`.
///
/// **5** finishes it: `NetworkAttachment` loses `address` and `cidr` as well,
/// so Core no longer numbers a provider's segment. That segment is per-project
/// and per-provider and has no uplink, so its addresses need only be unique
/// *within one wire* — which makes them the driver's to choose, exactly like a
/// VMID or a bridge name. Core keeps what is genuinely marketplace: the
/// network's identity, the machine's DNS name, and the MAC the guest matches
/// on.
///
/// That is the second half of Omnuv's addressing decision (called S1 in its
/// private queue).
/// The first half was Core recording the address the overlay allocated instead
/// of inventing one; this is Core stopping inventing the other one too.
///
/// The project's rules said this contract would get a deliberate version rather than
/// quiet erosion — it is a published interface in a public repository, and an
/// agent that still sends a gateway status is told so instead of being
/// silently ignored.
/// **6, as of the renames in phase 8.** `lifecycle` became `intent` and
/// `Deleted` became `Absent`. **Neither changes a byte on the wire**, and the
/// draft of this comment that said they did was the defect: it reasoned from
/// `serde(alias)`, which lets a new peer read an old payload and does nothing
/// in the direction that mattered. Core serializes desired state, so emitting
/// the new spellings would have broken every agent that had not yet upgraded —
/// the exact flag day a version range exists to avoid. The names are corrected
/// in Rust and the wire keeps its own.
///
/// So what does 6 actually assert? One thing, and it is a capability rather
/// than a format: **`ProviderView::version` is a monotonic revision, not a
/// content fingerprint.** A 5 peer may only compare it for equality — a
/// fingerprint moves sideways, so "different" is all it can mean. A 6 peer may
/// additionally compare it for *order*, and rely on a larger number being a
/// later view. Advertising 6 is how an agent says it understands that.
///
/// Additive fields have not bumped this and should not — `Observation` arrived
/// at 5 and an older agent simply sends none.
pub const PROTOCOL_VERSION: u32 = 6;

/// The oldest protocol this Core still answers. Protocol 5 agents are accepted
/// and their `lifecycle` key is the wire name itself (`intent` is the alias,
/// accepted in the other direction), so a provider upgrades
/// when it chooses rather than when Core does. Removing this is a decision about
/// abandoning running agents, and should look like one.
///
/// **Raising this floor is a hard cutoff, and that is the point.** Negotiation
/// is the right answer to a version that is merely *old*: both halves work, so
/// the provider upgrades on its own schedule. It is the wrong answer to a
/// version that cannot be safely spoken at all — a parsing flaw, a field that
/// leaks a credential, a fix the old wire format has no way to express. There
/// the compatible behaviour *is* the vulnerability, and a peer that keeps
/// speaking it keeps the hole open for as long as its operator is unhurried.
///
/// So a version below this floor is **withdrawn**, not deprecated: refused at
/// the handshake, refused on every subsequent request by an already-connected
/// agent, never translated, with no grace period to opt into. The cost is
/// deliberate and has to be paid knowingly — raising the floor takes providers
/// offline until they upgrade, which is worth it for an exploit and is not
/// worth it for a rename.
///
/// Two things must be true before raising it, and both are practical rather
/// than ceremonial:
///
/// - `providers.protocol_version` records what each peer actually *agreed*, so
///   the query "who goes dark if I raise this" can be answered first.
/// - [`MINIMUM_PROTOCOL_VERSION_REASON`] is updated in the same change, because
///   the refusal an operator reads is the only place the answer reaches them.
pub const MINIMUM_PROTOCOL_VERSION: u32 = 5;

/// Why the floor is where it is, in the words a refused provider's operator
/// reads. It travels in the refusal itself: "upgrade required" without a reason
/// is indistinguishable from an outage, and an operator who cannot tell those
/// apart retries instead of upgrading.
///
/// Kept in the same change as the floor it explains — a stale reason is worse
/// than none, because it is believed.
pub const MINIMUM_PROTOCOL_VERSION_REASON: &str = "protocol 4 and below describe the per-provider gateway that topology v2 \
     removed: an agent speaking one waits for desired state Core no longer \
     issues, and reports wiring that no longer exists";

/// What a peer advertising `offered` and this Core agree on, or why they cannot.
///
/// **The rule belongs here rather than in Core**, and until now it did not.
/// Core carried the only implementation, which meant the one thing a third
/// party writing a driver most needs to know — *will my handshake be accepted,
/// and at what version* — could be learned only by trying it against a server
/// they do not run. A contract whose acceptance rule is private is a contract
/// with a private half.
///
/// The highest version both sides speak wins, so an agent that already speaks
/// the newest gets it while one a version behind keeps working. Below the floor
/// is refused rather than translated: see [`MINIMUM_PROTOCOL_VERSION`] for why
/// a withdrawn version is a cutoff and not a deprecation.
pub fn negotiate(offered: &[u32]) -> Result<u32, VersionRefusal> {
    offered
        .iter()
        .copied()
        .filter(|v| (MINIMUM_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(v))
        .max()
        .ok_or(VersionRefusal {
            offered: offered.to_vec(),
            minimum: MINIMUM_PROTOCOL_VERSION,
            maximum: PROTOCOL_VERSION,
            reason: MINIMUM_PROTOCOL_VERSION_REASON,
        })
}

/// Why a handshake was refused, in the words its operator reads.
///
/// Carries the range rather than only the verdict: "upgrade required" with no
/// reason is indistinguishable from an outage, and an operator who reads it as
/// an outage retries instead of upgrading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRefusal {
    /// What the peer said it speaks.
    pub offered: Vec<u32>,
    pub minimum: u32,
    pub maximum: u32,
    /// Why the floor is where it is — [`MINIMUM_PROTOCOL_VERSION_REASON`].
    pub reason: &'static str,
}

impl core::fmt::Display for VersionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "no common protocol version: agent speaks {:?}, core speaks {}..={}. {}",
            self.offered, self.minimum, self.maximum, self.reason
        )
    }
}

impl std::error::Error for VersionRefusal {}

/// A string the wire needs in full and a log must never see.
///
/// **This is the class, not an instance.** A struct that carries a secret and
/// derives `Debug` prints that secret wherever anyone writes `{:?}` — a
/// `tracing` line, an `anyhow` context, a panic message — and every container
/// it nests in inherits the leak for free. `StreamCredentials` was given a
/// hand-written `Debug` for exactly that reason, and two more fields of the
/// same shape turned up immediately afterwards: the signal that the instance
/// had been fixed and the class had not. A per-struct `Debug` is the fix that
/// only works where it was applied, which is the fix that will be needed again.
///
/// So the type is the check. A field typed this way cannot be printed by
/// accident, and the next secret is redacted by being declared correctly rather
/// than by its author remembering that this file exists.
///
/// **`Display` redacts too, deliberately.** `{}` in a log is exactly as bad as
/// `{:?}` and is the easier of the two to write without thinking. The cost is
/// real and is the point: a caller that genuinely needs the characters asks for
/// them by name, and the ask is a word a reviewer sees in a diff. It is not
/// free — `format!("{key}")` compiled before and compiles now, and quietly
/// yields `<redacted>`, so a caller that wanted the value gets a useless string
/// instead of a compile error. That failure is visible in the output; the one
/// it replaces was visible only in a log file somebody else reads.
///
/// Nothing is shown at all: no length, no prefix, no first four characters.
/// A prefix is the helpful-looking variant everyone reaches for and it is a
/// real attack surface on a short secret — four characters given away are four
/// an attacker no longer guesses, and a length narrows the search on its own.
///
/// **`PartialEq` is `String`'s, and is not constant-time.** Checked against the
/// call sites rather than assumed: nothing compares one of these as an
/// authentication decision. Core persists them (`instances.overlay_setup_key`,
/// `recipe_deployments.stream_password`) and forwards the console password into
/// the viewer's own session; the agent parses one out of a guest file and
/// reports it upward. The only `==` any of them meets is a round-trip assertion
/// in a test, and desired state is compared for change by hashing its
/// *serialization*, never by `==`. A timing-safe comparison here would protect
/// nothing and would advertise a guarantee the type does not have. When one of
/// these is ever *verified* against a presented value, the verifier is where
/// constant time belongs — and it will not be in this crate, which describes
/// resource semantics and decides nothing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
// The wire is unchanged by construction: a newtype declared `transparent` is
// serialized and deserialized as the string it wraps, so a payload written
// before this type existed still parses and one written after is byte-identical
// to it. `PROTOCOL_VERSION` does not move, because nothing on the wire did.
#[serde(transparent)]
pub struct Redacted(String);

impl Redacted {
    /// The secret itself, as it has to cross the wire.
    ///
    /// Named to be greppable and to read as what it is at the call site:
    /// `key.expose()` says a secret is being taken out of its wrapper, which
    /// `key.as_str()` would not, and which a `Deref` or an `AsRef<str>` would
    /// hide entirely. That is why neither of those exists here — an invisible
    /// way out is the same defect one layer down.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl From<String> for Redacted {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Redacted {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Wire names are pinned explicitly rather than derived. `rename_all` would
/// render `K3sKubeVirt` as "k3s-kube-virt", which is not the identifier used
/// everywhere else, and these strings are persisted in `providers.runtime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeKind {
    #[serde(rename = "proxmox")]
    Proxmox,
    #[serde(rename = "k3s-kubevirt")]
    K3sKubeVirt,
    #[serde(rename = "openstack")]
    OpenStack,
}

impl RuntimeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeKind::Proxmox => "proxmox",
            RuntimeKind::K3sKubeVirt => "k3s-kubevirt",
            RuntimeKind::OpenStack => "openstack",
        }
    }
}

/// What a provider runtime can do, as normalized booleans. The scheduler reads
/// these; it never asks which runtime is underneath.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeCapabilities {
    pub vm: bool,
    pub gpu_passthrough: bool,
    pub persistent_disk: bool,
    pub portable_volume_attach: bool,
    pub cloud_init: bool,
    pub private_network: bool,
    pub inference_worker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDevice {
    /// Opaque provider-local device identity (e.g. a PCI address). Never parsed by Core.
    pub local_id: String,
    pub vendor: String,
    pub model: String,
    pub vram_mib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInventory {
    /// Opaque provider-local node identity. Never parsed by Core.
    pub local_id: String,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    #[serde(default)]
    pub gpus: Vec<GpuDevice>,
    /// What this node has already committed to guests the marketplace did not
    /// create. Advertised capacity minus this is what can honestly be sold.
    #[serde(default)]
    pub committed: Option<HostCommitment>,
}

/// What the host itself has committed, beyond anything the marketplace created.
///
/// A provider advertises capacity; the ledger books against that number and
/// nothing else. So a host advertising 64 cores while its owner runs a 60-core
/// workload of their own passes every oversell check we have, and the first
/// sign of trouble is a buyer's machine that will not start.
///
/// This is the missing half of that sum. It counts what the hypervisor has
/// handed to guests the marketplace did not create — deliberately not *what
/// those guests are*, which is the provider's business and none of ours.
/// Optional, because an older agent does not measure it and a guess would be
/// worse than an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCommitment {
    /// vCPUs configured on guests the marketplace did not create.
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    /// How many such guests there are. A count, never an identity.
    pub guests: u32,
}

/// One network adapter on a machine, and whether anything has ever crossed it.
///
/// **Holding an address is not the same as the address working.** Until this
/// existed, Core knew a machine's IP because the agent read it out of the
/// hypervisor's config and said so — `source: reported`, `observed: never` —
/// and the console's own footnote had to admit that an address being listed
/// "means the ledger holds it, not that a packet has ever crossed it".
///
/// The host can do better without touching the guest at all: its neighbour
/// table says which addresses have actually answered on each bridge. That is a
/// real observation, it costs one read per reconcile, it needs no guest agent,
/// and it keeps working when the guest's own agent is dead — which is exactly
/// when somebody wants to know whether the machine is on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterStatus {
    /// Provider-local adapter name, `net0`, `net1`. Opaque to Core.
    pub name: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    /// When the host last saw traffic from this address, if it ever has.
    /// `None` means not observed — which is information, not a failure.
    #[serde(default)]
    pub observed_at_unix: Option<u64>,
    /// How it was seen: `neighbour` for the host's own ARP/ND table. Named
    /// rather than boolean, because "we saw it" is worth much less than "we
    /// saw it *this way*" when the reading later turns out to be wrong.
    #[serde(default)]
    pub observed_by: Option<String>,
    /// Addresses the host has seen on this adapter *other than* the one above.
    ///
    /// **A field rather than a suffix on `name`, and that distinction is the
    /// whole reason it exists.** This was appended to the adapter's name —
    /// `net0 (host has also seen 10.201.0.101)` — because the contract had
    /// nowhere else to put it. The name is a key: Core stores one observation
    /// per `(provider, machine, adapter)`, so every distinct note minted a new
    /// row that the "adapters this machine no longer has" sweep could never
    /// remove, and the drawing showed adapters with impossible names.
    ///
    /// Additive and defaulted, so `PROTOCOL_VERSION` holds: an older agent
    /// sends nothing here and an older Core ignores it.
    #[serde(default)]
    pub also_seen: Vec<String>,
}

/// Everything the hypervisor will say about a machine the marketplace owns.
///
/// **Scoped to tagged machines, and that is the whole rule.** A machine
/// carrying a marketplace tag is one Core created and is answerable for, so
/// there is no reason to be shy about it: the more that comes back, the fewer
/// root-cause analyses end with somebody logging into a hypervisor. A machine
/// *without* a marketplace tag is the provider's own business and nothing about
/// it is reported at all — see `HostCommitment`, which is aggregate, opt-in and
/// audited, and is the only exception.
///
/// Every field is optional because every field comes from a call that can fail,
/// and a diagnostic that invents a value is worse than one that admits it could
/// not look.
// No `Eq`: pressure is a float, and two readings being "equal" is not a
// question worth being able to ask of a measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diagnostics {
    /// The hypervisor's own view: `running`, `paused`, `prelaunch`, `shutdown`.
    /// Distinct from the marketplace state, and the difference is the finding —
    /// `paused` reads as "up" from every angle except this one.
    #[serde(default)]
    pub run_state: Option<String>,
    /// A hypervisor lock: backup, migrate, snapshot, clone, rollback.
    ///
    /// The single most common reason a reconcile looks stuck for no visible
    /// reason: every call returns success, nothing changes, and the machine is
    /// simply not accepting work because somebody's backup is running.
    #[serde(default)]
    pub lock: Option<String>,
    /// Seconds since this machine booted. A number that keeps resetting is a
    /// boot loop, which looks identical to "slow to start" without it.
    #[serde(default)]
    pub uptime_s: Option<u64>,
    /// What the hypervisor actually gave it, so Core can compare against what
    /// it asked for. Drift is otherwise completely silent: a machine can run
    /// for months with half the memory that was sold.
    #[serde(default)]
    pub vcpus: Option<u32>,
    #[serde(default)]
    pub memory_mib: Option<u64>,
    #[serde(default)]
    pub memory_used_mib: Option<u64>,
    #[serde(default)]
    pub disk_gib: Option<u64>,
    /// Kernel pressure-stall percentages: the share of time *something* was
    /// waiting on this resource.
    ///
    /// The best answer to "why is this slow" that exists without entering the
    /// guest. Utilisation says a resource is busy; pressure says somebody is
    /// being made to wait for it, which is the thing the buyer feels.
    #[serde(default)]
    pub pressure_cpu: Option<f32>,
    #[serde(default)]
    pub pressure_io: Option<f32>,
    #[serde(default)]
    pub pressure_memory: Option<f32>,
    /// Whether the guest agent answered on this pass. Separates "the machine is
    /// down" from "the machine is up and we cannot see inside it", which are
    /// the same symptom and completely different faults.
    #[serde(default)]
    pub guest_agent: Option<bool>,
    /// PCI addresses actually attached. A GPU that was sold and did not attach
    /// is visible here rather than only to somebody reading the VM config by
    /// hand on the host.
    #[serde(default)]
    pub pci: Vec<String>,
    /// Which node of the provider's cluster it landed on.
    #[serde(default)]
    pub node: Option<String>,
    /// The most recent failed hypervisor task for this machine, with its exit
    /// status. Fetched only when the machine is not healthy: the answer to
    /// "what went wrong" usually already exists in the hypervisor's own task
    /// log, and nothing was carrying it up.
    #[serde(default)]
    pub last_task_error: Option<String>,
}

/// Where the hardware physically is. Declared by the operator, not discovered:
/// nothing on a hypervisor knows its own latitude, and IP geolocation is wrong
/// often enough to be worse than absent. Optional, because a provider may
/// decline to publish it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

/// What an agent reports upward. In Phase 1 a local discovery script produces
/// this directly; in Phase 2 the agent sends the identical shape over the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryReport {
    pub protocol_version: u32,
    pub runtime: RuntimeKind,
    pub capabilities: ComputeCapabilities,
    pub nodes: Vec<NodeInventory>,
    #[serde(default)]
    pub location: Option<GeoLocation>,
    #[serde(default)]
    pub city: Option<String>,
    /// Marketplace image ids this provider can build. The template behind
    /// each one is the agent's own configuration and is never reported.
    ///
    /// Read from the configuration, so it says what the agent was *asked* to
    /// offer. `held_images` says what is actually there; prefer it where both
    /// are present, and keep this for an agent that predates the catalogue.
    #[serde(default)]
    pub images: Vec<String>,
    /// What this provider is actually holding, with the digest of each.
    ///
    /// Additive: an agent that does not send it is one that cannot yet mirror,
    /// and Core falls back to `images` for it rather than concluding the
    /// provider holds nothing.
    #[serde(default)]
    pub held_images: Vec<HeldImage>,
}

impl InventoryReport {
    pub fn total_cpu_cores(&self) -> u32 {
        self.nodes.iter().map(|n| n.cpu_cores).sum()
    }
    pub fn total_memory_mib(&self) -> u64 {
        self.nodes.iter().map(|n| n.memory_mib).sum()
    }
    pub fn total_disk_gib(&self) -> u64 {
        self.nodes.iter().map(|n| n.disk_gib).sum()
    }
    pub fn gpu_count(&self) -> usize {
        self.nodes.iter().map(|n| n.gpus.len()).sum()
    }
}

/// What Core wants a provider to be running. The agent reconciles toward this;
/// it is never a command to execute once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    pub protocol_version: u32,
    /// A monotonic revision of everything below (since protocol 6; it was a
    /// content fingerprint before, which a 5 peer may still only compare for
    /// equality). An agent that already holds this
    /// version can say so when it asks, and Core answers with `unchanged`
    /// instead of the whole picture — Core's cost should grow with what is
    /// happening, not with how many machines exist.
    ///
    /// It does **not** mean the agent may skip a tick. Reconciliation still
    /// runs every time, because drift on the hypervisor is exactly what the
    /// loop exists to correct; what is saved is the transfer, not the work.
    #[serde(default)]
    pub version: u64,
    /// Set when the agent asked with `?known=<version>` and nothing has
    /// changed. The collections below are then empty and mean nothing: the
    /// agent reconciles against the copy it already holds.
    #[serde(default)]
    pub unchanged: bool,
    #[serde(default)]
    pub inference_workers: Vec<InferenceWorkerSpec>,
    #[serde(default)]
    pub instances: Vec<InstanceSpec>,
    /// The image catalogue: every image the marketplace publishes, with the
    /// digest that defines it and where to fetch it.
    ///
    /// **Offered, not imposed.** This is "here is what exists", never "you
    /// must hold all of this". A provider holds the subset it chooses — every
    /// image is disk, bandwidth and time, which is the provider's operational
    /// cost like keeping the hypervisor patched — and placement follows what
    /// it actually holds. Fewer images, fewer opportunities to earn; the
    /// incentive does the regulating, so nothing has to be enforced.
    #[serde(default)]
    pub images: Vec<ImageArtefact>,
    /// **How long the agent waits between looks when nothing wakes it**, in
    /// seconds: the poll that makes a lost push cost latency rather than
    /// correctness.
    ///
    /// Core's to set, never the agent's (omnuv's runtime configuration, D33:
    /// a value both sides use has one owner). Core builds two of its own
    /// clocks on it — how recent a report must be to prove anything, and how
    /// long a self-check nobody repeats stays a fact — and a poll chosen on
    /// the provider's side would quietly break both.
    ///
    /// **Sent in every answer, `unchanged` ones included**, which is why it is
    /// here and not in the handshake: a Core restarted with a new value
    /// reaches every agent at its next look, without the agent restarting. It
    /// describes the answer, not the collections above, so it means the same
    /// in an `unchanged` answer as in a full one.
    ///
    /// Additive, with no `PROTOCOL_VERSION` bump: `None` from a Core that
    /// predates it, and the agent then keeps its own default; an agent that
    /// predates it ignores it. Zero means not said, like absent: an interval
    /// of nothing is not a period an agent can keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u64>,
}

/// What an agent says with each heartbeat, `POST /provider/v1/heartbeat`.
///
/// The heartbeat carried no body until this existed, and both directions stay
/// additive: an agent that predates it sends none, which a Core reads as the
/// default here; a Core that predates it never reads the body at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// **Which tunables the agent is running**: twelve lowercase hexadecimal
    /// digits of a SHA-256 over them, as its own `check-config` prints them
    /// for the file it was given. So a deployment can prove the running agent
    /// took the file it wrote, and two agents, or a mirror and production,
    /// can be compared at a glance.
    ///
    /// A hash of the tunables alone: never of a credential, and never of
    /// where the agent is — two agents running the same timings report the
    /// same hash. `None` from an agent that does not report one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

/// One image in the marketplace catalogue: the bytes, and where to get them.
///
/// Distinct from `ImageSpec`, which travels with a machine and says what the
/// image *means* — its OS family, its first-boot generator, the account the
/// buyer gets. This says what it *is*. The agent needs only this to mirror an
/// image; the semantics reach it attached to the instance that uses them.
///
///
/// **The digest is the contract.** An image id has to mean the same machine on
/// every provider carrying it, and the only way to make that a fact rather
/// than a hope is to build the bytes once and have everybody else verify they
/// hold those bytes. A provider that built locally from "this base plus these
/// packages" would get different bytes on a different day from a moving
/// archive, and nothing could tell a legitimate difference from drift.
///
/// So a provider **mirrors** an image and never builds one. It may decline an
/// image; it may not redefine one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtefact {
    /// The marketplace id — `ubuntu-26.04`, `ubuntu-26.04-gaming`. What a
    /// buyer's machine names, and what the scheduler matches against.
    pub id: String,
    /// Lowercase hex sha256 of the artefact. Verified **before** it is
    /// imported: a half-fetched image imported as a template is a machine that
    /// boots wrong, which is worse than a machine that does not boot.
    pub sha256: String,
    /// Size in bytes, so a provider can decide whether it has room before
    /// spending an hour finding out that it does not.
    pub bytes: u64,
    /// Where to fetch it. Absolute, and reached over TLS like everything else
    /// the agent talks to.
    pub url: String,
}

/// An image a provider is actually holding, and the digest of what it holds.
///
/// Separate from `InventoryReport::images`, which is a list of ids read from
/// the agent's own configuration — a claim about *intent*, where a template
/// that was never built and one that was deleted advertise exactly the same
/// thing. This is *observed state is written only from observation* applied to
/// the one place an image id was still taken on trust, and it is the whole
/// mechanism by which drift becomes visible rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldImage {
    pub id: String,
    /// The digest of the artefact this template was imported from, as recorded
    /// at import. A value that does not match the catalogue means this
    /// provider is behind on that id — which makes it offline *for that id*,
    /// not offline.
    pub sha256: String,
}

/// One private DNS record. Naming is the marketplace's; a provider never
/// invents a buyer-visible name or address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// e.g. `gpu-2.internal`
    pub name: String,
    /// e.g. `10.200.99.11`
    pub address: String,
}

/// A buyer's virtual machine, normalized. The driver translates this into
/// runtime-native resources; nothing here names Proxmox, KubeVirt or OpenStack.
// `Debug` is written out below rather than derived: the console password's
// hash is attackable offline, and a derived `Debug` printed it through every
// `{:?}` on a spec or a desired state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InstanceSpec {
    /// How long Core is still prepared to wait for this machine, in seconds.
    ///
    /// The agent owns the fine clock — this clone is taking too long, retry,
    /// give up — and Core keeps a slower durable backstop in the database. Two
    /// clocks on purpose: the inner one is cheap and dies with the process,
    /// which is fine, and the outer one exists precisely because it can.
    ///
    /// `None` means Core did not say, and the agent should use its own
    /// default rather than waiting forever.
    #[serde(default)]
    pub budget_secs: Option<u64>,
    pub id: String,
    /// **`intent` in Rust, `lifecycle` on the wire, and that split is the
    /// point.** The old name reads as a state machine Core is driving; the
    /// field is a *target*, and the whole design rests on that difference. So
    /// the name developers read is corrected.
    ///
    /// The bytes are not, and the first attempt got this wrong in a way only
    /// production would have shown. `serde(alias)` lets a *new* peer read an
    /// *old* payload; it does nothing in the other direction, which is the one
    /// that matters here — Core serializes desired state and the agent reads
    /// it. Emitting `intent` would have meant every protocol 5 agent failing on
    /// a missing `lifecycle` field, so negotiating down to 5 was a promise Core
    /// could not keep: the handshake succeeded and the next poll did not parse.
    ///
    /// A rename is not worth a flag day. The wire keeps `lifecycle`, accepts
    /// `intent` from anyone who sends it, and every agent old and new works
    /// unchanged — which is what this repository's own rule already said: add
    /// the new name, keep the old.
    #[serde(rename = "lifecycle", alias = "intent")]
    pub intent: Lifecycle,
    pub name: String,
    /// What to build from, and everything about it that changes with the
    /// operating system. The agent maps the id to its own template.
    #[serde(default)]
    pub image: ImageSpec,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    /// Public SSH keys to inject at first boot. Never a private key.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    /// crypt(3) hash of the machine's console password, set at first boot for
    /// the image's default user. The plaintext exists only in the create
    /// response the buyer saw once. `None` on images that manage their own.
    #[serde(default)]
    pub console_password_hash: Option<String>,
    /// Which console password `console_password_hash` is: 0 is the one set at
    /// first boot, and each reset by the buyer adds one. A destination, not a
    /// command (R3): the agent sets the hash on a running machine through its
    /// guest agent when this is above the generation it last applied, so the
    /// thousandth identical send changes nothing. The plaintext of a reset
    /// exists only in the response the buyer saw once (BUYER-18 in omnuv's
    /// diagrams). Additive: an older Core sends none, which is 0.
    #[serde(default)]
    pub console_password_generation: u32,
    /// Core has seen this machine exist: a runtime id was reported for it.
    /// An agent that then finds no machine does **not** build one again — a
    /// clone from the image would put a blank disk where the buyer's was —
    /// and reports it lost instead, so the buyer decides (omnuv, 23 September
    /// 2026). Additive: an older Core sends none, which is `false`, and the
    /// agent then builds as it always did.
    #[serde(default)]
    pub built: bool,
    #[serde(default)]
    pub gpu_local_ids: Vec<String>,
    /// The provider node that holds the cards in `gpu_local_ids`, as the
    /// provider named it in its inventory. A PCI address is unique only per
    /// node, and identical hosts share them, so without this an agent could
    /// place on another node whose same slot is free and use a card Core never
    /// sold. `None` when there are no cards, or from a Core that predates it;
    /// an agent that receives `Some` places there or refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_node: Option<String>,
    /// Set when a reboot has been requested and not yet performed. Carries the
    /// request's identity so the agent can report which one it satisfied and
    /// the same reboot is never applied twice.
    #[serde(default)]
    pub reboot_token: Option<String>,
    /// The marketplace address this machine holds, and the network it belongs
    /// to. Set when the buyer's project has a private network: the machine then
    /// gets a second interface on the provider's isolated marketplace bridge
    /// instead of only a provider-local address.
    #[serde(default)]
    pub network: Option<NetworkAttachment>,
    /// Software to bring up at first boot, when the machine is a recipe
    /// deployment. The agent compiles it to what its runtime executes.
    #[serde(default)]
    pub recipe: Option<RecipeSpec>,
    /// How this machine joins the buyer's overlay, as a peer in its own right.
    ///
    /// **Topology v2.** Until 12 September 2026 the overlay client ran only on
    /// a per-provider gateway, so WireGuard terminated one VM short of the
    /// machine and every byte between them crossed the provider's bridge in
    /// clear text. The overlay made a buyer private from other tenants and from
    /// the internet, and not from their provider. Now the machine is a peer and
    /// there is no plaintext hop.
    ///
    /// `None` for a machine with no private network, and for an agent built
    /// before v2 — which simply ignores it and builds the machine it always
    /// did.
    #[serde(default)]
    pub overlay: Option<OverlayEnrolment>,
}

// Exhaustive, like `TunnelFrame`'s: no `..`, so a new field does not compile
// until somebody decides here whether it may be printed.
impl std::fmt::Debug for InstanceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let InstanceSpec {
            budget_secs,
            id,
            intent,
            name,
            image,
            vcpus,
            memory_mib,
            disk_gib,
            ssh_keys,
            console_password_hash,
            console_password_generation,
            built,
            gpu_local_ids,
            gpu_node,
            reboot_token,
            network,
            recipe,
            overlay,
        } = self;
        f.debug_struct("InstanceSpec")
            .field("budget_secs", budget_secs)
            .field("id", id)
            .field("intent", intent)
            .field("name", name)
            .field("image", image)
            .field("vcpus", vcpus)
            .field("memory_mib", memory_mib)
            .field("disk_gib", disk_gib)
            .field("ssh_keys", ssh_keys)
            .field(
                "console_password_hash",
                &console_password_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("console_password_generation", console_password_generation)
            .field("built", built)
            .field("gpu_local_ids", gpu_local_ids)
            .field("gpu_node", gpu_node)
            .field("reboot_token", reboot_token)
            .field("network", network)
            .field("recipe", recipe)
            .field("overlay", overlay)
            .finish()
    }
}

/// What a machine needs to enrol itself into its buyer's overlay.
///
/// Core mints the key, scoped to that project's group and to nothing else, one
/// per machine, and revokes it when the machine goes. The agent writes both
/// values into first-boot configuration and never stores them: a key that
/// outlives the boot it was made for is a way to enrol something nobody asked
/// for.
///
/// The address is deliberately **not** here. The overlay allocates it from a
/// range the marketplace owns and Core records what it assigned — *observed
/// state is written only from observation* — which is also why peering two of a
/// buyer's projects can never collide: every peer in the marketplace draws from
/// one space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayEnrolment {
    /// A single-use enrolment credential for this machine.
    ///
    /// [`Redacted`], and this is the field that made the type worth having: it
    /// is reached from `InstanceSpec` and from `DesiredState`, so one
    /// `{:?}` on a provider's desired state would have printed every
    /// outstanding enrolment key on that provider in a single log line.
    pub setup_key: Redacted,
    /// Where the overlay's control plane answers. Reached over the machine's
    /// own internet interface, on the provider's NAT bridge — never over the
    /// provider's LAN, which the host drops.
    pub management_url: String,
    /// What the peer calls itself, so a person can recognise it in the
    /// overlay's own listing and revoke the right one.
    #[serde(default)]
    pub hostname: Option<String>,
}

/// A recipe as the machine runtime executes it: a compose file brought up
/// at first boot, then the recipe's own finishing commands. Execution detail
/// only — which recipe this is, what it costs and why it was placed here are
/// the marketplace's business and stay there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecipeSpec {
    pub id: String,
    pub compose: String,
    /// Whether the containers reserve a GPU, so the runtime installs the
    /// container toolkit for it.
    #[serde(default)]
    pub gpu: bool,
    /// Shell, run in the compose directory once the containers are up.
    #[serde(default)]
    pub post_up: Vec<String>,
}

/// What the agent needs to know about an image to build a machine from it.
///
/// The operating system decides the first-boot mechanism, the user that gets
/// the buyer's credentials and how the buyer will log in; nothing else in the
/// contract changes between a Linux and a Windows image. The provider-local
/// template behind the id is the agent's own configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSpec {
    /// The marketplace image id, e.g. `ubuntu-26.04`.
    pub id: String,
    pub os_family: OsFamily,
    pub first_boot: FirstBoot,
    /// The account first boot creates for the buyer, e.g. `omnuv` or `Administrator`.
    pub default_user: String,
    pub auth_mode: AuthMode,
}

impl Default for ImageSpec {
    /// The image the marketplace shipped with, for messages from a Core that
    /// predates the catalog.
    fn default() -> Self {
        Self {
            id: "ubuntu-26.04".into(),
            os_family: OsFamily::Linux,
            first_boot: FirstBoot::CloudInit,
            default_user: "omnuv".into(),
            auth_mode: AuthMode::SshKey,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OsFamily {
    Linux,
    Windows,
}

/// The first-boot mechanism an image expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirstBoot {
    CloudInit,
    /// The Windows port of cloud-init.
    CloudbaseInit,
}

/// How the buyer authenticates to the machine. The console password exists
/// regardless; this is about the network login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    SshKey,
    Password,
}

/// A machine's place on a buyer's private network.
///
/// The address is the marketplace's, not the provider's — provider networks do
/// not invent buyer-visible addresses. The bridge it lands on has no uplink, so
/// the machine has no path to the provider's own network at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachment {
    /// The network itself. The driver derives the network's segment on this
    /// provider from it, in whatever its runtime calls a segment. Core does not
    /// know and must not guess: a bridge id is provider-local, the same class
    /// as a VMID.
    ///
    /// **And the addresses on that segment are the driver's too, as of
    /// protocol 5.** There is no `address` and no `cidr` here. The segment is
    /// per-project, per-provider and has no uplink, so an address on it need
    /// only be unique on that one wire — which is a provider-local fact, and
    /// Core inventing one was the last place it was numbering somebody else's
    /// network and hoping the two agreed.
    ///
    /// What a buyer sees is the overlay address, which the overlay allocates
    /// from a marketplace range and Core records; see the note on
    /// `PROTOCOL_VERSION`.
    #[serde(default)]
    pub network_id: String,
    /// The name the marketplace publishes for this machine.
    #[serde(default)]
    pub dns_name: Option<String>,
    /// The interface's hardware address. The driver assigns it and the guest
    /// matches on it: an interface cannot be found by name, because the distro
    /// chooses that and it differs by image and by slot.
    #[serde(default)]
    pub mac: String,
}

/// Normalized instance state reported upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstanceState {
    Pending,
    Provisioning,
    Running,
    Stopping,
    Stopped,
    Error,
    /// A value this build does not know: a newer peer sent a variant added
    /// after it. Read as "not understood", never as any of the above; see
    /// `unknown_variants_are_one_row_not_the_whole_report`.
    #[serde(other)]
    Unknown,
}

/// How a recipe's install went, as the guest itself reports it.
///
/// Named for the recipe rather than for first boot, because `FirstBoot` above
/// is already the *mechanism* an image uses. This is the outcome.
///
/// A recipe installs through cloud-init inside the machine, and until this
/// existed nothing outside the machine could tell a finished install from an
/// abandoned one: the VM boots, answers, and reports Running either way. Two
/// gaming machines sat like that for a day.
///
/// The provider reads it through the hypervisor's guest-agent channel — the
/// hypervisor asking the guest, not marketplace software running inside a
/// buyer's machine, which is a boundary that must not move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeProgress {
    /// cloud-init's own word for it: `running`, `done`, `error`, `disabled`,
    /// or `unknown` when the guest could not be asked.
    pub status: String,
    /// Which recipe step it was on, when the guest said so: "3/6".
    #[serde(default)]
    pub step: Option<String>,
    /// The failure, in the words the guest used. Never a summary invented
    /// here — a person debugging this needs the original.
    #[serde(default)]
    pub detail: Option<String>,
    /// The machine's own stream login, once it has minted one.
    ///
    /// **Additive and defaulted, so `PROTOCOL_VERSION` does not move.** An
    /// agent that has never heard of this field sends no such key, and Core
    /// reads that absence as *not delivered* — never as empty credentials.
    /// That is the same distinction `NodeInventory.committed` draws between
    /// unmeasured and zero, and it matters for the same reason: a blank user
    /// and password would be a login nobody can use, reported as one that
    /// works.
    #[serde(default)]
    pub stream_credentials: Option<StreamCredentials>,
}

impl RecipeProgress {
    pub fn finished(&self) -> bool {
        self.status == "done" || self.status == "disabled"
    }

    pub fn failed(&self) -> bool {
        self.status == "error"
    }
}

/// A stream's login, as the machine that minted it hands it up.
///
/// The guest generates its own: a password the marketplace chose is a password
/// the marketplace stored, and a machine the buyer owns is the only thing that
/// needs to know this one. So it is reported rather than issued, and it travels
/// on the channel the recipe's install progress already uses — one known file,
/// read with `VM.GuestAgent.FileRead`. Nothing wider is asked for, because
/// asking the guest to *run* something would need `VM.GuestAgent.Unrestricted`,
/// which is arbitrary execution inside a buyer's machine.
///
/// **`Debug` is derived again, and that is the fix rather than a regression.**
/// This type used to write its own, because a derived one prints the password,
/// `tracing` prints `Debug`, and this crate is public. That worked and did not
/// generalise: two more fields of the same shape were carrying secrets under a
/// derive, and a hand-written `Debug` per struct only ever protects the struct
/// somebody remembered. The redaction moved down to [`Redacted`], where the
/// field's own type enforces it and the derive is safe to take back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCredentials {
    pub user: String,
    /// The secret. Redacted in `Debug` and in `Display`, and nowhere else — it
    /// has to cross the wire intact to be worth delivering.
    pub password: Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceStatus {
    /// Whether trying again could plausibly work. `Some(false)` says stop: the
    /// image is not offered here, the spec is impossible, the card is gone.
    /// Without this Core must poll to learn anything, which is the chatter the
    /// version above exists to remove.
    #[serde(default)]
    pub retryable: Option<bool>,
    /// What this is waiting for, in the agent's own words: "the template to
    /// finish cloning", "a free card". "Waiting" without "for what" is not
    /// information.
    #[serde(default)]
    pub waiting_on: Option<String>,
    pub id: String,
    pub state: InstanceState,
    /// Echoes the `reboot_token` the agent acted on, so Core can close it out.
    #[serde(default)]
    pub rebooted_token: Option<String>,
    #[serde(default)]
    pub local_id: Option<String>,
    /// The provider node the machine runs on, named as the provider's inventory
    /// names it. Lets Core subtract its own guests from the node they are on:
    /// without it a host full of marketplace machines still looks big enough
    /// to take another, and only the provider-wide sum stops an oversell
    /// (CORE-42 in omnuv's diagrams). Additive: an older agent sends none, and
    /// none means "not reported", never "on no node".
    #[serde(default)]
    pub node: Option<String>,
    /// The console password generation this machine holds, as the agent last
    /// applied it (see `InstanceSpec::console_password_generation`). `None` is
    /// "not reported" — an older agent, or one that has not looked — never
    /// "has no password".
    #[serde(default)]
    pub console_password_generation: Option<u32>,
    #[serde(default)]
    pub private_ip: Option<String>,
    /// Every adapter this machine has, and whether the host has actually seen
    /// traffic from each. Additive: an older agent sends none and Core falls
    /// back to the single address below, believed but never witnessed.
    #[serde(default)]
    pub adapters: Vec<AdapterStatus>,
    /// Everything the hypervisor will say about this machine. Additive: an
    /// older agent sends none, and none means "not collected", never "healthy".
    #[serde(default)]
    pub diagnostics: Option<Diagnostics>,
    #[serde(default)]
    pub message: Option<String>,
    /// Only for a machine that was given a recipe, and only until it settles.
    /// Additive and defaulted, so an older agent that never sends it is not a
    /// protocol break — it simply reports nothing, as it always did.
    #[serde(default)]
    pub recipe_progress: Option<RecipeProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    Running,
    /// **The default, and the choice is deliberate.** `InstanceSpec::lifecycle`
    /// is a required field, so this is never what a missing value deserializes
    /// to — it is only what `Default::default()` builds. Even so, the inert
    /// variant is the only safe one to pick: a default of `Running` would let a
    /// half-constructed spec start a machine, and `Deleted` would let one
    /// remove a machine. `Stopped` does nothing at all, which is the right
    /// behaviour for an instruction nobody actually gave.
    #[default]
    Stopped,
    /// **`Absent`, not `Deleted`** — protocol 6. Every value here is a
    /// destination, and this one was the exception that proved it: `Deleted` is
    /// a command wearing a state's clothes, and it reads wrong on the thousandth
    /// identical send while the agent is still tearing the machine down. *This
    /// machine should not exist* stays true throughout that, and stays true
    /// afterwards. The rename moves the odd one out toward the rule rather than
    /// away from it.
    ///
    /// **`deleted` on the wire, and a renamed variant is the worse half of the
    /// problem.** A renamed *field* an old peer cannot find is at least a clear
    /// deserialization error; a renamed *value* it has never heard of is the
    /// same error arriving only for the machines that happen to be reaching
    /// this state — so a teardown would fail while everything else looked
    /// healthy. Core emits the value, so only Core's spelling matters, and it
    /// stays the one every shipped agent already parses.
    #[serde(rename = "deleted", alias = "absent")]
    Absent,
}

/// How to execute an inference worker. Carries execution detail (image, model
/// repo, arguments) but no marketplace decision logic: the provider is told
/// what to run, never why it was placed here or what it costs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceWorkerSpec {
    /// How long Core is still prepared to wait for this worker, in seconds.
    ///
    /// The agent owns the fine clock — this clone is taking too long, retry,
    /// give up — and Core keeps a slower durable backstop in the database. Two
    /// clocks on purpose: the inner one is cheap and dies with the process,
    /// which is fine, and the outer one exists precisely because it can.
    ///
    /// `None` means Core did not say, and the agent should use its own
    /// default rather than waiting forever.
    #[serde(default)]
    pub budget_secs: Option<u64>,
    pub id: String,
    /// **`intent` in Rust, `lifecycle` on the wire** — the same split as on
    /// `InstanceSpec`, for the same reasons. Missing this one in the first pass
    /// would have put `intent` on the wire for machines and `lifecycle` for
    /// workers, which is worse than either name: a reader would reasonably
    /// conclude the two fields meant different things.
    #[serde(rename = "lifecycle", alias = "intent")]
    pub intent: Lifecycle,
    pub image: String,
    pub model_repo: String,
    #[serde(default)]
    pub vllm_args: Vec<String>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    /// Opaque provider-local GPU identities this worker must use.
    #[serde(default)]
    pub gpu_local_ids: Vec<String>,
    /// The node holding those cards; see `InstanceSpec::gpu_node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_node: Option<String>,
    /// Port the worker serves its OpenAI-compatible API on.
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerState {
    Pending,
    Deploying,
    LoadingModel,
    Ready,
    Draining,
    Error,
    Offline,
    /// A value this build does not know: a newer peer sent a variant added
    /// after it. Read as "not understood", never as any of the above; see
    /// `unknown_variants_are_one_row_not_the_whole_report`.
    #[serde(other)]
    Unknown,
}

/// Normalized worker state reported upward. `local_id` is opaque to Core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkerStatus {
    /// Whether trying again could plausibly work. `Some(false)` says stop: the
    /// image is not offered here, the spec is impossible, the card is gone.
    /// Without this Core must poll to learn anything, which is the chatter the
    /// version above exists to remove.
    #[serde(default)]
    pub retryable: Option<bool>,
    /// What this is waiting for, in the agent's own words: "the template to
    /// finish cloning", "a free card". "Waiting" without "for what" is not
    /// information.
    #[serde(default)]
    pub waiting_on: Option<String>,
    pub id: String,
    pub state: WorkerState,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Every adapter this machine has, and whether the host has actually seen
    /// traffic from each. Additive: an older agent sends none and Core falls
    /// back to the single address below, believed but never witnessed.
    #[serde(default)]
    pub adapters: Vec<AdapterStatus>,
    /// Everything the hypervisor will say about this machine. Additive: an
    /// older agent sends none, and none means "not collected", never "healthy".
    #[serde(default)]
    pub diagnostics: Option<Diagnostics>,
    /// A note about this worker's *state*, and only that.
    ///
    /// Core stores it in a column called `last_error` and the console paints it
    /// in a warning box, so anything put here reads as a fault. A healthy
    /// worker's VM name sat in that box for a day because this looked like a
    /// free-text slot. Leave it `None` when there is nothing wrong.
    #[serde(default)]
    pub message: Option<String>,
    /// What the Workload Agent inside this machine last said about itself.
    ///
    /// Absent means nothing has reported — an older agent, a machine that has
    /// not booted far enough, or a report gone stale. It must never be read as
    /// "unhealthy": the Provider Agent's own probe is what decides `state`, and
    /// this only ever *adds* detail to it. A push that never arrives costs
    /// latency and never truth.
    #[serde(default)]
    pub telemetry: Option<WorkloadReport>,
}

/// What a Workload Agent observes from inside a machine the marketplace owns.
///
/// The reason this tier exists at all is physical: a passed-through GPU is
/// bound to `vfio-pci` on the host, so the host has no driver to ask and
/// `nvidia-smi` there cannot see the card. Utilisation, real VRAM, temperature
/// and power exist only inside the guest.
///
/// Never collected from a buyer's machine. The buyer owns it, could forge any
/// of this, and its silence would be indistinguishable from a dead machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadReport {
    /// The marketplace id of the workload this describes.
    pub workload_id: String,
    /// Seconds since the Workload Agent started. A number that keeps resetting
    /// is a crash loop, which is invisible in a health check that only asks
    /// whether something answers right now.
    pub uptime_s: u64,
    /// Whether the thing beside it will actually serve a request.
    pub health: WorkloadHealth,
    /// How far along the model is. Absent once serving.
    #[serde(default)]
    pub model: Option<ModelProgress>,
    #[serde(default)]
    pub gpus: Vec<GpuTelemetry>,
    #[serde(default)]
    pub serving: Option<ServingStats>,
    /// Connections this machine saw arriving. The responder's half of the
    /// reachability handshake: without it, a probe that "succeeded" cannot be
    /// distinguished from something else answering in this machine's place.
    #[serde(default)]
    pub observed: Vec<ObservedPeer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadHealth {
    /// Answering, and answering promptly.
    Serving,
    /// The process is up and the port answers, but slowly enough that routing
    /// traffic here would hurt. An HTTP 200 alone cannot tell these apart, and
    /// that gap is why `state` is not the whole story.
    Degraded,
    /// Up, not yet able to serve — weights still loading.
    Starting,
    /// Down.
    Down,
    /// A value this build does not know: a newer peer sent a variant added
    /// after it. Read as "not understood", never as any of the above; see
    /// `unknown_variants_are_one_row_not_the_whole_report`.
    #[serde(other)]
    Unknown,
}

/// Where a model is between "nothing on disk" and "ready to serve".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProgress {
    pub stage: ModelStage,
    /// Bytes in the model cache. The honest measure of a download: the weights
    /// are fetched inside a container we do not run, so the observable fact is
    /// the cache growing on disk.
    #[serde(default)]
    pub cached_bytes: u64,
    /// Bytes gained since the previous report, so a stall is visible as zero
    /// rather than as a number that merely stopped rising.
    #[serde(default)]
    pub delta_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelStage {
    Downloading,
    Loading,
    Loaded,
    /// A value this build does not know: a newer peer sent a variant added
    /// after it. Read as "not understood", never as any of the above; see
    /// `unknown_variants_are_one_row_not_the_whole_report`.
    #[serde(other)]
    Unknown,
}

/// One GPU, as the guest sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuTelemetry {
    /// Index inside the guest. Not the provider-local id: the host and the
    /// guest number cards differently, and conflating them attributes load to
    /// the wrong card.
    pub index: u32,
    pub name: String,
    /// The card's real VRAM, which retires the host-side static device table.
    pub vram_total_mib: u64,
    pub vram_used_mib: u64,
    pub utilization_pct: u32,
    #[serde(default)]
    pub temperature_c: Option<u32>,
    /// Milliwatts, not watts as a float: this type is compared for equality
    /// all the way up the stack, and a float in a wire type makes that a
    /// question about representation instead of about the card.
    #[serde(default)]
    pub power_mw: Option<u32>,
}

/// Load, for placement to reason about later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServingStats {
    pub requests_running: u32,
    /// Depth of the queue. The number that says "this worker is full" before
    /// latency does.
    pub requests_waiting: u32,
    #[serde(default)]
    pub prompt_tokens_total: u64,
    #[serde(default)]
    pub generation_tokens_total: u64,
}

/// One thing an agent checked about itself, and what it found.
///
/// The failure this exists for is silence. A gateway VM that exists, is
/// `running`, and has been reconciled to the desired state can still be unable
/// to reach the overlay — and every surface above it reports health, because
/// every surface above it is asking whether the *object* is there. It took a
/// buyer's endpoint answering 502 to notice, and the machine behind it had been
/// healthy the whole time.
///
/// So a check names what it verified and, crucially, whether it verified
/// **presence** or **reachability**. The two fail independently and only the
/// second one is what a buyer experiences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfCheck {
    /// Stable identifier, e.g. `gateway.peer.connected`. Named so Core can
    /// track one check over time rather than diffing prose.
    pub name: String,
    pub kind: CheckKind,
    pub result: CheckResult,
    /// What was observed, in the agent's own words. Present on a failure and
    /// worth having on a pass: "connected, 3 peers" ages better than "ok".
    #[serde(default)]
    pub detail: Option<String>,
    /// What this check is about, when it is about one thing: a gateway id, a
    /// network id, a bridge name.
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// The thing is configured and exists.
    Presence,
    /// The thing actually works: a packet got somewhere and something answered.
    /// This is the one that matters, and the one nothing asked before.
    Connectivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    /// Could not be determined — no guest agent, still booting, not applicable
    /// here. Never to be shown as a pass, and never as a failure either: the
    /// difference between "broken" and "not known" is most of the value of
    /// checking at all.
    #[serde(other)]
    Unknown,
}

/// One end's account of a path, so two ends can be compared.
///
/// ## Why two ends and not one
///
/// A single prober can only say "I connected". It cannot say *what* it
/// connected to. A stale NAT entry, a recycled address, another tenant's
/// machine on a bridge that should not have been shared — each of those answers
/// a probe perfectly, and a one-ended check calls the path healthy.
///
/// So both ends report independently and Core compares. TCP already proves
/// bidirectionality at the transport layer; what this adds is **identity** (the
/// machine that answered is the machine we sold) and **attribution** (which hop
/// failed, from who saw what).
///
/// Four outcomes, and the second is the one nothing else can find:
///
/// ```text
/// both saw it            the path works, and the responder is the right machine
/// prober only            something answered that was not our machine
/// responder only         someone is reaching it by a path we did not open
/// neither                the path is down; the hop checks localize it
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityReport {
    /// The endpoint this probe was for.
    pub endpoint_id: String,
    /// What was dialled, as `address:port`.
    pub target: String,
    pub outcome: ProbeOutcome,
    /// The address the prober dialled *from*. This is what the responder will
    /// have seen, and it is what makes the two accounts comparable without
    /// trusting either end's clock very far.
    #[serde(default)]
    pub source: Option<String>,
    /// Seconds since the epoch, by the prober's clock. Used only to bound a
    /// comparison window — never to order events, because two machines'
    /// clocks disagreeing is ordinary and not a fault.
    pub at_unix: u64,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// A connection was established.
    Connected,
    /// Something is there and said no. Very different from silence: refused
    /// means the path works and the service does not.
    Refused,
    /// Silence. The usual shape of a broken overlay or a missing policy.
    TimedOut,
    /// No route at all.
    Unreachable,
    /// A value this build does not know: a newer peer sent a variant added
    /// after it. Read as "not understood", never as any of the above; see
    /// `unknown_variants_are_one_row_not_the_whole_report`.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPeer {
    /// Who connected, as the guest saw them.
    pub peer: String,
    /// The local port they reached.
    pub port: u16,
    pub at_unix: u64,
}

/// One line of the agent's own audit log, travelling up to the marketplace.
///
/// The provider's copy on their disk stays authoritative for them: this is a
/// *subset* sent so Core can show a provider what was asked of their hardware
/// in the same words, and so a buyer's timeline can say what actually happened
/// rather than only what state a thing reached. It carries no secret and no
/// buyer payload, by the same redaction policy the local log follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339, from the provider's clock.
    pub at: String,
    /// What was done: "instance.start", "gateway.delete".
    pub action: String,
    /// Who asked. "core" for anything arriving as desired state, "agent" for
    /// work the agent decided to do itself.
    pub actor: String,
    /// What it acted on, in marketplace terms.
    pub subject: String,
    pub outcome: String,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    pub protocol_version: u32,
    /// A slice of the agent's own audit log since the last report. Bounded by
    /// the agent and again by Core: a provider is semi-trusted, and an
    /// unbounded list from one is a way to fill somebody else's database.
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
    #[serde(default)]
    pub workers: Vec<WorkerStatus>,
    #[serde(default)]
    pub instances: Vec<InstanceStatus>,
    /// What this agent verified about itself on this pass. Additive: an older
    /// Core ignores it, and an older agent sends none.
    #[serde(default)]
    pub checks: Vec<SelfCheck>,
    /// **What this report claims to cover, and whether it covers it.**
    ///
    /// Without this a report is a list of things, and a list of things cannot
    /// say whether it is *all* of them. An empty `instances` is then
    /// indistinguishable from an agent that failed to enumerate — so Core can
    /// never safely conclude a machine is gone, which is the one conclusion that
    /// frees a card and deletes a ledger row.
    ///
    /// Additive and defaulted, so `PROTOCOL_VERSION` holds: an older agent sends
    /// none and Core treats its reports as it always has — evidence of presence,
    /// never of absence.
    #[serde(default)]
    pub observation: Option<Observation>,
}

/// The provenance of one status report: what was looked at, when, and whether
/// the looking finished.
///
/// This is the wire form of a rule the control plane already holds internally —
/// *unknown is not empty*. A scan that could not complete reports that it could
/// not complete, rather than reporting nothing found; evidence from a provider
/// needs the same property, because the failure mode is identical and the
/// consequence is worse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Increments once per agent process start. Two reports from different
    /// generations cannot be ordered against each other by `sequence` alone,
    /// so a restart is visible rather than looking like a reordering.
    pub generation: u64,
    /// Monotonic within a generation. Lets Core drop a report that arrived out
    /// of order instead of applying it over newer evidence.
    pub sequence: u64,
    /// When the agent *looked*, not when Core received it. A report delayed in
    /// flight is stale evidence, and only this field can say so.
    pub collected_at_unix: i64,
    /// Which kinds this report enumerated: `desired_instances` and
    /// `desired_workers`, the words the agent sends and Core's SQL matches (it
    /// said `instances`, `workers`, which nobody sends). A kind that is absent
    /// from this list was not looked at, which is different from having none.
    /// An untyped string today; a typed kind would be a wire change.
    #[serde(default)]
    pub scope: Vec<String>,
    /// False when any enumeration failed, was bounded, or was skipped. A report
    /// that is not complete may prove presence and may never prove absence.
    pub complete: bool,
    /// Why, in the agent's own words, when it is not complete.
    #[serde(default)]
    pub incomplete_because: Vec<String>,
    /// The provider desired revision this evidence answers, when the agent knows
    /// it. Correlates evidence with an input; it does **not** give a provider
    /// authority over any project's epoch.
    #[serde(default)]
    pub desired_revision: Option<u64>,
}

impl Observation {
    /// Whether absence may be concluded for a kind from this report.
    ///
    /// Three conditions, and dropping any one of them is how a healthy provider
    /// gets its machines deleted: the report finished, it actually looked at
    /// this kind, and it is not older than evidence already held.
    pub fn may_prove_absence(&self, kind: &str) -> bool {
        self.complete && self.scope.iter().any(|s| s == kind)
    }

    /// Whether this report supersedes one already held. A report from an earlier
    /// generation is not older — it is from a different process, and only
    /// `collected_at_unix` can compare across that boundary.
    pub fn supersedes(&self, held: &Observation) -> bool {
        if self.generation == held.generation {
            self.sequence > held.sequence
        } else {
            self.collected_at_unix > held.collected_at_unix
        }
    }
}

/// Frames on the reverse tunnel.
///
/// The provider dials Core and holds the connection open; Core then sends work
/// *down* that connection. Nothing marketplace-initiated needs an inbound path
/// to the provider, so a provider behind NAT, CGNAT or a restrictive firewall
/// participates with no configuration at all.
///
/// Text frames carrying JSON: the payloads are themselves JSON or SSE, so a
/// binary framing layer would buy nothing and cost debuggability.
///
/// `Debug` is written out below rather than derived: `body` and `data` carry a
/// buyer's prompts, a model's answers and console keystrokes, typed passwords
/// included, and a derived `Debug` printed them through any `{:?}` on a frame.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum TunnelFrame {
    /// Core -> provider: run this request against a local worker.
    Request {
        id: String,
        /// Marketplace worker id; the agent resolves it to a local endpoint so
        /// Core never needs to know the provider's addressing.
        worker_id: String,
        path: String,
        body: String,
    },
    /// Core -> provider: the caller went away; stop work on this id.
    Cancel {
        id: String,
    },
    /// provider -> Core: response status, before any body.
    Head {
        id: String,
        status: u16,
    },
    /// provider -> Core: a body chunk, streamed as it arrives.
    Chunk {
        id: String,
        data: String,
    },
    /// provider -> Core: the response is complete.
    End {
        id: String,
    },
    /// provider -> Core: this request failed locally.
    Error {
        id: String,
        message: String,
    },
    /// Core -> provider: open a console on one of this provider's machines.
    ///
    /// Out-of-band access: the hypervisor's own console, so it works when the
    /// machine's network does not, and nothing runs in the guest for it. The
    /// agent answers with `Head` (open) or `Error`, then `ConsoleData` frames
    /// flow both ways until `Cancel` (Core) or `End` (provider).
    ConsoleOpen {
        id: String,
        instance_id: String,
        kind: ConsoleKind,
    },
    /// Either direction: raw console bytes, base64 — a terminal stream is not
    /// UTF-8 at frame boundaries, and the tunnel is text.
    ConsoleData {
        id: String,
        data: String,
    },
    /// Core -> provider: the buyer's terminal changed size.
    ConsoleResize {
        id: String,
        cols: u16,
        rows: u16,
    },
    /// provider -> Core, after `Head`: a one-time secret the viewer needs to
    /// authenticate inside the console protocol (VNC's password). Minted by
    /// the hypervisor for this session only; never stored.
    ConsoleCredential {
        id: String,
        password: Redacted,
    },
    /// Core -> provider: desired state changed, reconcile now.
    ///
    /// A nudge, not the payload: the agent then fetches desired state over the
    /// normal endpoint, so there is one authoritative representation rather
    /// than two that can drift.
    Reconcile,
    /// Either direction: liveness, so a silently dead TCP connection is noticed.
    Ping,
    Pong,
}

/// What a payload is, without what it says: its length.
struct Elided<'a>(&'a str);

impl std::fmt::Debug for Elided<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}

// **Exhaustive on purpose.** Every variant and field is named, with no `..`,
// so a field added later does not compile until somebody decides here whether
// it may be printed.
impl std::fmt::Debug for TunnelFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelFrame::Request {
                id,
                worker_id,
                path,
                body,
            } => f
                .debug_struct("Request")
                .field("id", id)
                .field("worker_id", worker_id)
                .field("path", path)
                .field("body", &Elided(body))
                .finish(),
            TunnelFrame::Cancel { id } => f.debug_struct("Cancel").field("id", id).finish(),
            TunnelFrame::Head { id, status } => f
                .debug_struct("Head")
                .field("id", id)
                .field("status", status)
                .finish(),
            TunnelFrame::Chunk { id, data } => f
                .debug_struct("Chunk")
                .field("id", id)
                .field("data", &Elided(data))
                .finish(),
            TunnelFrame::End { id } => f.debug_struct("End").field("id", id).finish(),
            TunnelFrame::Error { id, message } => f
                .debug_struct("Error")
                .field("id", id)
                .field("message", message)
                .finish(),
            TunnelFrame::ConsoleOpen {
                id,
                instance_id,
                kind,
            } => f
                .debug_struct("ConsoleOpen")
                .field("id", id)
                .field("instance_id", instance_id)
                .field("kind", kind)
                .finish(),
            TunnelFrame::ConsoleData { id, data } => f
                .debug_struct("ConsoleData")
                .field("id", id)
                .field("data", &Elided(data))
                .finish(),
            TunnelFrame::ConsoleResize { id, cols, rows } => f
                .debug_struct("ConsoleResize")
                .field("id", id)
                .field("cols", cols)
                .field("rows", rows)
                .finish(),
            TunnelFrame::ConsoleCredential { id, password } => f
                .debug_struct("ConsoleCredential")
                .field("id", id)
                .field("password", password)
                .finish(),
            TunnelFrame::Reconcile => f.write_str("Reconcile"),
            TunnelFrame::Ping => f.write_str("Ping"),
            TunnelFrame::Pong => f.write_str("Pong"),
        }
    }
}

/// Which console a machine offers. Decided by its image (`ImageSpec`), never
/// by the buyer: a serial terminal for machines that log in on a tty, VNC for
/// ones that need a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleKind {
    Serial,
    Vnc,
}

impl ConsoleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConsoleKind::Serial => "serial",
            ConsoleKind::Vnc => "vnc",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InventoryReport {
        InventoryReport {
            protocol_version: PROTOCOL_VERSION,
            runtime: RuntimeKind::Proxmox,
            capabilities: ComputeCapabilities {
                vm: true,
                gpu_passthrough: true,
                ..Default::default()
            },
            location: None,
            city: None,
            // What this provider can build from. Absent means it offers the
            // marketplace's default only.
            images: vec!["ubuntu-26.04".into()],
            // What it is actually holding, which is the claim Core should
            // believe. The digest is what makes an image id mean one machine.
            held_images: vec![HeldImage {
                id: "ubuntu-26.04".into(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            }],
            nodes: vec![NodeInventory {
                local_id: "pve".into(),
                cpu_cores: 16,
                memory_mib: 65536,
                disk_gib: 1000,
                committed: None,
                gpus: vec![GpuDevice {
                    local_id: "0000:01:00.0".into(),
                    vendor: "NVIDIA".into(),
                    model: "RTX 4090".into(),
                    vram_mib: 24564,
                }],
            }],
        }
    }

    /// Enrolment is additive too: an agent built before topology v2 ignores it
    /// and builds the machine it always did, and a Core built before v2 sends
    /// none, which a new agent reads as "this machine is not a peer".
    ///
    /// That second direction is the one worth testing. `None` has to mean *no
    /// overlay for this machine* and never *the field was lost in transit* —
    /// because the two are indistinguishable on the wire, and the safe reading
    /// is the one that builds a working machine on a provider-local address
    /// rather than a machine that silently joins nothing and reports success.
    #[test]
    fn enrolment_is_invisible_to_a_peer_that_predates_it() {
        let with = serde_json::to_string(&InstanceSpec {
            id: "i-1".into(),
            intent: Lifecycle::Running,
            name: "gpu-1".into(),
            vcpus: 4,
            memory_mib: 8192,
            disk_gib: 40,
            overlay: Some(OverlayEnrolment {
                setup_key: "A-B-C".into(),
                management_url: "https://api.omnuv.com:8443".into(),
                hostname: Some("onv-gpu-1".into()),
            }),
            ..Default::default()
        })
        .unwrap();

        // An older agent deserializes it and simply does not see the field.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct InstanceSpecAsItWasBefore {
            id: String,
            name: String,
            vcpus: u32,
        }
        let old: InstanceSpecAsItWasBefore = serde_json::from_str(&with).unwrap();
        assert_eq!(old.name, "gpu-1");

        // And a newer agent reading an older Core sees `None`, not an error.
        let mut v = serde_json::to_value(InstanceSpec {
            id: "i-2".into(),
            name: "gpu-2".into(),
            ..Default::default()
        })
        .unwrap();
        v.as_object_mut().unwrap().remove("overlay");
        let fresh: InstanceSpec = serde_json::from_value(v).unwrap();
        assert!(fresh.overlay.is_none());
    }

    /// The catalogue is additive in both directions, which is why
    /// `PROTOCOL_VERSION` does not move for it.
    #[test]
    fn the_catalogue_is_invisible_to_a_peer_that_predates_it() {
        // An agent built before the catalogue deserializes a DesiredState
        // carrying one, and simply does not see the images.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct DesiredStateAsItWasBefore {
            protocol_version: u32,
            #[serde(default)]
            version: u64,
            // No `gateways` any more: the field is gone from the contract as
            // of protocol 3, and an agent that predates the catalogue reads a
            // DesiredState without it exactly as it reads one without images.
        }

        let with_catalogue = serde_json::to_string(&DesiredState {
            protocol_version: PROTOCOL_VERSION,
            version: 7,
            unchanged: false,
            inference_workers: Vec::new(),
            instances: Vec::new(),
            images: vec![ImageArtefact {
                id: "ubuntu-26.04-gaming".into(),
                sha256: "abc123".into(),
                bytes: 8_000_000_000,
                url: "https://api.omnuv.com/v1/provider/images/ubuntu-26.04-gaming".into(),
            }],
            poll_interval_secs: None,
        })
        .unwrap();
        let old: DesiredStateAsItWasBefore = serde_json::from_str(&with_catalogue).unwrap();
        assert_eq!(old.version, 7);

        // And the other way: a Core built before the catalogue sends none, so
        // a new agent sees an empty catalogue rather than failing to parse.
        // Empty means "nothing published", which is what an older Core means.
        let without: DesiredState =
            serde_json::from_str(r#"{"protocol_version":2,"version":7}"#).unwrap();
        assert!(without.images.is_empty());

        // Same for what comes back up: an agent that cannot mirror sends no
        // `held_images`, and Core must read that as "does not report digests"
        // rather than as "holds nothing".
        // Built by taking a real report and deleting the key, rather than by
        // hand-writing the schema: a fixture that lists every field is a
        // second copy of the contract, and it goes stale the first time the
        // real one gains a required field.
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().remove("held_images");
        let report: InventoryReport = serde_json::from_value(v).unwrap();
        assert!(report.held_images.is_empty());
        assert_eq!(report.images, vec!["ubuntu-26.04".to_string()]);
    }

    #[test]
    fn roundtrips_and_totals() {
        let r = sample();
        let back: InventoryReport =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(r, back, "inventory report must survive a JSON roundtrip");
        assert_eq!(back.total_cpu_cores(), 16);
        assert_eq!(back.gpu_count(), 1);
    }

    #[test]
    fn tunnel_frames_roundtrip_and_are_tagged() {
        let frames = vec![
            TunnelFrame::Request {
                id: "r1".into(),
                worker_id: "w1".into(),
                path: "/v1/chat/completions".into(),
                body: "{}".into(),
            },
            TunnelFrame::Chunk {
                id: "r1".into(),
                data: "data: {}\n\n".into(),
            },
            TunnelFrame::End { id: "r1".into() },
            TunnelFrame::Ping,
        ];
        for f in frames {
            let json = serde_json::to_string(&f).unwrap();
            // The tag is what lets either side dispatch without guessing.
            assert!(json.contains("\"t\":"), "frame must carry its tag: {json}");
            assert_eq!(f, serde_json::from_str(&json).unwrap());
        }
    }

    #[test]
    fn worker_state_wire_names_match_the_database_check_constraint() {
        // These strings are written straight into inference_workers.status,
        // which has a CHECK constraint. A rename here is a breaking change.
        for (state, expected) in [
            (WorkerState::LoadingModel, "\"LOADING_MODEL\""),
            (WorkerState::Ready, "\"READY\""),
            (WorkerState::Error, "\"ERROR\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), expected);
        }
    }

    #[test]
    fn runtime_kind_wire_names_are_stable() {
        // These strings are the wire contract and land in the providers.runtime
        // column. Changing one is a breaking protocol change.
        for rk in [
            RuntimeKind::Proxmox,
            RuntimeKind::K3sKubeVirt,
            RuntimeKind::OpenStack,
        ] {
            let json = serde_json::to_string(&rk).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", rk.as_str()),
                "serde name must match as_str()"
            );
        }
    }
}

#[cfg(test)]
mod workload_tests {
    use super::*;

    fn report() -> WorkloadReport {
        WorkloadReport {
            workload_id: "worker_1".into(),
            uptime_s: 90,
            health: WorkloadHealth::Serving,
            model: None,
            gpus: vec![GpuTelemetry {
                index: 0,
                name: "NVIDIA GeForce RTX 3090".into(),
                vram_total_mib: 24576,
                vram_used_mib: 21000,
                utilization_pct: 87,
                temperature_c: Some(71),
                power_mw: Some(305_500),
            }],
            serving: Some(ServingStats {
                requests_running: 2,
                requests_waiting: 5,
                prompt_tokens_total: 100,
                generation_tokens_total: 40,
            }),
            observed: vec![],
        }
    }

    #[test]
    fn a_report_survives_a_round_trip() {
        let json = serde_json::to_string(&report()).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkloadReport>(&json).unwrap(),
            report()
        );
    }

    /// The whole reason `telemetry` did not bump PROTOCOL_VERSION. An agent
    /// built before this field existed receives it and must ignore it, not
    /// fail: a provider running last month's agent has to keep working.
    #[test]
    fn an_older_peer_ignores_telemetry_it_does_not_know() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct WorkerStatusAsItWasBefore {
            id: String,
            state: WorkerState,
        }

        let with_telemetry = serde_json::to_string(&WorkerStatus {
            retryable: None,
            waiting_on: None,
            id: "worker_1".into(),
            state: WorkerState::Ready,
            local_id: None,
            endpoint: None,
            adapters: Vec::new(),
            diagnostics: None,
            message: None,
            telemetry: Some(report()),
        })
        .unwrap();

        let old: WorkerStatusAsItWasBefore = serde_json::from_str(&with_telemetry).unwrap();
        assert_eq!(old.id, "worker_1");
    }

    /// And the other direction: a newer Core reading an older agent's status,
    /// which carries no telemetry at all.
    #[test]
    fn a_newer_peer_accepts_a_status_with_no_telemetry() {
        let from_an_old_agent = r#"{"id":"worker_1","state":"READY"}"#;
        let s: WorkerStatus = serde_json::from_str(from_an_old_agent).unwrap();
        assert!(s.telemetry.is_none());
    }

    /// Health is not a boolean. `Degraded` exists because an HTTP 200 from a
    /// worker that takes 30 seconds to answer is indistinguishable from a
    /// healthy one, and routing to it hurts.
    #[test]
    fn degraded_is_distinct_from_serving_and_from_down() {
        for (a, b) in [
            (WorkloadHealth::Serving, WorkloadHealth::Degraded),
            (WorkloadHealth::Degraded, WorkloadHealth::Down),
            (WorkloadHealth::Starting, WorkloadHealth::Down),
        ] {
            // The wire words, which a rename could make collide; the variants
            // themselves are distinct by construction.
            let (wa, wb) = (
                serde_json::to_string(&a).unwrap(),
                serde_json::to_string(&b).unwrap(),
            );
            assert_ne!(wa, wb);
            assert_eq!(serde_json::from_str::<WorkloadHealth>(&wa).unwrap(), a);
            assert_eq!(serde_json::from_str::<WorkloadHealth>(&wb).unwrap(), b);
        }
    }
}

#[cfg(test)]
mod selfcheck_tests {
    use super::*;

    /// Presence and connectivity are different questions, and conflating them
    /// is what let a gateway that existed but could reach nothing report as
    /// healthy for hours.
    #[test]
    fn presence_and_connectivity_are_not_the_same_check() {
        let exists = SelfCheck {
            name: "gateway.vm".into(),
            kind: CheckKind::Presence,
            result: CheckResult::Pass,
            detail: Some("vmid 103, running".into()),
            subject: Some("gw-cc8d3ca7".into()),
        };
        let reaches = SelfCheck {
            name: "gateway.peer.connected".into(),
            kind: CheckKind::Connectivity,
            result: CheckResult::Fail,
            detail: Some("Management: Disconnected".into()),
            subject: Some("gw-cc8d3ca7".into()),
        };
        // The exact state we were in. Both are true at once, and only reporting
        // the first is how it stayed invisible.
        // What travels, rather than the values just written above: both come
        // back as sent, and their kinds are different words on the wire.
        for c in [&exists, &reaches] {
            let back: SelfCheck = serde_json::from_str(&serde_json::to_string(c).unwrap()).unwrap();
            assert_eq!(&back, c);
        }
        let kind = |c: &SelfCheck| serde_json::to_value(c).unwrap()["kind"].clone();
        assert_ne!(
            kind(&exists),
            kind(&reaches),
            "presence and connectivity travel as one kind"
        );
    }

    /// Unknown is not a pass and not a failure. A machine still booting has not
    /// failed its checks, and reporting either extreme is a lie.
    #[test]
    fn unknown_is_its_own_answer() {
        // On the wire, where two results could collide: three distinct words,
        // and each comes back as itself. Comparing the variants in Rust, as
        // this did, cannot fail.
        let words: Vec<String> = [CheckResult::Pass, CheckResult::Fail, CheckResult::Unknown]
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        assert_eq!(words[2], "\"unknown\"");
        assert!(
            words[0] != words[2] && words[1] != words[2] && words[0] != words[1],
            "{words:?}"
        );
        for (r, w) in [CheckResult::Pass, CheckResult::Fail, CheckResult::Unknown]
            .iter()
            .zip(&words)
        {
            assert_eq!(&serde_json::from_str::<CheckResult>(w).unwrap(), r);
        }
    }

    #[test]
    fn a_check_survives_a_round_trip() {
        let c = SelfCheck {
            name: "core.reachable".into(),
            kind: CheckKind::Connectivity,
            result: CheckResult::Pass,
            detail: None,
            subject: None,
        };
        let back: SelfCheck = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    /// An older agent sends a status report with no `checks` at all, and a
    /// newer Core must read it rather than reject it.
    #[test]
    fn a_status_report_without_checks_still_parses() {
        // A real StatusReport, as an agent from before `checks` sends it. It
        // parsed a Value and a struct of its own, so removing `#[serde(default)]`
        // from StatusReport.checks would not have failed it.
        let report: StatusReport =
            serde_json::from_str(r#"{"protocol_version": 6, "instances": []}"#).unwrap();
        assert!(report.checks.is_empty());
    }
}

/// Comparing the two ends of a probe.
///
/// Deliberately a pure function on the protocol crate: both Core and anything
/// third-party reading these reports should agree on what the pair means, and
/// the meaning is the whole point of collecting two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Corroboration {
    /// Both ends saw it. The path works and the responder is the right machine.
    Confirmed,
    /// The prober connected and the machine never saw it. **Something else
    /// answered**: a stale NAT entry, a recycled address, another tenant's
    /// machine on a bridge that should not be shared. A one-ended check calls
    /// this healthy, which is why there are two.
    Impostor,
    /// The machine saw a connection the prober did not make. Someone is
    /// reaching it by a path nobody opened.
    Unexpected,
    /// Neither end saw anything. The path is down; the hop checks localize it.
    Down,
    /// Not enough to say — the responder has not reported since the probe, or
    /// predates this. Never to be shown as either good or bad news.
    Unknown,
}

/// How far apart two clocks may be before a pair is no longer comparable.
///
/// Generous on purpose. Guest clocks drift, and a machine that has just booted
/// may be minutes out until NTP settles; treating that as a failed handshake
/// would make the check fire loudest exactly when a machine is new.
pub const CORROBORATION_WINDOW_SECS: u64 = 180;

/// Whether a probe and what the machine saw are the same event.
///
/// Matched on the prober's source address first and the clock only as a bound,
/// because the addresses are facts both ends observe directly and the clocks
/// are not.
pub fn corroborate(
    probe: &ReachabilityReport,
    observed: &[ObservedPeer],
    responder_reported_at: Option<u64>,
) -> Corroboration {
    let Some(reported_at) = responder_reported_at else {
        return Corroboration::Unknown;
    };
    // The machine has not spoken since the probe, so its silence says nothing.
    // Saturating throughout: these are provider-supplied numbers, and one near
    // u64::MAX panicked a debug build and wrapped a release one.
    if reported_at.saturating_add(CORROBORATION_WINDOW_SECS) < probe.at_unix {
        return Corroboration::Unknown;
    }

    let source = probe.source.as_deref();
    // The port the probe dialled, when its target says one; a connection the
    // machine saw on another port is another conversation.
    let port = probe
        .target
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok());
    let saw_this_prober = observed.iter().any(|o| {
        source.is_some_and(|s| o.peer == s)
            && port.is_none_or(|p| o.port == p)
            && o.at_unix.saturating_add(CORROBORATION_WINDOW_SECS) >= probe.at_unix
            && probe.at_unix.saturating_add(CORROBORATION_WINDOW_SECS) >= o.at_unix
    });

    match (probe.outcome, saw_this_prober) {
        (ProbeOutcome::Connected, true) => Corroboration::Confirmed,
        // **Not seen yet is not an impostor.** A machine whose last report
        // came before the probe cannot have recorded it; within the window
        // above, that read as "something else answered".
        (ProbeOutcome::Connected, false) if reported_at < probe.at_unix => Corroboration::Unknown,
        // Connected to something that is not this machine.
        (ProbeOutcome::Connected, false) => Corroboration::Impostor,
        // Refused is the service saying no over a working path, so the machine
        // legitimately may not record an established connection. Not evidence
        // of an impostor.
        (ProbeOutcome::Refused, _) => Corroboration::Down,
        (_, true) => Corroboration::Unexpected,
        (_, false) => Corroboration::Down,
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;

    fn probe(outcome: ProbeOutcome, at: u64) -> ReachabilityReport {
        ReachabilityReport {
            endpoint_id: "ep1".into(),
            target: "10.200.99.10:8080".into(),
            outcome,
            source: Some("100.93.27.247".into()),
            at_unix: at,
            rtt_ms: Some(3),
        }
    }

    fn seen(peer: &str, at: u64) -> ObservedPeer {
        ObservedPeer {
            peer: peer.into(),
            port: 8080,
            at_unix: at,
        }
    }

    /// Provider-supplied times near the end of u64 answer, rather than
    /// panicking a debug build or wrapping a release one.
    /// A machine that has not reported since the probe says nothing about it,
    /// even inside the window; one that has, and did not see it, is the
    /// finding.
    #[test]
    fn a_report_from_before_the_probe_cannot_call_it_an_impostor() {
        assert_eq!(
            corroborate(&probe(ProbeOutcome::Connected, 1000), &[], Some(995)),
            Corroboration::Unknown
        );
        assert_eq!(
            corroborate(&probe(ProbeOutcome::Connected, 1000), &[], Some(1005)),
            Corroboration::Impostor
        );
    }

    /// Seen from the prober's address but on another port is not this probe.
    #[test]
    fn a_connection_on_another_port_is_not_this_one() {
        let other_port = ObservedPeer {
            peer: "100.93.27.247".into(),
            port: 22,
            at_unix: 1000,
        };
        assert_eq!(
            corroborate(
                &probe(ProbeOutcome::Connected, 1000),
                &[other_port],
                Some(1010)
            ),
            Corroboration::Impostor
        );
        assert_eq!(
            corroborate(
                &probe(ProbeOutcome::Connected, 1000),
                &[seen("100.93.27.247", 1000)],
                Some(1010)
            ),
            Corroboration::Confirmed
        );
    }

    #[test]
    fn a_time_at_the_end_of_the_range_does_not_overflow() {
        let far = u64::MAX - 1;
        assert_eq!(
            corroborate(
                &probe(ProbeOutcome::Connected, 1000),
                &[seen("100.93.27.247", far)],
                Some(far)
            ),
            Corroboration::Impostor
        );
        assert_eq!(
            corroborate(
                &probe(ProbeOutcome::Connected, far),
                &[seen("100.93.27.247", far)],
                Some(far)
            ),
            Corroboration::Confirmed
        );
    }

    #[test]
    fn both_ends_agreeing_is_the_only_confirmation() {
        let c = corroborate(
            &probe(ProbeOutcome::Connected, 1000),
            &[seen("100.93.27.247", 1000)],
            Some(1010),
        );
        assert_eq!(c, Corroboration::Confirmed);
    }

    /// The case a single-ended check cannot see, and the reason for all of
    /// this: the prober connected to *something*, and it was not our machine.
    #[test]
    fn connected_to_something_that_is_not_our_machine() {
        let c = corroborate(&probe(ProbeOutcome::Connected, 1000), &[], Some(1010));
        assert_eq!(c, Corroboration::Impostor);
        // And a connection from a *different* source is not our probe either.
        let c = corroborate(
            &probe(ProbeOutcome::Connected, 1000),
            &[seen("10.0.0.9", 1000)],
            Some(1010),
        );
        assert_eq!(c, Corroboration::Impostor);
    }

    #[test]
    fn neither_end_saw_anything() {
        assert_eq!(
            corroborate(&probe(ProbeOutcome::TimedOut, 1000), &[], Some(1010)),
            Corroboration::Down
        );
    }

    /// Someone reached the machine by a path we did not open. Worth surfacing:
    /// on a correctly fenced bridge it should be impossible.
    #[test]
    fn a_connection_nobody_made() {
        let c = corroborate(
            &probe(ProbeOutcome::TimedOut, 1000),
            &[seen("100.93.27.247", 1000)],
            Some(1010),
        );
        assert_eq!(c, Corroboration::Unexpected);
    }

    /// Refused means the path works and the service does not — the machine may
    /// never record an established connection, so this must not read as an
    /// impostor.
    #[test]
    fn refused_is_a_working_path_with_a_dead_service() {
        assert_eq!(
            corroborate(&probe(ProbeOutcome::Refused, 1000), &[], Some(1010)),
            Corroboration::Down
        );
    }

    /// A machine that has not spoken since the probe tells us nothing, and
    /// must not be counted against it.
    #[test]
    fn a_silent_responder_is_unknown_not_guilty() {
        assert_eq!(
            corroborate(&probe(ProbeOutcome::Connected, 5000), &[], None),
            Corroboration::Unknown
        );
        // Reported long before the probe: its account cannot cover it.
        assert_eq!(
            corroborate(&probe(ProbeOutcome::Connected, 5000), &[], Some(100)),
            Corroboration::Unknown
        );
    }

    /// Clocks drift, and a machine minutes out of step must not read as a
    /// failed handshake — that would fire loudest exactly when a machine is new.
    #[test]
    fn clock_drift_inside_the_window_still_corroborates() {
        let c = corroborate(
            &probe(ProbeOutcome::Connected, 1000),
            &[seen("100.93.27.247", 1000 + CORROBORATION_WINDOW_SECS - 1)],
            Some(1200),
        );
        assert_eq!(c, Corroboration::Confirmed);
    }

    #[test]
    fn a_probe_survives_a_round_trip() {
        let p = probe(ProbeOutcome::Connected, 1000);
        assert_eq!(
            serde_json::from_str::<ReachabilityReport>(&serde_json::to_string(&p).unwrap())
                .unwrap(),
            p
        );
    }
}

/// The compatibility review for the 11 September additions, made mechanical.
///
/// Four fields were added at once — `adapters`, `links`, `committed` and the
/// meaning of `overlay_address` — and none of them bumps `PROTOCOL_VERSION`,
/// because each is additive and defaulted. That claim is worth exactly as much
/// as the test that proves it, so here it is in both directions: an older peer
/// must ignore what it does not know, and a newer peer must read an older
/// peer's silence as "not measured" rather than as zero.
#[cfg(test)]
mod additions_of_11_september {
    use super::*;

    #[test]
    fn an_older_core_ignores_adapters_it_does_not_know() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct InstanceStatusAsItWasBefore {
            id: String,
            state: InstanceState,
            private_ip: Option<String>,
        }
        let sent = serde_json::to_string(&InstanceStatus {
            retryable: None,
            waiting_on: None,
            id: "i1".into(),
            state: InstanceState::Running,
            rebooted_token: None,
            local_id: Some("101".into()),
            node: None,
            console_password_generation: None,
            private_ip: Some("10.200.99.5".into()),
            adapters: vec![AdapterStatus {
                name: "net1".into(),
                address: Some("10.200.99.5".into()),
                mac: Some("bc:24:11:00:00:01".into()),
                observed_at_unix: Some(1_789_000_000),
                observed_by: Some("neighbour".into()),
                also_seen: vec!["10.201.0.100".into()],
            }],
            diagnostics: None,
            message: None,
            recipe_progress: None,
        })
        .unwrap();

        let old: InstanceStatusAsItWasBefore = serde_json::from_str(&sent).unwrap();
        // The single address is still there, so the old reading is unchanged.
        assert_eq!(old.private_ip.as_deref(), Some("10.200.99.5"));
    }

    /// The direction that actually bites. An agent that has not been upgraded
    /// sends no `adapters`, no `links` and no `committed`, and Core must read
    /// that as *not measured* — never as an empty set it can act on. Deciding
    /// a provider has committed zero cores, because it did not say, is how a
    /// blind spot becomes a wrong number.
    #[test]
    fn an_older_agent_reports_absence_not_zero() {
        // Still shaped like protocol 2, gateways and all. Those fields are
        // gone from the contract; an older agent that sends them must not make
        // Core fail to read the rest of the report.
        let from_an_old_agent = r#"{
            "protocol_version": 2,
            "workers": [],
            "instances": [],
            "gateways": [],
            "links": []
        }"#;
        let got: StatusReport = serde_json::from_str(from_an_old_agent).unwrap();
        assert!(got.checks.is_empty());

        let node: NodeInventory = serde_json::from_str(
            r#"{"local_id":"pve","cpu_cores":16,"memory_mib":65536,"disk_gib":1000}"#,
        )
        .unwrap();
        assert!(
            node.committed.is_none(),
            "an unmeasured commitment must be None, never Some(0)"
        );
    }

    /// An address the host has never seen must be distinguishable from one it
    /// has. This is the whole point of the field: "the ledger holds it" and
    /// "a packet crossed it" were the same value until now.
    #[test]
    fn a_believed_address_is_not_an_observed_one() {
        let believed: AdapterStatus =
            serde_json::from_str(r#"{"name":"net0","address":"192.168.1.5"}"#).unwrap();
        assert!(believed.observed_at_unix.is_none());

        let seen: AdapterStatus = serde_json::from_str(
            r#"{"name":"net0","address":"192.168.1.5",
                "observed_at_unix":1789000000,"observed_by":"neighbour"}"#,
        )
        .unwrap();
        assert_eq!(seen.observed_by.as_deref(), Some("neighbour"));
        assert_ne!(believed.observed_at_unix, seen.observed_at_unix);
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    /// **The property the whole of phase 6 rests on.** An empty list is evidence
    /// of absence only when the report finished *and* actually looked. Drop
    /// either condition and a provider whose agent failed to enumerate has its
    /// machines deleted and its cards resold.
    #[test]
    fn absence_needs_a_complete_report_that_looked() {
        let looked = |complete: bool, scope: &[&str]| Observation {
            generation: 1,
            sequence: 1,
            collected_at_unix: 1_000,
            scope: scope.iter().map(|s| s.to_string()).collect(),
            complete,
            incomplete_because: vec![],
            desired_revision: None,
        };
        assert!(looked(true, &["instances"]).may_prove_absence("instances"));
        // Finished, but never enumerated this kind.
        assert!(!looked(true, &["workers"]).may_prove_absence("instances"));
        // Enumerated it, but did not finish.
        assert!(!looked(false, &["instances"]).may_prove_absence("instances"));
        // A report carrying no scope at all proves nothing absent, which is what
        // an older agent's reports become: presence only, exactly as before.
        assert!(!looked(true, &[]).may_prove_absence("instances"));
    }

    /// A restart is not a reordering. Sequence numbers restart with the process,
    /// so comparing them across generations would make the first report of a new
    /// agent look older than the last report of the old one — and be discarded.
    #[test]
    fn a_restart_is_not_a_reordering() {
        let at = |generation, sequence, collected_at_unix| Observation {
            generation,
            sequence,
            collected_at_unix,
            scope: vec!["instances".into()],
            complete: true,
            incomplete_because: vec![],
            desired_revision: None,
        };
        let held = at(1, 900, 5_000);
        // Same process, later sequence: newer.
        assert!(at(1, 901, 5_060).supersedes(&held));
        // Same process, earlier sequence: a reordered report, dropped.
        assert!(!at(1, 899, 5_060).supersedes(&held));
        // New process starting from sequence 1, but collected later: newer.
        assert!(at(2, 1, 5_120).supersedes(&held));
        // New process replaying something genuinely old: still not newer.
        assert!(!at(2, 1, 4_000).supersedes(&held));
    }

    /// Additive: a report from an agent that has never heard of this field
    /// parses and carries no observation — which the rule above turns into
    /// "presence only", the behaviour Core had before.
    ///
    /// **This test once asserted `PROTOCOL_VERSION == 5`** to say that adding
    /// the field had not bumped it. Phase 8's renames then bumped it for an
    /// unrelated reason and the assertion became false while the property it
    /// stood for stayed true — which is the tell of a test written about a
    /// number rather than about a behaviour. What it means is below: an older
    /// peer's payload parses, whatever the current version happens to be.
    #[test]
    fn an_older_agents_report_still_parses() {
        let older = r#"{"protocol_version":5,"instances":[],"workers":[]}"#;
        let r: StatusReport = serde_json::from_str(older).expect("older report must parse");
        assert!(
            r.observation.is_none(),
            "an absent observation is absent, not defaulted to complete"
        );
        const {
            assert!(
                MINIMUM_PROTOCOL_VERSION <= 5,
                "a protocol 5 agent is still supported, so its reports must still parse"
            )
        };
    }
}

#[cfg(test)]
mod protocol_six_tests {
    use super::*;

    /// **A protocol 5 agent's payload still parses.** The rename is a bump
    /// because the bytes changed, not because older peers are abandoned: an
    /// agent in the field keeps sending `lifecycle` until somebody upgrades it,
    /// and Core reading that is what makes the upgrade order *Core first, then
    /// providers, at their own pace*.
    #[test]
    fn a_protocol_five_payload_still_parses() {
        let old = r#"{"id":"i-1","lifecycle":"running","name":"gpu-1","vcpus":2,
                      "memory_mib":4096,"disk_gib":20}"#;
        let spec: InstanceSpec = serde_json::from_str(old).expect("a v5 spec must parse");
        assert_eq!(spec.intent, Lifecycle::Running);
    }

    /// And the new name is what Core *writes*, so an upgraded agent sees the
    /// contract the documentation describes.
    #[test]
    fn the_rename_is_in_rust_and_the_wire_is_unchanged() {
        let spec = InstanceSpec {
            id: "i-1".into(),
            intent: Lifecycle::Absent,
            name: "gpu-1".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).expect("serializes");

        // Core serializes desired state and the agent reads it, so what Core
        // *emits* is the only thing an un-upgraded agent's parser sees. This
        // test asserted the opposite two versions ago, and that assertion would
        // have taken every protocol 5 agent down on the deploy that shipped it.
        assert!(json.contains("\"lifecycle\""), "{json}");
        assert!(!json.contains("\"intent\""), "{json}");
        assert!(json.contains("\"deleted\""), "{json}");
        assert!(!json.contains("\"absent\""), "{json}");

        // And both spellings are read, so a peer that has moved on early is
        // not punished for it.
        for key in ["lifecycle", "intent"] {
            for value in ["deleted", "absent"] {
                let raw = json.replace(
                    "\"lifecycle\":\"deleted\"",
                    &format!("\"{key}\":\"{value}\""),
                );
                let back: InstanceSpec = serde_json::from_str(&raw)
                    .unwrap_or_else(|e| panic!("{key}={value} must parse: {e}"));
                assert_eq!(back.intent, Lifecycle::Absent);
            }
        }
    }

    /// **Every value is still a destination**, which is the rule the renames
    /// exist to restore. The test worth having is the one that asks the
    /// question R3 poses: what does this value mean on the thousandth identical
    /// send? Each of these means the same thing every time.
    #[test]
    fn every_desired_value_is_a_destination() {
        for v in [Lifecycle::Running, Lifecycle::Stopped, Lifecycle::Absent] {
            // **The variant name, not the wire word.** A verb would read as an
            // instruction to do something now; these are all adjectives
            // describing where the machine should end up. This test used to ask
            // the serialized form, which stopped being the right question once
            // the wire kept `deleted` for compatibility — and the rule was
            // always about the vocabulary a developer reads, since the bytes
            // persuade nobody.
            let name = format!("{v:?}");
            // Whole names: `Stopped` is a place, `Stop` an order. The clause
            // this replaced, `starts_with("Stop\"")`, could never match a
            // Debug name and so never ran.
            assert!(
                ![
                    "Start", "Stop", "Restart", "Reboot", "Delete", "Destroy", "Create"
                ]
                .contains(&name.as_str())
                    && !name.starts_with("Delete"),
                "{name} reads as a command rather than a destination"
            );
        }
        // Legacy on purpose, and the one value where that is worth a comment:
        // every shipped agent parses `deleted`, and none has heard of `absent`.
        assert_eq!(
            serde_json::to_string(&Lifecycle::Absent).unwrap(),
            "\"deleted\""
        );
    }

    /// The supported range is stated rather than implied, so dropping an old
    /// peer is a deliberate edit here rather than an accident somewhere else.
    #[test]
    fn the_supported_range_is_explicit() {
        assert_eq!(PROTOCOL_VERSION, 6);
        assert_eq!(MINIMUM_PROTOCOL_VERSION, 5);
        const { assert!(MINIMUM_PROTOCOL_VERSION < PROTOCOL_VERSION) };
    }

    /// A withdrawal that cannot say why is an outage as far as the operator on
    /// the other end can tell, and an operator who reads it as an outage
    /// retries rather than upgrades. So the reason ships with the floor, and
    /// this asserts it is a sentence rather than a placeholder somebody meant
    /// to fill in.
    #[test]
    fn the_floor_says_why_it_is_where_it_is() {
        assert!(
            MINIMUM_PROTOCOL_VERSION_REASON.len() > 40,
            "the refusal has to be readable by whoever has to act on it"
        );
        assert!(
            MINIMUM_PROTOCOL_VERSION_REASON.contains(&(MINIMUM_PROTOCOL_VERSION - 1).to_string()),
            "the reason names the highest withdrawn version, so raising the \
             floor without updating it fails here rather than in production"
        );
    }
}

#[cfg(test)]
mod rename_is_complete_tests {
    /// **Every spec renamed, or none should have been.** The first pass renamed
    /// `InstanceSpec.lifecycle` and missed `InferenceWorkerSpec.lifecycle`,
    /// which would have put `intent` on the wire for machines and `lifecycle`
    /// for workers — worse than either name alone, because a reader would
    /// reasonably conclude the two fields meant different things.
    ///
    /// Checked against the source rather than against a list somebody maintains,
    /// so a spec added later with the old name fails here.
    #[test]
    fn no_spec_still_declares_a_lifecycle_field() {
        // Was `src.split("#[cfg(test)]").next()`, which stopped at the first
        // test module and so never reached the production code declared below
        // it. The shared stripper removes each test module instead of
        // truncating at one.
        let body = super::source_scan::production_source();
        let offenders: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("pub lifecycle:"))
            .collect();
        assert!(
            offenders.is_empty(),
            "still declaring lifecycle: {offenders:?}"
        );
        assert_eq!(
            body.matches("pub intent: Lifecycle").count(),
            2,
            "both InstanceSpec and InferenceWorkerSpec carry the renamed field"
        );
    }
}

/// A secret joins the status report, and it rides the channel the recipe's own
/// outcome already travels. Two things need proving: that an agent which never
/// heard of it is not misread as having delivered nothing usable, and that the
/// secret does not escape through `Debug`. The second is the one that will
/// actually catch a regression.
#[cfg(test)]
mod stream_credential_tests {
    use super::*;

    fn status_reporting(p: RecipeProgress) -> InstanceStatus {
        InstanceStatus {
            retryable: None,
            waiting_on: None,
            id: "i1".into(),
            state: InstanceState::Running,
            rebooted_token: None,
            local_id: Some("101".into()),
            node: None,
            console_password_generation: None,
            private_ip: Some("10.200.99.5".into()),
            adapters: vec![],
            diagnostics: None,
            message: None,
            recipe_progress: Some(p),
        }
    }

    /// The direction that bites, and the same shape as `committed` above: an
    /// agent that has never heard of the field sends nothing, and nothing must
    /// read as *not delivered*. Empty credentials are a login that cannot work,
    /// reported as one that can — so `None` is the only honest parse.
    #[test]
    fn an_older_agent_sends_no_credentials_and_absence_is_not_empty() {
        let from_an_old_agent = r#"{"status":"done","step":"3/6"}"#;
        let p: RecipeProgress = serde_json::from_str(from_an_old_agent).unwrap();
        assert!(
            p.stream_credentials.is_none(),
            "undelivered credentials must be None, never Some with empty strings"
        );
        // And the rest of the report is unchanged, which is what additive means.
        assert!(p.finished());
        assert_eq!(p.step.as_deref(), Some("3/6"));
    }

    /// An upgraded agent's report survives the trip — inside the status it
    /// rides on rather than on its own, because that is where it will be.
    #[test]
    fn a_newer_report_round_trips() {
        let sent = status_reporting(RecipeProgress {
            status: "done".into(),
            step: None,
            detail: None,
            stream_credentials: Some(StreamCredentials {
                user: "omnuv".into(),
                password: "correct-horse-battery-staple".into(),
            }),
        });
        let back: InstanceStatus =
            serde_json::from_str(&serde_json::to_string(&sent).unwrap()).unwrap();
        assert_eq!(back, sent);
    }

    /// **The test that earns its keep.** A derived `Debug` prints the password,
    /// `tracing` prints `Debug`, and this repository is public. The whole
    /// `InstanceStatus` is checked as well as the leaf, because the wrapper is
    /// what somebody will actually log: redacting a field is worth nothing if
    /// it does not survive being nested in the value that carries it.
    #[test]
    fn the_password_never_reaches_a_debug_line() {
        const PASSWORD: &str = "correct-horse-battery-staple";
        let creds = StreamCredentials {
            user: "omnuv".into(),
            password: PASSWORD.into(),
        };

        let shown = format!("{creds:?}");
        assert!(
            !shown.contains(PASSWORD),
            "the password is in Debug output: {shown}"
        );
        // The whole line, not a substring of it. A field added to this type
        // later fails here, which is the point: a new field on a credential is
        // exactly when somebody should be made to look at `Debug` again.
        assert_eq!(
            shown,
            r#"StreamCredentials { user: "omnuv", password: <redacted> }"#
        );

        let nested = format!(
            "{:?}",
            status_reporting(RecipeProgress {
                status: "done".into(),
                step: None,
                detail: None,
                stream_credentials: Some(creds.clone()),
            })
        );
        assert!(
            !nested.contains(PASSWORD),
            "the password escapes through the status: {nested}"
        );

        // And serialization is deliberately *not* redacted. Stated here so that
        // anyone tempted to "finish the job" by redacting `Serialize` too
        // breaks this test rather than the delivery, which would fail silently
        // as a login that never works.
        assert!(serde_json::to_string(&creds).unwrap().contains(PASSWORD));
    }
}

/// **The class, tested as a class.** [`Redacted`] exists so that a secret
/// cannot reach a log by accident; what follows proves that it does not, that
/// the wire never noticed the type change, and that a payload written before
/// the type existed still parses into it.
///
/// Every `Debug` assertion is on the *whole* rendered string rather than on a
/// `.contains()`. A `.contains()` guarding a leak passes on a render that was
/// truncated, which is to say it passes for the wrong reason in exactly the
/// case the test exists to catch.
#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// Long enough that a prefix leak would be visible, and distinctive enough
    /// that a substring search cannot match anything else in these payloads.
    const SECRET: &str = "0E38B183-B8B6-45CE-B93B-2EF63F3D14E4";

    /// Both formatters, and nothing but the marker from either. `{}` reaches
    /// for a secret as readily as `{:?}` and is the easier one to write without
    /// thinking, so redacting only `Debug` would leave the more likely half
    /// open. No length and no prefix: four helpful characters are four an
    /// attacker no longer has to guess.
    #[test]
    fn neither_formatter_shows_anything_at_all() {
        let r = Redacted::from(SECRET);
        assert_eq!(format!("{r:?}"), "<redacted>");
        assert_eq!(format!("{r}"), "<redacted>");
        // The one door out, and deliberately the only one: no `Deref`, no
        // `AsRef<str>`, so a call site that takes the secret says so.
        assert_eq!(r.expose(), SECRET);
    }

    /// The three fields the sweep called genuine secrets, each rendered whole.
    /// A field added to one of these later fails here, which is the point: a
    /// new field beside a credential is exactly when somebody should be made to
    /// look at `Debug` again.
    #[test]
    fn every_secret_bearing_type_renders_without_its_secret() {
        let enrolment = OverlayEnrolment {
            setup_key: SECRET.into(),
            management_url: "https://api.omnuv.com:8443".into(),
            hostname: Some("onv-gpu-1".into()),
        };
        assert_eq!(
            format!("{enrolment:?}"),
            r#"OverlayEnrolment { setup_key: <redacted>, management_url: "https://api.omnuv.com:8443", hostname: Some("onv-gpu-1") }"#
        );

        let creds = StreamCredentials {
            user: "omnuv".into(),
            password: SECRET.into(),
        };
        assert_eq!(
            format!("{creds:?}"),
            r#"StreamCredentials { user: "omnuv", password: <redacted> }"#
        );

        let frame = TunnelFrame::ConsoleCredential {
            id: "c-1".into(),
            password: SECRET.into(),
        };
        assert_eq!(
            format!("{frame:?}"),
            r#"ConsoleCredential { id: "c-1", password: <redacted> }"#
        );
    }

    /// The containers, which are what somebody actually logs. `DesiredState` is
    /// the one that mattered: a single `{:?}` on it would have printed every
    /// outstanding enrolment key on that provider in one line.
    ///
    /// Not a whole-string literal here, and not out of laziness — these two
    /// types take additive fields most releases, so a literal would fail
    /// regularly for a reason that has nothing to do with a leak, and a test
    /// that cries wolf is one nobody reads. Counting closes the hole the
    /// whole-string rule exists to close: a truncated render fails the marker
    /// count, so the secret's absence cannot pass vacuously.
    #[test]
    fn a_secret_does_not_escape_through_the_value_that_carries_it() {
        let spec = InstanceSpec {
            id: "i-1".into(),
            overlay: Some(OverlayEnrolment {
                setup_key: SECRET.into(),
                management_url: "https://api.omnuv.com:8443".into(),
                hostname: None,
            }),
            ..Default::default()
        };
        let state = DesiredState {
            protocol_version: PROTOCOL_VERSION,
            version: 7,
            unchanged: false,
            inference_workers: vec![],
            instances: vec![spec.clone(), spec.clone()],
            images: vec![],
            poll_interval_secs: None,
        };

        let spec_shown = format!("{spec:?}");
        assert_eq!(
            spec_shown.matches(SECRET).count(),
            0,
            "InstanceSpec prints the key: {spec_shown}"
        );
        assert_eq!(
            spec_shown.matches("<redacted>").count(),
            1,
            "InstanceSpec: {spec_shown}"
        );

        // Two machines, two keys, and the count is what proves neither of them
        // is the one that got through.
        let state_shown = format!("{state:?}");
        assert_eq!(
            state_shown.matches(SECRET).count(),
            0,
            "DesiredState prints a key: {state_shown}"
        );
        assert_eq!(
            state_shown.matches("<redacted>").count(),
            2,
            "DesiredState: {state_shown}"
        );
    }

    /// **The wire is unchanged, and it is proved against literals** rather than
    /// against a round trip — a round trip passes just as happily when both
    /// halves move together, which is the failure this crate has already
    /// shipped once. A secret is a bare JSON string before and after, so
    /// `PROTOCOL_VERSION` stays 6: nothing on the wire moved.
    #[test]
    fn a_secret_is_still_a_bare_json_string() {
        // `#[serde(transparent)]` on the newtype, checked rather than assumed:
        // the value is the string, not an object wrapping one and not an array.
        assert_eq!(
            serde_json::to_string(&Redacted::from(SECRET)).unwrap(),
            format!("\"{SECRET}\"")
        );

        let enrolment = OverlayEnrolment {
            setup_key: SECRET.into(),
            management_url: "https://api.omnuv.com:8443".into(),
            hostname: Some("onv-gpu-1".into()),
        };
        assert_eq!(
            serde_json::to_string(&enrolment).unwrap(),
            r#"{"setup_key":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4","management_url":"https://api.omnuv.com:8443","hostname":"onv-gpu-1"}"#
        );

        assert_eq!(
            serde_json::to_string(&StreamCredentials {
                user: "omnuv".into(),
                password: SECRET.into(),
            })
            .unwrap(),
            r#"{"user":"omnuv","password":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4"}"#
        );

        // The enum variant is here because an externally-visible variant is the
        // easiest serialization to break by accident: the tag, the variant name
        // and the field all have to survive, and a newtype in one field is
        // precisely the kind of change that quietly re-shapes one of them.
        assert_eq!(
            serde_json::to_string(&TunnelFrame::ConsoleCredential {
                id: "c-1".into(),
                password: SECRET.into(),
            })
            .unwrap(),
            r#"{"t":"console_credential","id":"c-1","password":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4"}"#
        );
    }

    /// An older peer reads a variant added after it as `Unknown`, and the
    /// rest of the report still parses: one row not understood, not a whole
    /// provider's report rejected.
    #[test]
    fn unknown_variants_are_one_row_not_the_whole_report() {
        fn parse<T: serde::de::DeserializeOwned>(s: &str) -> T {
            serde_json::from_value(serde_json::Value::String(s.into())).unwrap()
        }
        assert_eq!(
            parse::<InstanceState>("HIBERNATING"),
            InstanceState::Unknown
        );
        assert_eq!(parse::<WorkerState>("QUANTISING"), WorkerState::Unknown);
        assert_eq!(
            parse::<WorkloadHealth>("throttled"),
            WorkloadHealth::Unknown
        );
        assert_eq!(parse::<ModelStage>("verifying"), ModelStage::Unknown);
        assert_eq!(parse::<CheckResult>("skipped"), CheckResult::Unknown);
        assert_eq!(parse::<ProbeOutcome>("filtered"), ProbeOutcome::Unknown);
        // Known values are unchanged, in both directions.
        assert_eq!(parse::<InstanceState>("RUNNING"), InstanceState::Running);
        assert_eq!(
            serde_json::to_value(ProbeOutcome::TimedOut).unwrap(),
            "timed_out"
        );

        let parsed: StatusReport = serde_json::from_str(
            r#"{"protocol_version":6,"instances":[
                {"id":"a","state":"HIBERNATING"},
                {"id":"b","state":"RUNNING"}]}"#,
        )
        .expect("a report with one unknown state was rejected whole");
        assert_eq!(parsed.instances[0].state, InstanceState::Unknown);
        assert_eq!(parsed.instances[1].state, InstanceState::Running);
    }

    /// The console password's hash and the tunnel's payloads print as what
    /// they are, never as what they say: through a spec, through a desired
    /// state that carries it, and through every frame with a payload.
    #[test]
    fn debug_elides_the_hash_and_the_payloads() {
        const HASH: &str = "$6$saltsalt$Qm9vYmFyYmF6cXV4";
        let spec = InstanceSpec {
            console_password_hash: Some(HASH.into()),
            name: "gpu-1".into(),
            ..Default::default()
        };
        let desired = DesiredState {
            protocol_version: PROTOCOL_VERSION,
            version: 1,
            unchanged: false,
            inference_workers: vec![],
            instances: vec![spec.clone()],
            images: vec![],
            poll_interval_secs: None,
        };
        for printed in [
            format!("{spec:?}"),
            format!("{desired:?}"),
            format!("{spec:#?}"),
        ] {
            assert!(!printed.contains(HASH), "the hash printed: {printed}");
            assert!(
                printed.contains("<redacted>") && printed.contains("gpu-1"),
                "{printed}"
            );
        }
        let unset = format!("{:?}", InstanceSpec::default());
        assert!(
            unset.contains("console_password_hash: None"),
            "an absent hash must still read as absent: {unset}"
        );

        let said = "my password is hunter2";
        for frame in [
            TunnelFrame::Request {
                id: "r".into(),
                worker_id: "w".into(),
                path: "/v1/chat".into(),
                body: said.into(),
            },
            TunnelFrame::Chunk {
                id: "r".into(),
                data: said.into(),
            },
            TunnelFrame::ConsoleData {
                id: "c".into(),
                data: said.into(),
            },
        ] {
            let printed = format!("{frame:?}");
            assert!(!printed.contains("hunter2"), "a payload printed: {printed}");
            assert!(
                printed.contains(&format!("<{} bytes>", said.len())),
                "{printed}"
            );
        }
        let printed = format!(
            "{:?}",
            TunnelFrame::Error {
                id: "r".into(),
                message: "worker gone".into()
            }
        );
        assert!(
            printed.contains("worker gone"),
            "an error's message is not a payload: {printed}"
        );
    }

    /// And the other direction: payloads as they are written today, by a peer
    /// that has never heard of this type, still parse. This is the half
    /// `serde(alias)` does not cover and the half that takes providers down
    /// when it is wrong.
    #[test]
    fn todays_payloads_still_deserialize() {
        let enrolment: OverlayEnrolment = serde_json::from_str(
            r#"{"setup_key":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4","management_url":"https://api.omnuv.com:8443"}"#,
        )
        .unwrap();
        assert_eq!(enrolment.setup_key.expose(), SECRET);
        assert_eq!(enrolment.hostname, None);

        let creds: StreamCredentials = serde_json::from_str(
            r#"{"user":"omnuv","password":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4"}"#,
        )
        .unwrap();
        assert_eq!(creds.password.expose(), SECRET);

        let frame: TunnelFrame = serde_json::from_str(
            r#"{"t":"console_credential","id":"c-1","password":"0E38B183-B8B6-45CE-B93B-2EF63F3D14E4"}"#,
        )
        .unwrap();
        assert_eq!(
            frame,
            TunnelFrame::ConsoleCredential {
                id: "c-1".into(),
                password: SECRET.into()
            }
        );
    }
}

/// Reading this crate's own source, with its tests taken back out of it.
///
/// Every source-level check needs this and needs the same guard: **the file
/// being searched contains the searcher**, so a scan that reads `lib.rs` whole
/// finds its own assertion strings and fails against code that is correct. That
/// has happened three times in this repository already.
///
/// The scope used to be `src.split("#[cfg(test)]").next()` — everything up to
/// the *first* test module. That is a truncation rather than a filter, and it
/// quietly stopped scanning two-fifths of the way down the file: `Corroboration`,
/// `corroborate` and `CORROBORATION_WINDOW_SECS` are production code declared
/// *after* a test module, and nothing was checking them. Brace matching removes
/// each test module and keeps what comes after it.
#[cfg(test)]
mod source_scan {
    /// `lib.rs` with every `#[cfg(test)]` module removed.
    ///
    /// The brace counting is naive about braces inside string literals, and that
    /// is a decision rather than an oversight: it only ever runs over lines
    /// *inside* a test module, where an unbalanced brace in a literal would end
    /// the skip early and leak test text into the result. Which is precisely what
    /// the sentinels below detect — so the property is measured on the real file
    /// rather than argued from the parser.
    pub(super) fn production_source() -> String {
        let mut kept = String::new();
        let mut skipping: Option<i32> = None;
        let mut after_attribute = false;

        for line in include_str!("lib.rs").lines() {
            if let Some(depth) = skipping.as_mut() {
                *depth += braces(line);
                if *depth <= 0 {
                    skipping = None;
                }
                continue;
            }
            if line.trim() == "#[cfg(test)]" {
                after_attribute = true;
                continue;
            }
            if after_attribute {
                // The item the attribute applied to. A `#[cfg(test)]` on
                // something that opens no block — a `use`, a single item — drops
                // that one line and nothing else.
                after_attribute = false;
                let opened = braces(line);
                if opened > 0 {
                    skipping = Some(opened);
                }
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        kept
    }

    fn braces(line: &str) -> i32 {
        line.matches('{').count() as i32 - line.matches('}').count() as i32
    }

    /// **The observer, proved before anything is trusted to it.** A stripper that
    /// returned an empty string would let every scan built on it report a clean
    /// pass over nothing, and a clean pass over nothing is the failure that looks
    /// most like success.
    #[test]
    fn the_stripper_keeps_production_and_drops_tests() {
        let body = production_source();

        // `Corroboration` is declared *after* a test module. It is in this list
        // as the regression test for the old truncating scope, not as decoration.
        for marker in [
            "pub struct DesiredState",
            "pub enum Corroboration",
            "pub fn corroborate",
        ] {
            assert!(
                body.contains(marker),
                "production code was stripped away: {marker}"
            );
        }
        for marker in [
            "JustChecks",
            "neither_formatter_shows_anything_at_all",
            "0E38B183",
        ] {
            assert!(
                !body.contains(marker),
                "test code survived the strip: {marker}"
            );
        }
    }
}

/// **The class, held closed by something that runs.**
///
/// `StreamCredentials` was given a hand-written `Debug` because its password
/// printed in full through the derived one. Two more fields with the same shape
/// turned up within the hour — which is the tell that an instance was fixed and
/// the class was left open. `Redacted` closes it by declaration, but only for a
/// field somebody remembered to declare that way, and nobody remembers on the
/// release where it matters.
///
/// So this holds every field whose *name* says it carries a secret to being typed
/// `Redacted`. A new `pub password: String` fails at `cargo test`, rather than in
/// a `{:?}` on a provider's desired state months later.
///
/// What it cannot do is recognise a secret that is not named like one. A field
/// called `blob` holding an enrolment key passes this check, and only a person
/// reading the diff catches it. The vocabulary is a net with a known mesh size,
/// not a proof — said plainly, because a control whose limits are unwritten gets
/// believed past them.
#[cfg(test)]
mod secret_vocabulary_tests {
    use super::source_scan::production_source;

    /// A name says "secret" when any underscore-separated part of it is one of
    /// these, singular or plural.
    const VOCABULARY: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "token",
        "key",
        "credential",
        "ticket",
        "auth",
    ];

    /// Names that read as secrets and are not, each with the reason it is let
    /// through. **The reason is the load-bearing half.** A bare list is a list
    /// somebody appends to without looking, which is how a detector stops
    /// detecting; being made to write a sentence is the entire cost of this
    /// control, and the only thing between it and decoration.
    const NOT_A_SECRET: &[(&str, &str)] = &[
        (
            "ssh_keys",
            "public keys by contract — a private key is never accepted here",
        ),
        (
            "console_password_hash",
            "a crypt(3) verifier, typed String so no consumer breaks; InstanceSpec's hand-written Debug prints it as <redacted>, which debug_elides_the_hash_and_the_payloads asserts",
        ),
        (
            "console_password_generation",
            "a counter of resets: which password, never what it is",
        ),
        (
            "reboot_token",
            "an idempotency nonce, so one reboot is applied once. It authenticates nothing",
        ),
        (
            "rebooted_token",
            "the agent's echo of that nonce, for the same reason",
        ),
        (
            "prompt_tokens_total",
            "a count of model tokens: the collision is with billing vocabulary, not with credentials",
        ),
        (
            "generation_tokens_total",
            "the same count, the other direction",
        ),
        (
            "stream_credentials",
            "the container. Its own `password` field is scanned on its own line, which is where the secret actually is",
        ),
        (
            "auth_mode",
            "an enum saying key-or-password, and neither of them",
        ),
    ];

    /// Every `name: type` pair in the body — field declarations and struct
    /// literal initializers alike.
    ///
    /// Not told apart, on purpose. Telling them apart means tracking whether the
    /// walk is inside a struct body, and all it would buy today is excusing one
    /// line of a `Default` impl. An initializer reading `setup_key: some_local`
    /// failing the check is the direction a detector should fail in when it gates
    /// nothing destructive.
    fn fields(body: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in body.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Splitting on `{` as well as `,` opens an inline enum variant into
            // its fields. `ConsoleCredential { id: String, password: Redacted }`
            // is where the console password lives, and a variant field carries no
            // `pub` — so a scan anchored on `pub` walks straight past a secret
            // that is already on the wire.
            for piece in line.replace('{', ",").split(',') {
                let piece = piece.trim();
                let piece = piece.strip_prefix("pub ").unwrap_or(piece).trim();
                let Some((name, ty)) = piece.split_once(':') else {
                    continue;
                };
                let (name, ty) = (name.trim(), ty.trim());
                // A Rust field name and nothing else: this is what keeps a JSON
                // key in a string literal (`"setup_key":`) and a path segment
                // (`AuthMode::SshKey`) out of the results.
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    continue;
                }
                out.push((name.to_owned(), ty.to_owned()));
            }
        }
        out
    }

    fn says_secret(name: &str) -> bool {
        name.split('_').any(|part| {
            let singular = part.strip_suffix('s').unwrap_or(part);
            VOCABULARY.contains(&part) || VOCABULARY.contains(&singular)
        })
    }

    #[test]
    fn every_field_whose_name_says_secret_is_typed_redacted() {
        let body = production_source();
        let (mut offenders, mut protected, mut excused) = (Vec::new(), Vec::new(), Vec::new());

        for (name, ty) in fields(&body) {
            if !says_secret(&name) {
                continue;
            }
            if NOT_A_SECRET.iter().any(|(excuse, _)| *excuse == name) {
                excused.push(name);
            } else if ty.contains("Redacted") {
                protected.push(name);
            } else {
                offenders.push(format!("{name}: {ty}"));
            }
        }

        assert!(
            offenders.is_empty(),
            "a field named like a secret is not typed `Redacted`, so it prints in \
             full through any `{{:?}}` on the value that carries it: {offenders:?}. \
             Either declare it `Redacted` — the wire does not move, the newtype is \
             `serde(transparent)` — or add it to NOT_A_SECRET with the reason it \
             is not one."
        );

        // Non-vacuity, in both directions. A scan that found nothing would pass
        // this test while asserting nothing at all, which is the shape every
        // check in this file exists to avoid.
        assert!(
            protected.iter().any(|n| n == "setup_key") && protected.iter().any(|n| n == "password"),
            "the three known secrets are no longer being found by the scan, so a \
             pass here means the scan is broken rather than the crate is clean: \
             found {protected:?}"
        );
        assert!(
            fields(&body).len() > 100,
            "the scan read {} fields out of a 1,500-line crate — it is not reading \
             the source it thinks it is",
            fields(&body).len()
        );

        // An excuse nobody can point at any more is an excuse nobody reviews.
        for (name, why) in NOT_A_SECRET {
            assert!(
                excused.iter().any(|e| e == name),
                "NOT_A_SECRET still excuses `{name}` ({why}) and no such field \
                 exists — delete the entry rather than leaving the list describing \
                 a crate that has moved on"
            );
        }
    }
}
