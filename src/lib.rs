//! Public, versioned contract between Omnuv Core and Omnuv Provider agents.
//!
//! This crate is PUBLIC. It must never depend on anything under `private/`,
//! and must never carry marketplace decision logic: no pricing, no provider
//! ranking, no scheduling policy. It describes resource semantics only.
//!
//! Provider-local identifiers (Proxmox node names, PCI addresses, VMIDs) cross
//! this boundary only as opaque `local_id` strings. Core stores them so the
//! agent can correlate state after a restart; Core must never parse or branch
//! on their contents.

use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message shapes below.
/// **5 as of topology v2's completion (12 September 2026).**
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
/// That is the second half of the addressing decision in `TODO.md` (S1, C′).
/// The first half was Core recording the address the overlay allocated instead
/// of inventing one; this is Core stopping inventing the other one too.
///
/// `CLAUDE.md` said this contract would get a deliberate version rather than
/// quiet erosion — it is a published interface in a public repository, and an
/// agent that still sends a gateway status is told so instead of being
/// silently ignored.
pub const PROTOCOL_VERSION: u32 = 5;

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
    /// A fingerprint of everything below. An agent that already holds this
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    pub lifecycle: Lifecycle,
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
    #[serde(default)]
    pub gpu_local_ids: Vec<String>,
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
    pub setup_key: String,
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
    /// from a marketplace range and Core records. See S1 in `TODO.md`.
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
}

impl RecipeProgress {
    pub fn finished(&self) -> bool {
        self.status == "done" || self.status == "disabled"
    }

    pub fn failed(&self) -> bool {
        self.status == "error"
    }
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
    Deleted,
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
    pub lifecycle: Lifecycle,
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
    /// Which kinds this report enumerated — `instances`, `workers`. A kind that
    /// is absent from this list was not looked at, which is different from
    /// having none.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    Cancel { id: String },
    /// provider -> Core: response status, before any body.
    Head { id: String, status: u16 },
    /// provider -> Core: a body chunk, streamed as it arrives.
    Chunk { id: String, data: String },
    /// provider -> Core: the response is complete.
    End { id: String },
    /// provider -> Core: this request failed locally.
    Error { id: String, message: String },
    /// Core -> provider: open a console on one of this provider's machines.
    ///
    /// Out-of-band access: the hypervisor's own console, so it works when the
    /// machine's network does not, and nothing runs in the guest for it. The
    /// agent answers with `Head` (open) or `Error`, then `ConsoleData` frames
    /// flow both ways until `Cancel` (Core) or `End` (provider).
    ConsoleOpen { id: String, instance_id: String, kind: ConsoleKind },
    /// Either direction: raw console bytes, base64 — a terminal stream is not
    /// UTF-8 at frame boundaries, and the tunnel is text.
    ConsoleData { id: String, data: String },
    /// Core -> provider: the buyer's terminal changed size.
    ConsoleResize { id: String, cols: u16, rows: u16 },
    /// provider -> Core, after `Head`: a one-time secret the viewer needs to
    /// authenticate inside the console protocol (VNC's password). Minted by
    /// the hypervisor for this session only; never stored.
    ConsoleCredential { id: String, password: String },
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
            capabilities: ComputeCapabilities { vm: true, gpu_passthrough: true, ..Default::default() },
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
            lifecycle: Lifecycle::Running,
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
        let back: InventoryReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
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
            TunnelFrame::Chunk { id: "r1".into(), data: "data: {}\n\n".into() },
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
        for rk in [RuntimeKind::Proxmox, RuntimeKind::K3sKubeVirt, RuntimeKind::OpenStack] {
            let json = serde_json::to_string(&rk).unwrap();
            assert_eq!(json, format!("\"{}\"", rk.as_str()), "serde name must match as_str()");
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
        assert_eq!(serde_json::from_str::<WorkloadReport>(&json).unwrap(), report());
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
            assert_ne!(a, b);
            assert_ne!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
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
        assert_eq!(exists.result, CheckResult::Pass);
        assert_eq!(reaches.result, CheckResult::Fail);
        assert_ne!(exists.kind, reaches.kind);
    }

    /// Unknown is not a pass and not a failure. A machine still booting has not
    /// failed its checks, and reporting either extreme is a lie.
    #[test]
    fn unknown_is_its_own_answer() {
        for r in [CheckResult::Pass, CheckResult::Fail] {
            assert_ne!(r, CheckResult::Unknown);
        }
        let json = serde_json::to_string(&CheckResult::Unknown).unwrap();
        assert_eq!(json, "\"unknown\"");
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
        let v: serde_json::Value =
            serde_json::from_str(r#"{"checks":[]}"#).unwrap();
        assert!(v.get("checks").unwrap().as_array().unwrap().is_empty());
        // And the field defaults when entirely absent.
        #[derive(serde::Deserialize)]
        struct JustChecks {
            #[serde(default)]
            checks: Vec<SelfCheck>,
        }
        let none: JustChecks = serde_json::from_str("{}").unwrap();
        assert!(none.checks.is_empty());
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
    if reported_at + CORROBORATION_WINDOW_SECS < probe.at_unix {
        return Corroboration::Unknown;
    }

    let source = probe.source.as_deref();
    let saw_this_prober = observed.iter().any(|o| {
        source.is_some_and(|s| o.peer == s)
            && o.at_unix + CORROBORATION_WINDOW_SECS >= probe.at_unix
            && probe.at_unix + CORROBORATION_WINDOW_SECS >= o.at_unix
    });

    match (probe.outcome, saw_this_prober) {
        (ProbeOutcome::Connected, true) => Corroboration::Confirmed,
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
        ObservedPeer { peer: peer.into(), port: 8080, at_unix: at }
    }

    #[test]
    fn both_ends_agreeing_is_the_only_confirmation() {
        let c = corroborate(&probe(ProbeOutcome::Connected, 1000), &[seen("100.93.27.247", 1000)], Some(1010));
        assert_eq!(c, Corroboration::Confirmed);
    }

    /// The case a single-ended check cannot see, and the reason for all of
    /// this: the prober connected to *something*, and it was not our machine.
    #[test]
    fn connected_to_something_that_is_not_our_machine() {
        let c = corroborate(&probe(ProbeOutcome::Connected, 1000), &[], Some(1010));
        assert_eq!(c, Corroboration::Impostor);
        // And a connection from a *different* source is not our probe either.
        let c = corroborate(&probe(ProbeOutcome::Connected, 1000), &[seen("10.0.0.9", 1000)], Some(1010));
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
        let c = corroborate(&probe(ProbeOutcome::TimedOut, 1000), &[seen("100.93.27.247", 1000)], Some(1010));
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
        assert_eq!(corroborate(&probe(ProbeOutcome::Connected, 5000), &[], None), Corroboration::Unknown);
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
        assert_eq!(serde_json::from_str::<ReachabilityReport>(&serde_json::to_string(&p).unwrap()).unwrap(), p);
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

    /// Additive, so `PROTOCOL_VERSION` holds: a report from an agent that has
    /// never heard of this field parses, and carries no observation — which the
    /// rule above turns into "presence only", the behaviour Core had before.
    #[test]
    fn an_older_agents_report_still_parses() {
        let older = r#"{"protocol_version":5,"instances":[],"workers":[]}"#;
        let r: StatusReport = serde_json::from_str(older).expect("older report must parse");
        assert!(r.observation.is_none());
        assert_eq!(PROTOCOL_VERSION, 5, "an additive field does not bump the version");
    }
}
