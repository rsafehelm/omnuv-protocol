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
pub const PROTOCOL_VERSION: u32 = 2;

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
    #[serde(default)]
    pub images: Vec<String>,
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
    /// The overlay gateways this provider should be running: one per buyer
    /// network that has a machine here. A gateway whose network has no machine
    /// left on this provider is listed with `Lifecycle::Deleted` until the
    /// agent reports it gone.
    #[serde(default)]
    pub gateways: Vec<GatewaySpec>,
}

/// A provider's overlay gateway for one buyer network.
///
/// A small VM, one per buyer network on the provider, and the only kind of
/// overlay peer there. It exists so that the overlay client never runs on the
/// hypervisor: a WireGuard interface writing routes there could cover the
/// management address and take the host — and every guest on it — off the
/// network.
///
/// It carries one buyer's traffic only. It sits on a segment of its own with
/// that buyer's machines, holds that buyer's key, and answers that buyer's
/// names; two tenants on one provider never share a segment or a gateway.
/// Nothing in the Omnuv control plane depends on it, so a broken gateway must
/// never make a healthy provider look offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewaySpec {
    /// How long Core is still prepared to wait for this gateway, in seconds.
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
    /// The buyer network this gateway serves. The driver derives the network's
    /// segment on this provider from it, and puts the gateway and the
    /// network's machines there.
    #[serde(default)]
    pub network_id: String,
    /// Where the overlay control plane lives. The agent does not reach Core
    /// through this; it is handed to the gateway's overlay client.
    pub management_url: String,
    /// Enrols the gateway into exactly one buyer's network. Issued by Core,
    /// never minted by the provider.
    pub setup_key: String,
    /// The project slice this gateway routes. The agent must advertise this and
    /// nothing wider — never a supernet, never a default route.
    pub advertise_cidr: Option<String>,
    /// The gateway's own address on the provider's marketplace bridge, e.g.
    /// `10.200.4.1/24`. It is the next hop for every buyer machine here.
    #[serde(default)]
    pub slice_address: Option<String>,
    /// Public SSH keys for operator access to the gateway itself.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    /// The whole project's name → address map, served as `.internal` by the
    /// gateway's resolver. Every provider's gateway carries every name, which
    /// is what keeps placement invisible: a buyer machine asks its own
    /// gateway and gets an answer for a machine anywhere in the project.
    #[serde(default)]
    pub dns_records: Vec<DnsRecord>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GatewayState {
    Pending,
    Deploying,
    Ready,
    Error,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatus {
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
    pub state: GatewayState,
    #[serde(default)]
    pub local_id: Option<String>,
    /// The address the gateway holds on the overlay, once it has one.
    #[serde(default)]
    pub overlay_address: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// A buyer's virtual machine, normalized. The driver translates this into
/// runtime-native resources; nothing here names Proxmox, KubeVirt or OpenStack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// provider from it — the same one the network's gateway sits on.
    #[serde(default)]
    pub network_id: String,
    /// e.g. `10.200.4.12`
    pub address: String,
    /// The whole project network, e.g. `10.200.4.0/24`. Reached through the
    /// gateway; the machine is configured with a /32 so that addresses on other
    /// providers are routed rather than assumed to be on this segment.
    pub cidr: String,
    /// The provider's gateway on this network, e.g. `10.200.4.1`.
    pub gateway: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    Running,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub message: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub gateways: Vec<GatewayStatus>,
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
            nodes: vec![NodeInventory {
                local_id: "pve".into(),
                cpu_cores: 16,
                memory_mib: 65536,
                disk_gib: 1000,
                gpus: vec![GpuDevice {
                    local_id: "0000:01:00.0".into(),
                    vendor: "NVIDIA".into(),
                    model: "RTX 4090".into(),
                    vram_mib: 24564,
                }],
            }],
        }
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
