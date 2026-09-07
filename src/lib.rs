//! Public, versioned contract between Omnu Core and Omnu Provider agents.
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
pub const PROTOCOL_VERSION: u32 = 1;

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
    #[serde(default)]
    pub inference_workers: Vec<InferenceWorkerSpec>,
    #[serde(default)]
    pub instances: Vec<InstanceSpec>,
    /// The overlay gateway this provider should be running, if any. `None`
    /// means no buyer here needs one, and an existing gateway is torn down.
    #[serde(default)]
    pub gateway: Option<GatewaySpec>,
}

/// The provider's overlay gateway.
///
/// A small VM that is the only peer on this provider. It exists so that the
/// overlay client never runs on the hypervisor: a WireGuard interface writing
/// routes there could cover the management address and take the host — and
/// every guest on it — off the network.
///
/// It carries buyer traffic only. Nothing in the Omnu control plane depends on
/// it, so a broken gateway must never make a healthy provider look offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewaySpec {
    pub id: String,
    pub lifecycle: Lifecycle,
    /// Where the overlay control plane lives. The agent does not reach Core
    /// through this; it is handed to the gateway's overlay client.
    pub management_url: String,
    /// Enrols the gateway into exactly one buyer's network. Issued by Core,
    /// never minted by the provider.
    pub setup_key: String,
    /// The project slice this gateway routes. The agent must advertise this and
    /// nothing wider — never a supernet, never a default route.
    pub advertise_cidr: Option<String>,
    /// Public SSH keys for operator access to the gateway itself.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
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
    pub id: String,
    pub lifecycle: Lifecycle,
    pub name: String,
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    /// Public SSH keys to inject at first boot. Never a private key.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    #[serde(default)]
    pub gpu_local_ids: Vec<String>,
    /// Set when a reboot has been requested and not yet performed. Carries the
    /// request's identity so the agent can report which one it satisfied and
    /// the same reboot is never applied twice.
    #[serde(default)]
    pub reboot_token: Option<String>,
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
    pub id: String,
    pub state: WorkerState,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub protocol_version: u32,
    #[serde(default)]
    pub workers: Vec<WorkerStatus>,
    #[serde(default)]
    pub instances: Vec<InstanceStatus>,
    #[serde(default)]
    pub gateway: Option<GatewayStatus>,
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
