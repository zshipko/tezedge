// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! Manages connected peers.

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dns_lookup::LookupError;
use futures::lock::Mutex;
use rand::seq::SliceRandom;
use riker::actors::*;
use slog::{debug, info, trace, warn, Logger};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::time::timeout;

use networking::p2p::peer::{bootstrap, Bootstrap, BootstrapOutput, Peer, PeerRef, SendMessage};
use networking::p2p::{
    network_channel::{
        NetworkChannelMsg, NetworkChannelRef, NetworkChannelTopic, PeerBootstrapFailed,
    },
    peer::PeerError,
};
use networking::{LocalPeerInfo, PeerId, ShellCompatibilityVersion};
use tezos_identity::Identity;
use tezos_messages::p2p::encoding::prelude::*;

use crate::shell_channel::{ShellChannelMsg, ShellChannelRef};
use crate::subscription::*;
use crate::PeerConnectionThreshold;

/// Timeout for outgoing connections
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Whitelist all IP addresses after 30 minutes
const WHITELIST_INTERVAL: Duration = Duration::from_secs(1_800);
/// How often to do DNS peer discovery
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);
/// Limit how often we allow to trigger check of a peer count
const CHECK_PEER_COUNT_LIMIT: Duration = Duration::from_secs(5);

/// Check peer threshold
/// Received message instructs this actor to check whether number of connected peers is within desired bounds
#[derive(Clone, Debug)]
pub struct CheckPeerCount;

/// Whitelist all IP address.
#[derive(Clone, Debug)]
pub struct WhitelistAllIpAddresses;

/// Accept incoming peer connection.
#[derive(Clone, Debug)]
pub struct AcceptPeer {
    stream: Arc<Mutex<Option<TcpStream>>>,
    address: SocketAddr,
}

/// Open connection to the remote peer node.
#[derive(Clone, Debug)]
pub struct ConnectToPeer {
    pub address: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct P2p {
    /// Node p2p port
    pub listener_port: u16,
    pub disable_mempool: bool,
    pub private_node: bool,

    pub peer_threshold: PeerConnectionThreshold,

    /// Bootstrap lookup addresses disable/enable
    pub disable_bootstrap_lookup: bool,
    /// Used for lookup with DEFAULT_P2P_PORT_FOR_LOOKUP
    pub bootstrap_lookup_addresses: Vec<(String, u16)>,

    /// Peers (IP:port) which we try to connect all the time
    pub bootstrap_peers: Vec<SocketAddr>,
}

impl P2p {
    pub const DEFAULT_P2P_PORT_FOR_LOOKUP: u16 = 9732;
}

/// This actor is responsible for peer management.
///
/// It monitors number of connected peers. If the number of connected peers is too low it tries to
/// connect to more peers. If the number of connected peers is too high, then randomly selected peers
/// are disconnected.
#[actor(
    CheckPeerCount,
    WhitelistAllIpAddresses,
    AcceptPeer,
    ConnectToPeer,
    NetworkChannelMsg,
    ShellChannelMsg,
    SystemEvent,
    DeadLetter
)]
pub struct PeerManager {
    /// All events generated by the network layer will end up in this channel
    network_channel: NetworkChannelRef,
    /// All events from shell will be published to this channel
    shell_channel: ShellChannelRef,
    /// Tokio runtime
    tokio_executor: Handle,

    /// Peer count threshold
    threshold: PeerConnectionThreshold,
    /// Map of all peers
    peers: HashMap<ActorUri, PeerState>,
    /// List of potential peers to connect to
    potential_peers: HashSet<SocketAddr>,
    /// Bootstrap peer, which we try to connect all the the, if no other peers presents
    bootstrap_addresses: HashSet<(String, u16)>,

    /// Indicates that mempool should be disabled
    disable_mempool: bool,
    /// Indicates that p2p is working in private mode
    private_node: bool,

    /// Local node info covers:
    /// - listener_port - we will listen for incoming connection at this port
    /// - identity
    /// - Network/protocol version
    local_node_info: Arc<LocalPeerInfo>,

    /// Message receiver boolean indicating whether
    /// more connections should be accepted from network
    rx_run: Arc<AtomicBool>,
    /// set of blacklisted IP addresses
    ip_blacklist: HashSet<IpAddr>,
    /// Last time we did DNS peer discovery
    discovery_last: Option<Instant>,
    /// Last time we checked peer count
    check_peer_count_last: Option<Instant>,
    /// Indicates that system is shutting down
    shutting_down: bool,
}

/// Reference to [peer manager](PeerManager) actor.
pub type PeerManagerRef = ActorRef<PeerManagerMsg>;

impl PeerManager {
    pub fn actor(
        sys: &impl ActorRefFactory,
        network_channel: NetworkChannelRef,
        shell_channel: ShellChannelRef,
        tokio_executor: Handle,
        identity: Arc<Identity>,
        shell_compatibility_version: Arc<ShellCompatibilityVersion>,
        p2p_config: P2p,
    ) -> Result<PeerManagerRef, CreateError> {
        sys.actor_of_props::<PeerManager>(
            PeerManager::name(),
            Props::new_args((
                network_channel,
                shell_channel,
                tokio_executor,
                identity,
                shell_compatibility_version,
                p2p_config,
            )),
        )
    }

    /// The `PeerManager` is intended to serve as a singleton actor so that's why
    /// we won't support multiple names per instance.
    fn name() -> &'static str {
        "peer-manager"
    }

    /// Try to discover new remote peers to connect
    fn discover_peers(&mut self, log: &Logger) {
        if self.peers.is_empty()
            || self
                .discovery_last
                .filter(|discovery_last| discovery_last.elapsed() <= DISCOVERY_INTERVAL)
                .is_none()
        {
            self.discovery_last = Some(Instant::now());

            info!(log, "Doing peer DNS lookup"; "bootstrap_addresses" => format!("{:?}", &self.bootstrap_addresses));
            self.process_new_potential_peers(dns_lookup_peers(&self.bootstrap_addresses, &log));
        } else {
            let msg: Arc<PeerMessageResponse> = Arc::new(PeerMessage::Bootstrap.into());
            self.peers.values().for_each(|peer_state| {
                peer_state
                    .peer_id
                    .peer_ref
                    .tell(SendMessage::new(msg.clone()), None)
            });
        }
    }

    fn try_to_connect_to_potential_peers(&mut self, ctx: &Context<PeerManagerMsg>) {
        let num_of_required_peers = self.calculate_count_of_required_peers();
        let mut addresses_to_connect = self
            .potential_peers
            .iter()
            .cloned()
            .collect::<Vec<SocketAddr>>();
        // randomize peers as a security measurement
        addresses_to_connect.shuffle(&mut rand::thread_rng());
        addresses_to_connect
            .drain(0..cmp::min(num_of_required_peers, addresses_to_connect.len()))
            .for_each(|address| {
                self.potential_peers.remove(&address);
                ctx.myself()
                    .tell(ConnectToPeer { address }, ctx.myself().into())
            });
    }

    fn calculate_count_of_required_peers(&mut self) -> usize {
        cmp::max(
            (self.threshold.high + 3 * self.threshold.low) / 4 - self.peers.len(),
            self.threshold.low,
        )
    }

    /// Create new peer actor
    fn create_peer(
        sys: &impl ActorRefFactory,
        network_channel: NetworkChannelRef,
        tokio_executor: Handle,
        info: BootstrapOutput,
    ) -> Result<PeerRef, CreateError> {
        Peer::actor(sys, network_channel, tokio_executor, info)
    }

    /// Check if given ip address is blacklisted to connect to
    fn is_blacklisted(&self, ip_address: &IpAddr) -> bool {
        self.ip_blacklist.contains(ip_address)
    }

    fn blacklist_address(&mut self, address: SocketAddr, reason: String, log: &Logger) {
        info!(log, "Blacklisting IP";
                   "ip" => format!("{}", address.ip()),
                   "reason" => reason,
        );
        self.ip_blacklist.insert(address.ip());

        // TODO: call firewall
    }

    fn blacklist_peer(&mut self, peer_id: Arc<PeerId>, reason: String, actor_system: &ActorSystem) {
        let log = actor_system.log();
        warn!(log, "Blacklisting peer";
                   "peer_uri" => peer_id.peer_ref.uri().to_string(),
                   "peer_id" => peer_id.peer_id_marker.clone(),
                   "reason" => reason.clone(),
        );

        // blacklist
        self.blacklist_address(peer_id.peer_address, reason, &log);

        // stop actor
        actor_system.stop(peer_id.peer_ref.clone());

        // send message
        self.network_channel.tell(
            Publish {
                msg: NetworkChannelMsg::PeerBlacklisted(peer_id),
                topic: NetworkChannelTopic::NetworkEvents.into(),
            },
            None,
        );
    }

    fn trigger_check_peer_count(&mut self, ctx: &Context<PeerManagerMsg>) {
        let should_trigger = self
            .check_peer_count_last
            .map(|check_peer_count_last| check_peer_count_last.elapsed() > CHECK_PEER_COUNT_LIMIT)
            .unwrap_or(true);

        if should_trigger {
            self.check_peer_count_last = Some(Instant::now());
            ctx.myself().tell(CheckPeerCount, None);
        }
    }

    fn process_new_potential_peers<I: IntoIterator<Item = SocketAddr>>(
        &mut self,
        potential_peers: I,
    ) {
        let sock_addresses = potential_peers
            .into_iter()
            .filter(|address: &SocketAddr| !self.is_blacklisted(&address.ip()))
            .collect::<Vec<_>>();

        // we want to make sure, that we dont want to have unlimited potential peers (num_of_required_peers * 10)
        let num_of_max_potential_peers = self.calculate_count_of_required_peers() * 10;

        // collect all
        let mut addresses_to_connect = self
            .potential_peers
            .iter()
            .cloned()
            .collect::<Vec<SocketAddr>>();
        addresses_to_connect.extend(sock_addresses);
        // randomize peers as a security measurement
        addresses_to_connect.shuffle(&mut rand::thread_rng());

        // try to limit
        if addresses_to_connect.len() > num_of_max_potential_peers {
            let count_to_remove = addresses_to_connect.len() - num_of_max_potential_peers;
            for i in 0..count_to_remove {
                addresses_to_connect.remove(i);
            }
        }

        self.potential_peers.clear();
        self.potential_peers.extend(addresses_to_connect);
    }

    fn check_peer_count(&mut self, ctx: &Context<PeerManagerMsg>) {
        let peers_count = self.peers.len();

        if peers_count < self.threshold.low {
            // peer count is too low, try to connect to more peers
            warn!(ctx.system.log(), "Peer count is too low"; "actual" => peers_count, "required" => self.threshold.low);
            if self.potential_peers.len() < self.threshold.low {
                self.discover_peers(&ctx.system.log());
            }
            self.try_to_connect_to_potential_peers(ctx);
        } else if peers_count > self.threshold.high {
            // peer count is too high, disconnect some peers
            warn!(ctx.system.log(), "Peer count is too high. Some peers will be stopped"; "actual" => peers_count, "limit" => self.threshold.high);

            // stop some peers
            self.peers
                .values()
                .take(peers_count - self.threshold.high)
                .for_each(|peer_state| ctx.system.stop(peer_state.peer_id.peer_ref.clone()))
        }

        self.check_peer_count_last = Some(Instant::now());
    }
}

impl
    ActorFactoryArgs<(
        NetworkChannelRef,
        ShellChannelRef,
        Handle,
        Arc<Identity>,
        Arc<ShellCompatibilityVersion>,
        P2p,
    )> for PeerManager
{
    fn create_args(
        (
            network_channel,
            shell_channel,
            tokio_executor,
            identity,
            shell_compatibility_version,
            p2p_config,
        ): (
            NetworkChannelRef,
            ShellChannelRef,
            Handle,
            Arc<Identity>,
            Arc<ShellCompatibilityVersion>,
            P2p,
        ),
    ) -> Self {
        // resolve all bootstrap addresses
        // defaultlly init from bootstrap_peers
        let mut bootstrap_addresses = HashSet::from_iter(
            p2p_config
                .bootstrap_peers
                .iter()
                .map(|addr| (addr.ip().to_string(), addr.port())),
        );

        // if lookup enabled, add also configuted lookup addresses
        if !p2p_config.disable_bootstrap_lookup {
            bootstrap_addresses.extend(p2p_config.bootstrap_lookup_addresses);
        };

        PeerManager {
            network_channel,
            shell_channel,
            tokio_executor,
            bootstrap_addresses,
            threshold: p2p_config.peer_threshold,
            local_node_info: Arc::new(LocalPeerInfo::new(
                p2p_config.listener_port,
                identity,
                shell_compatibility_version,
            )),
            disable_mempool: p2p_config.disable_mempool,
            private_node: p2p_config.private_node,
            rx_run: Arc::new(AtomicBool::new(true)),
            potential_peers: HashSet::new(),
            peers: HashMap::new(),
            ip_blacklist: HashSet::new(),
            discovery_last: None,
            check_peer_count_last: None,
            shutting_down: false,
        }
    }
}

impl Actor for PeerManager {
    type Msg = PeerManagerMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        subscribe_to_actor_terminated(ctx.system.sys_events(), ctx.myself());
        subscribe_to_shell_shutdown(&self.shell_channel, ctx.myself());
        subscribe_to_dead_letters(ctx.system.dead_letters(), ctx.myself());
        subscribe_to_network_commands(&self.network_channel, ctx.myself());

        ctx.schedule::<Self::Msg, _>(
            Duration::from_secs(10),
            Duration::from_secs(15),
            ctx.myself(),
            None,
            CheckPeerCount.into(),
        );
        ctx.schedule::<Self::Msg, _>(
            WHITELIST_INTERVAL,
            WHITELIST_INTERVAL,
            ctx.myself(),
            None,
            WhitelistAllIpAddresses.into(),
        );

        let listener_port = self.local_node_info.listener_port();
        let myself = ctx.myself();
        let rx_run = self.rx_run.clone();
        let log = ctx.system.log();

        // start to listen for incoming p2p connections
        self.tokio_executor.spawn(async move {
            begin_listen_incoming(listener_port, myself, rx_run, &log).await;
        });
    }

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        self.discover_peers(&ctx.system.log());
        self.try_to_connect_to_potential_peers(ctx);
    }

    fn post_stop(&mut self) {
        self.rx_run.store(false, Ordering::Relaxed);
    }

    fn sys_recv(
        &mut self,
        ctx: &Context<Self::Msg>,
        msg: SystemMsg,
        sender: Option<BasicActorRef>,
    ) {
        if let SystemMsg::Event(evt) = msg {
            self.receive(ctx, evt, sender);
        }
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<DeadLetter> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(
        &mut self,
        ctx: &Context<Self::Msg>,
        msg: DeadLetter,
        _sender: Option<BasicActorRef>,
    ) {
        if self.peers.remove(msg.recipient.uri()).is_some() {
            if self.shutting_down {
                return;
            }
            self.trigger_check_peer_count(ctx);
        }
    }
}

impl Receive<ShellChannelMsg> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ShellChannelMsg, _sender: Sender) {
        if let ShellChannelMsg::ShuttingDown(_) = msg {
            unsubscribe_from_dead_letters(ctx.system.dead_letters(), ctx.myself());
            self.shutting_down = true;
            self.rx_run.store(false, Ordering::Release);
        }
    }
}

impl Receive<SystemEvent> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(
        &mut self,
        ctx: &Context<Self::Msg>,
        msg: SystemEvent,
        _sender: Option<BasicActorRef>,
    ) {
        if let SystemEvent::ActorTerminated(evt) = msg {
            if self.peers.remove(evt.actor.uri()).is_some() {
                if self.shutting_down {
                    return;
                }
                self.trigger_check_peer_count(ctx);
            }
        }
    }
}

impl Receive<CheckPeerCount> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, _msg: CheckPeerCount, _: Sender) {
        if self.shutting_down {
            return;
        }
        self.check_peer_count(ctx);
    }
}

impl Receive<NetworkChannelMsg> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: NetworkChannelMsg, _sender: Sender) {
        match msg {
            NetworkChannelMsg::ProcessAdvertisedPeers(peer, message) => {
                // extract potential peers from the advertise message
                info!(ctx.system.log(), "Received advertise message"; "peer_id" => peer.peer_id_marker.clone(), "peers" => format!("{:?}", message.id().join(", ")));
                self.process_new_potential_peers(
                    message
                        .id()
                        .iter()
                        .filter_map(|str_ip_port| str_ip_port.parse().ok())
                        .collect::<Vec<SocketAddr>>(),
                );
            }
            NetworkChannelMsg::SendBootstrapPeers(peer) => {
                // to a bootstrap message we will respond with list of potential peers
                trace!(ctx.system.log(), "Received bootstrap message"; "peer_id" => peer.peer_id_marker.clone());
                let addresses = self
                    .peers
                    .values()
                    .filter(|peer_state| peer_state.peer_id.peer_ref != peer.peer_ref)
                    .map(|peer_state| peer_state.peer_id.peer_address)
                    .collect::<Vec<_>>();
                let msg = Arc::new(AdvertiseMessage::new(&addresses).into());
                peer.peer_ref.tell(SendMessage::new(msg), None);
            }
            NetworkChannelMsg::ProcessFailedBootstrapAddress(PeerBootstrapFailed {
                address,
                potential_peers_to_connect,
            }) => {
                // received message that bootstrap process failed for the peer
                match potential_peers_to_connect {
                    Some(peers) => {
                        self.process_new_potential_peers(
                            peers
                                .iter()
                                .filter_map(|str_ip_port| str_ip_port.parse().ok())
                                .collect::<Vec<SocketAddr>>(),
                        );
                        self.trigger_check_peer_count(ctx);
                    }
                    None => {
                        self.blacklist_address(
                            address,
                            String::from("peer failed at bootstrap process"),
                            &ctx.system.log(),
                        );
                    }
                }
            }
            NetworkChannelMsg::BlacklistPeer(peer_id, reason) => {
                self.blacklist_peer(peer_id, reason, &ctx.system);
            }
            NetworkChannelMsg::ProcessSuccessBootstrapAddress(peer_id) => {
                let _ = self
                    .peers
                    .insert(peer_id.peer_ref.uri().clone(), PeerState { peer_id });
            }
            _ => (),
        }
    }
}

impl Receive<WhitelistAllIpAddresses> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(
        &mut self,
        ctx: &Context<Self::Msg>,
        _msg: WhitelistAllIpAddresses,
        _sender: Sender,
    ) {
        info!(ctx.system.log(), "Whitelisting all IP addresses");
        self.ip_blacklist.clear();
    }
}

impl Receive<ConnectToPeer> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ConnectToPeer, _sender: Sender) {
        // received message instructing this actor that it should open new p2p connection to the remote peer

        if self.is_blacklisted(&msg.address.ip()) {
            debug!(ctx.system.log(), "Peer is blacklisted - will not connect"; "ip" => format!("{}", msg.address.ip()));
            return;
        }

        // spawn non-blocking tcp stream for outgoing connection
        let system = ctx.system.clone();
        let local_node_info = self.local_node_info.clone();
        let network_channel = self.network_channel.clone();
        let tokio_executor = self.tokio_executor.clone();
        let disable_mempool = self.disable_mempool;
        let private_node = self.private_node;

        self.tokio_executor.spawn(async move {
            debug!(system.log(), "(Outgoing) Connecting to IP"; "ip" => msg.address);
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(&msg.address)).await {
                Ok(Ok(stream)) => {
                    debug!(system.log(), "(Outgoing) Connection to peer successful, so start bootstrapping"; "incoming" => false, "ip" => msg.address);
                    match bootstrap(Bootstrap::outgoing(stream, msg.address.clone(), disable_mempool, private_node), local_node_info, &system.log()).await {
                        Ok(bootstrap_output) => {
                            match Self::create_peer(&system, network_channel.clone(), tokio_executor, bootstrap_output) {
                                Ok(_peer) => (),
                                Err(e) => {
                                    warn!(system.log(), "(Outgoing) Connection failed to create peer actor"; "ip" => format!("{}", msg.address.ip()), "reason" => format!("{}", e))
                                }
                            }
                        },
                        Err(err) => {
                            warn!(system.log(), "(Outgoing) Connection to peer failed"; "incoming" => false, "reason" => format!("{}", &err), "ip" => &msg.address);
                            failed_bootstrap_peer(err, msg.address, network_channel);
                        },
                    }
                }
                Ok(Err(e)) => {
                    info!(system.log(), "(Outgoing) Connection to peer failed"; "ip" => msg.address, "reason" => format!("{:?}", e));
                }
                Err(_) => {
                    info!(system.log(), "(Outgoing) Connection timed out"; "ip" => msg.address);
                }
            }
        });
    }
}

impl Receive<AcceptPeer> for PeerManager {
    type Msg = PeerManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: AcceptPeer, _sender: Sender) {
        if self.is_blacklisted(&msg.address.ip()) {
            warn!(ctx.system.log(), "Peer is blacklisted - will not accept connection"; "ip" => format!("{}", msg.address.ip()));
        } else if self.peers.len() < self.threshold.high {
            debug!(ctx.system.log(), "Connection from"; "ip" => msg.address);

            let system = ctx.system.clone();
            let local_node_info = self.local_node_info.clone();
            let network_channel = self.network_channel.clone();
            let tokio_executor = self.tokio_executor.clone();
            let disable_mempool = self.disable_mempool;
            let private_node = self.private_node;

            self.tokio_executor.spawn(async move {
                debug!(system.log(), "Bootstrapping"; "incoming" => true, "ip" => &msg.address);
                match bootstrap(Bootstrap::incoming(msg.stream, msg.address.clone(), disable_mempool, private_node), local_node_info, &system.log()).await {
                    Ok(bootstrap_output) => {
                        match Self::create_peer(&system, network_channel.clone(), tokio_executor, bootstrap_output) {
                            Ok(_peer) => (),
                            Err(e) => {
                                warn!(system.log(), "Failed to process connection from peer - create peer actor error"; "ip" => format!("{}", msg.address.ip()), "reason" => format!("{}", e));
                            }
                        }
                    },
                    Err(err) => {
                        warn!(system.log(), "Connection to peer failed"; "incoming" => true, "reason" => format!("{}", &err), "ip" => &msg.address);
                        failed_bootstrap_peer(err, msg.address, network_channel);
                    },
                }
            });
        } else {
            debug!(
                ctx.system.log(),
                "Cannot accept incoming peer connection because peer limit was reached"
            );
            drop(msg.stream); // not needed, just wanted to be explicit here
        }
    }
}

fn failed_bootstrap_peer(
    err: PeerError,
    peer_address: SocketAddr,
    network_channel: NetworkChannelRef,
) {
    let potential_peers = match err {
        PeerError::NackWithMotiveReceived { nack_info } => {
            Some(nack_info.potential_peers_to_connect().clone())
        }
        _ => None,
    };

    // notify that peer failed at bootstrap process
    network_channel.tell(
        Publish {
            msg: NetworkChannelMsg::ProcessFailedBootstrapAddress(PeerBootstrapFailed {
                address: peer_address,
                potential_peers_to_connect: potential_peers,
            }),
            topic: NetworkChannelTopic::NetworkCommands.into(),
        },
        None,
    );
}

/// Start to listen for incoming connections indefinitely.
async fn begin_listen_incoming(
    listener_port: u16,
    peer_manager: PeerManagerRef,
    rx_run: Arc<AtomicBool>,
    log: &Logger,
) {
    let listener_address = format!("0.0.0.0:{}", listener_port)
        .parse::<SocketAddr>()
        .expect("Failed to parse listener address");
    let listener = TcpListener::bind(&listener_address)
        .await
        .expect("Failed to bind to address");
    info!(log, "Start to listen for incoming p2p connections"; "port" => listener_port);

    while rx_run.load(Ordering::Acquire) {
        if let Ok((stream, address)) = listener.accept().await {
            if rx_run.load(Ordering::Acquire) {
                peer_manager.tell(
                    AcceptPeer {
                        stream: Arc::new(Mutex::new(Some(stream))),
                        address,
                    },
                    None,
                );
            }
        }
    }

    info!(log, "Stop listening for incoming p2p connections"; "port" => listener_port);
}

/// Do DNS lookup for collection of names and create collection of socket addresses
fn dns_lookup_peers(
    bootstrap_addresses: &HashSet<(String, u16)>,
    log: &Logger,
) -> HashSet<SocketAddr> {
    let mut resolved_peers = HashSet::new();
    for (address, port) in bootstrap_addresses {
        match resolve_dns_name_to_peer_address(address, *port) {
            Ok(peers) => resolved_peers.extend(&peers),
            Err(e) => {
                warn!(log, "DNS lookup failed"; "address" => address, "reason" => format!("{:?}", e))
            }
        }
    }
    resolved_peers
}

/// Try to resolve common peer name into Socket Address representation
fn resolve_dns_name_to_peer_address(
    address: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, LookupError> {
    // filter just for [`AI_SOCKTYPE SOCK_STREAM`]
    let hints = dns_lookup::AddrInfoHints {
        socktype: i32::from(dns_lookup::SockType::Stream),
        ..dns_lookup::AddrInfoHints::default()
    };

    let addrs =
        dns_lookup::getaddrinfo(Some(address), Some(port.to_string().as_str()), Some(hints))?
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .filter(|info: &dns_lookup::AddrInfo| {
                // filter just IP_NET and IP_NET6 addresses
                dns_lookup::AddrFamily::Inet.eq(&info.address)
                    || dns_lookup::AddrFamily::Inet6.eq(&info.address)
            })
            .map(|info: dns_lookup::AddrInfo| {
                // convert to uniform IPv6 format
                match &info.sockaddr {
                    SocketAddr::V4(ipv4) => {
                        // convert ipv4 to ipv6
                        SocketAddr::new(IpAddr::V6(ipv4.ip().to_ipv6_mapped()), ipv4.port())
                    }
                    SocketAddr::V6(_) => info.sockaddr,
                }
            })
            .collect();
    Ok(addrs)
}

/// Holds information about a specific peer.
struct PeerState {
    /// Reference to peer actor
    peer_id: Arc<PeerId>,
}
