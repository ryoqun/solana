use {
    crossbeam_channel::Sender,
    jsonrpc_core::{BoxFuture, ErrorCode, MetaIoHandler, Metadata, Result},
    jsonrpc_core_client::{transports::ipc, RpcError},
    jsonrpc_derive::rpc,
    jsonrpc_ipc_server::{
        tokio::sync::oneshot::channel as oneshot_channel, RequestContext, ServerBuilder,
    },
    log::*,
    serde::{de::Deserializer, Deserialize, Serialize},
    solana_accounts_db::accounts_index::AccountIndex,
    solana_core::{
        admin_rpc_post_init::AdminRpcRequestMetadataPostInit,
        consensus::{tower_storage::TowerStorage, Tower},
        repair::repair_service,
        validator::ValidatorStartProgress,
    },
    solana_geyser_plugin_manager::GeyserPluginManagerRequest,
    solana_gossip::contact_info::{ContactInfo, Protocol, SOCKET_ADDR_UNSPECIFIED},
    solana_rpc::rpc::verify_pubkey,
    solana_rpc_client_api::{config::RpcAccountIndex, custom_error::RpcCustomError},
    solana_sdk::{
        exit::Exit,
        pubkey::Pubkey,
        signature::{read_keypair_file, Keypair, Signer},
    },
    std::{
        collections::{HashMap, HashSet},
        error,
        fmt::{self, Display},
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{Arc, RwLock},
        thread::{self, Builder},
        time::{Duration, SystemTime},
    },
    tokio::runtime::Runtime,
};

#[derive(Clone)]
pub struct AdminRpcRequestMetadata {
    pub rpc_addr: Option<SocketAddr>,
    pub start_time: SystemTime,
    pub start_progress: Arc<RwLock<ValidatorStartProgress>>,
    pub validator_exit: Arc<RwLock<Exit>>,
    pub authorized_voter_keypairs: Arc<RwLock<Vec<Arc<Keypair>>>>,
    pub tower_storage: Arc<dyn TowerStorage>,
    pub staked_nodes_overrides: Arc<RwLock<HashMap<Pubkey, u64>>>,
    pub post_init: Arc<RwLock<Option<AdminRpcRequestMetadataPostInit>>>,
    pub rpc_to_plugin_manager_sender: Option<Sender<GeyserPluginManagerRequest>>,
}

impl Metadata for AdminRpcRequestMetadata {}

impl AdminRpcRequestMetadata {
    fn with_post_init<F, R>(&self, func: F) -> Result<R>
    where
        F: FnOnce(&AdminRpcRequestMetadataPostInit) -> Result<R>,
    {
        if let Some(post_init) = self.post_init.read().unwrap().as_ref() {
            func(post_init)
        } else {
            Err(jsonrpc_core::error::Error::invalid_params(
                "Retry once validator start up is complete",
            ))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminRpcContactInfo {
    pub id: String,
    pub gossip: SocketAddr,
    pub tvu: SocketAddr,
    pub tvu_quic: SocketAddr,
    pub serve_repair_quic: SocketAddr,
    pub tpu: SocketAddr,
    pub tpu_forwards: SocketAddr,
    pub tpu_vote: SocketAddr,
    pub rpc: SocketAddr,
    pub rpc_pubsub: SocketAddr,
    pub serve_repair: SocketAddr,
    pub last_updated_timestamp: u64,
    pub shred_version: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminRpcRepairWhitelist {
    pub whitelist: Vec<Pubkey>,
}

impl From<ContactInfo> for AdminRpcContactInfo {
    fn from(node: ContactInfo) -> Self {
        macro_rules! unwrap_socket {
            ($name:ident) => {
                node.$name().unwrap_or(SOCKET_ADDR_UNSPECIFIED)
            };
            ($name:ident, $protocol:expr) => {
                node.$name($protocol).unwrap_or(SOCKET_ADDR_UNSPECIFIED)
            };
        }
        Self {
            id: node.pubkey().to_string(),
            last_updated_timestamp: node.wallclock(),
            gossip: unwrap_socket!(gossip),
            tvu: unwrap_socket!(tvu, Protocol::UDP),
            tvu_quic: unwrap_socket!(tvu, Protocol::QUIC),
            serve_repair_quic: unwrap_socket!(serve_repair, Protocol::QUIC),
            tpu: unwrap_socket!(tpu, Protocol::UDP),
            tpu_forwards: unwrap_socket!(tpu_forwards, Protocol::UDP),
            tpu_vote: unwrap_socket!(tpu_vote),
            rpc: unwrap_socket!(rpc),
            rpc_pubsub: unwrap_socket!(rpc_pubsub),
            serve_repair: unwrap_socket!(serve_repair, Protocol::UDP),
            shred_version: node.shred_version(),
        }
    }
}

impl Display for AdminRpcContactInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Identity: {}", self.id)?;
        writeln!(f, "Gossip: {}", self.gossip)?;
        writeln!(f, "TVU: {}", self.tvu)?;
        writeln!(f, "TVU QUIC: {}", self.tvu_quic)?;
        writeln!(f, "TPU: {}", self.tpu)?;
        writeln!(f, "TPU Forwards: {}", self.tpu_forwards)?;
        writeln!(f, "TPU Votes: {}", self.tpu_vote)?;
        writeln!(f, "RPC: {}", self.rpc)?;
        writeln!(f, "RPC Pubsub: {}", self.rpc_pubsub)?;
        writeln!(f, "Serve Repair: {}", self.serve_repair)?;
        writeln!(f, "Last Updated Timestamp: {}", self.last_updated_timestamp)?;
        writeln!(f, "Shred Version: {}", self.shred_version)
    }
}

impl Display for AdminRpcRepairWhitelist {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Repair whitelist: {:?}", &self.whitelist)
    }
}

#[rpc]
pub trait AdminRpc {
    type Metadata;

    #[rpc(meta, name = "exit")]
    fn exit(&self, meta: Self::Metadata) -> Result<()>;

    #[rpc(meta, name = "reloadPlugin")]
    fn reload_plugin(
        &self,
        meta: Self::Metadata,
        name: String,
        config_file: String,
    ) -> BoxFuture<Result<()>>;

    #[rpc(meta, name = "unloadPlugin")]
    fn unload_plugin(&self, meta: Self::Metadata, name: String) -> BoxFuture<Result<()>>;

    #[rpc(meta, name = "loadPlugin")]
    fn load_plugin(&self, meta: Self::Metadata, config_file: String) -> BoxFuture<Result<String>>;

    #[rpc(meta, name = "listPlugins")]
    fn list_plugins(&self, meta: Self::Metadata) -> BoxFuture<Result<Vec<String>>>;

    #[rpc(meta, name = "rpcAddress")]
    fn rpc_addr(&self, meta: Self::Metadata) -> Result<Option<SocketAddr>>;

    #[rpc(name = "setLogFilter")]
    fn set_log_filter(&self, filter: String) -> Result<()>;

    #[rpc(meta, name = "startTime")]
    fn start_time(&self, meta: Self::Metadata) -> Result<SystemTime>;

    #[rpc(meta, name = "startProgress")]
    fn start_progress(&self, meta: Self::Metadata) -> Result<ValidatorStartProgress>;

    #[rpc(meta, name = "addAuthorizedVoter")]
    fn add_authorized_voter(&self, meta: Self::Metadata, keypair_file: String) -> Result<()>;

    #[rpc(meta, name = "addAuthorizedVoterFromBytes")]
    fn add_authorized_voter_from_bytes(&self, meta: Self::Metadata, keypair: Vec<u8>)
        -> Result<()>;

    #[rpc(meta, name = "removeAllAuthorizedVoters")]
    fn remove_all_authorized_voters(&self, meta: Self::Metadata) -> Result<()>;

    #[rpc(meta, name = "setIdentity")]
    fn set_identity(
        &self,
        meta: Self::Metadata,
        keypair_file: String,
        require_tower: bool,
    ) -> Result<()>;

    #[rpc(meta, name = "setIdentityFromBytes")]
    fn set_identity_from_bytes(
        &self,
        meta: Self::Metadata,
        identity_keypair: Vec<u8>,
        require_tower: bool,
    ) -> Result<()>;

    #[rpc(meta, name = "setStakedNodesOverrides")]
    fn set_staked_nodes_overrides(&self, meta: Self::Metadata, path: String) -> Result<()>;

    #[rpc(meta, name = "contactInfo")]
    fn contact_info(&self, meta: Self::Metadata) -> Result<AdminRpcContactInfo>;

    #[rpc(meta, name = "repairShredFromPeer")]
    fn repair_shred_from_peer(
        &self,
        meta: Self::Metadata,
        pubkey: Option<Pubkey>,
        slot: u64,
        shred_index: u64,
    ) -> Result<()>;

    #[rpc(meta, name = "repairWhitelist")]
    fn repair_whitelist(&self, meta: Self::Metadata) -> Result<AdminRpcRepairWhitelist>;

    #[rpc(meta, name = "setRepairWhitelist")]
    fn set_repair_whitelist(&self, meta: Self::Metadata, whitelist: Vec<Pubkey>) -> Result<()>;

    #[rpc(meta, name = "getSecondaryIndexKeySize")]
    fn get_secondary_index_key_size(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<HashMap<RpcAccountIndex, usize>>;

    #[rpc(meta, name = "setPublicTpuAddress")]
    fn set_public_tpu_address(
        &self,
        meta: Self::Metadata,
        public_tpu_addr: SocketAddr,
    ) -> Result<()>;

    #[rpc(meta, name = "setPublicTpuForwardsAddress")]
    fn set_public_tpu_forwards_address(
        &self,
        meta: Self::Metadata,
        public_tpu_forwards_addr: SocketAddr,
    ) -> Result<()>;
}

pub struct AdminRpcImpl;
impl AdminRpc for AdminRpcImpl {
    type Metadata = AdminRpcRequestMetadata;

    fn exit(&self, meta: Self::Metadata) -> Result<()> {
        debug!("exit admin rpc request received");

        thread::Builder::new()
            .name("solProcessExit".into())
            .spawn(move || {
                // Delay exit signal until this RPC request completes, otherwise the caller of `exit` might
                // receive a confusing error as the validator shuts down before a response is sent back.
                thread::sleep(Duration::from_millis(100));

                warn!("validator exit requested");
                meta.validator_exit.write().unwrap().exit();

                // TODO: Debug why Exit doesn't always cause the validator to fully exit
                // (rocksdb background processing or some other stuck thread perhaps?).
                //
                // If the process is still alive after five seconds, exit harder
                thread::sleep(Duration::from_secs(5));
                warn!("validator exit timeout");
                std::process::exit(0);
            })
            .unwrap();
        Ok(())
    }

    fn reload_plugin(
        &self,
        meta: Self::Metadata,
        name: String,
        config_file: String,
    ) -> BoxFuture<Result<()>> {
        Box::pin(async move {
            // Construct channel for plugin to respond to this particular rpc request instance
            let (response_sender, response_receiver) = oneshot_channel();

            // Send request to plugin manager if there is a geyser service
            if let Some(ref rpc_to_manager_sender) = meta.rpc_to_plugin_manager_sender {
                rpc_to_manager_sender
                    .send(GeyserPluginManagerRequest::ReloadPlugin {
                        name,
                        config_file,
                        response_sender,
                    })
                    .expect("GeyerPluginService should never drop request receiver");
            } else {
                return Err(jsonrpc_core::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "No geyser plugin service".to_string(),
                    data: None,
                });
            }

            // Await response from plugin manager
            response_receiver
                .await
                .expect("GeyerPluginService's oneshot sender shouldn't drop early")
        })
    }

    fn load_plugin(&self, meta: Self::Metadata, config_file: String) -> BoxFuture<Result<String>> {
        Box::pin(async move {
            // Construct channel for plugin to respond to this particular rpc request instance
            let (response_sender, response_receiver) = oneshot_channel();

            // Send request to plugin manager if there is a geyser service
            if let Some(ref rpc_to_manager_sender) = meta.rpc_to_plugin_manager_sender {
                rpc_to_manager_sender
                    .send(GeyserPluginManagerRequest::LoadPlugin {
                        config_file,
                        response_sender,
                    })
                    .expect("GeyerPluginService should never drop request receiver");
            } else {
                return Err(jsonrpc_core::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "No geyser plugin service".to_string(),
                    data: None,
                });
            }

            // Await response from plugin manager
            response_receiver
                .await
                .expect("GeyerPluginService's oneshot sender shouldn't drop early")
        })
    }

    fn unload_plugin(&self, meta: Self::Metadata, name: String) -> BoxFuture<Result<()>> {
        Box::pin(async move {
            // Construct channel for plugin to respond to this particular rpc request instance
            let (response_sender, response_receiver) = oneshot_channel();

            // Send request to plugin manager if there is a geyser service
            if let Some(ref rpc_to_manager_sender) = meta.rpc_to_plugin_manager_sender {
                rpc_to_manager_sender
                    .send(GeyserPluginManagerRequest::UnloadPlugin {
                        name,
                        response_sender,
                    })
                    .expect("GeyerPluginService should never drop request receiver");
            } else {
                return Err(jsonrpc_core::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "No geyser plugin service".to_string(),
                    data: None,
                });
            }

            // Await response from plugin manager
            response_receiver
                .await
                .expect("GeyerPluginService's oneshot sender shouldn't drop early")
        })
    }

    fn list_plugins(&self, meta: Self::Metadata) -> BoxFuture<Result<Vec<String>>> {
        Box::pin(async move {
            // Construct channel for plugin to respond to this particular rpc request instance
            let (response_sender, response_receiver) = oneshot_channel();

            // Send request to plugin manager
            if let Some(ref rpc_to_manager_sender) = meta.rpc_to_plugin_manager_sender {
                rpc_to_manager_sender
                    .send(GeyserPluginManagerRequest::ListPlugins { response_sender })
                    .expect("GeyerPluginService should never drop request receiver");
            } else {
                return Err(jsonrpc_core::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "No geyser plugin service".to_string(),
                    data: None,
                });
            }

            // Await response from plugin manager
            response_receiver
                .await
                .expect("GeyerPluginService's oneshot sender shouldn't drop early")
        })
    }

    fn rpc_addr(&self, meta: Self::Metadata) -> Result<Option<SocketAddr>> {
        debug!("rpc_addr admin rpc request received");
        Ok(meta.rpc_addr)
    }

    fn set_log_filter(&self, filter: String) -> Result<()> {
        debug!("set_log_filter admin rpc request received");
        solana_logger::setup_with(&filter);
        Ok(())
    }

    fn start_time(&self, meta: Self::Metadata) -> Result<SystemTime> {
        debug!("start_time admin rpc request received");
        Ok(meta.start_time)
    }

    fn start_progress(&self, meta: Self::Metadata) -> Result<ValidatorStartProgress> {
        debug!("start_progress admin rpc request received");
        Ok(*meta.start_progress.read().unwrap())
    }

    fn add_authorized_voter(&self, meta: Self::Metadata, keypair_file: String) -> Result<()> {
        debug!("add_authorized_voter request received");

        let authorized_voter = read_keypair_file(keypair_file)
            .map_err(|err| jsonrpc_core::error::Error::invalid_params(format!("{err}")))?;

        AdminRpcImpl::add_authorized_voter_keypair(meta, authorized_voter)
    }

    fn add_authorized_voter_from_bytes(
        &self,
        meta: Self::Metadata,
        keypair: Vec<u8>,
    ) -> Result<()> {
        debug!("add_authorized_voter_from_bytes request received");

        let authorized_voter = Keypair::from_bytes(&keypair).map_err(|err| {
            jsonrpc_core::error::Error::invalid_params(format!(
                "Failed to read authorized voter keypair from provided byte array: {err}"
            ))
        })?;

        AdminRpcImpl::add_authorized_voter_keypair(meta, authorized_voter)
    }

    fn remove_all_authorized_voters(&self, meta: Self::Metadata) -> Result<()> {
        debug!("remove_all_authorized_voters received");
        meta.authorized_voter_keypairs.write().unwrap().clear();
        Ok(())
    }

    fn set_identity(
        &self,
        meta: Self::Metadata,
        keypair_file: String,
        require_tower: bool,
    ) -> Result<()> {
        debug!("set_identity request received");

        let identity_keypair = read_keypair_file(&keypair_file).map_err(|err| {
            jsonrpc_core::error::Error::invalid_params(format!(
                "Failed to read identity keypair from {keypair_file}: {err}"
            ))
        })?;

        AdminRpcImpl::set_identity_keypair(meta, identity_keypair, require_tower)
    }

    fn set_identity_from_bytes(
        &self,
        meta: Self::Metadata,
        identity_keypair: Vec<u8>,
        require_tower: bool,
    ) -> Result<()> {
        debug!("set_identity_from_bytes request received");

        let identity_keypair = Keypair::from_bytes(&identity_keypair).map_err(|err| {
            jsonrpc_core::error::Error::invalid_params(format!(
                "Failed to read identity keypair from provided byte array: {err}"
            ))
        })?;

        AdminRpcImpl::set_identity_keypair(meta, identity_keypair, require_tower)
    }

    fn set_staked_nodes_overrides(&self, meta: Self::Metadata, path: String) -> Result<()> {
        let loaded_config = load_staked_nodes_overrides(&path)
            .map_err(|err| {
                error!(
                    "Failed to load staked nodes overrides from {}: {}",
                    &path, err
                );
                jsonrpc_core::error::Error::internal_error()
            })?
            .staked_map_id;
        let mut write_staked_nodes = meta.staked_nodes_overrides.write().unwrap();
        write_staked_nodes.clear();
        write_staked_nodes.extend(loaded_config);
        info!("Staked nodes overrides loaded from {}", path);
        debug!("overrides map: {:?}", write_staked_nodes);
        Ok(())
    }

    fn contact_info(&self, meta: Self::Metadata) -> Result<AdminRpcContactInfo> {
        meta.with_post_init(|post_init| Ok(post_init.cluster_info.my_contact_info().into()))
    }

    fn repair_shred_from_peer(
        &self,
        meta: Self::Metadata,
        pubkey: Option<Pubkey>,
        slot: u64,
        shred_index: u64,
    ) -> Result<()> {
        debug!("repair_shred_from_peer request received");

        meta.with_post_init(|post_init| {
            repair_service::RepairService::request_repair_for_shred_from_peer(
                post_init.cluster_info.clone(),
                post_init.cluster_slots.clone(),
                pubkey,
                slot,
                shred_index,
                &post_init.repair_socket.clone(),
                post_init.outstanding_repair_requests.clone(),
            );
            Ok(())
        })
    }

    fn repair_whitelist(&self, meta: Self::Metadata) -> Result<AdminRpcRepairWhitelist> {
        debug!("repair_whitelist request received");

        meta.with_post_init(|post_init| {
            let whitelist: Vec<_> = post_init
                .repair_whitelist
                .read()
                .unwrap()
                .iter()
                .copied()
                .collect();
            Ok(AdminRpcRepairWhitelist { whitelist })
        })
    }

    fn set_repair_whitelist(&self, meta: Self::Metadata, whitelist: Vec<Pubkey>) -> Result<()> {
        debug!("set_repair_whitelist request received");

        let whitelist: HashSet<Pubkey> = whitelist.into_iter().collect();
        meta.with_post_init(|post_init| {
            *post_init.repair_whitelist.write().unwrap() = whitelist;
            warn!(
                "Repair whitelist set to {:?}",
                &post_init.repair_whitelist.read().unwrap()
            );
            Ok(())
        })
    }

    fn get_secondary_index_key_size(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<HashMap<RpcAccountIndex, usize>> {
        debug!(
            "get_secondary_index_key_size rpc request received: {:?}",
            pubkey_str
        );
        let index_key = verify_pubkey(&pubkey_str)?;
        meta.with_post_init(|post_init| {
            let bank = post_init.bank_forks.read().unwrap().root_bank();

            // Take ref to enabled AccountSecondaryIndexes
            let enabled_account_indexes = &bank.accounts().accounts_db.account_indexes;

            // Exit if secondary indexes are not enabled
            if enabled_account_indexes.is_empty() {
                debug!("get_secondary_index_key_size: secondary index not enabled.");
                return Ok(HashMap::new());
            };

            // Make sure the requested key is not explicitly excluded
            if !enabled_account_indexes.include_key(&index_key) {
                return Err(RpcCustomError::KeyExcludedFromSecondaryIndex {
                    index_key: index_key.to_string(),
                }
                .into());
            }

            // Grab a ref to the AccountsDbfor this Bank
            let accounts_index = &bank.accounts().accounts_db.accounts_index;

            // Find the size of the key in every index where it exists
            let found_sizes = enabled_account_indexes
                .indexes
                .iter()
                .filter_map(|index| {
                    accounts_index
                        .get_index_key_size(index, &index_key)
                        .map(|size| (rpc_account_index_from_account_index(index), size))
                })
                .collect::<HashMap<_, _>>();

            // Note: Will return an empty HashMap if no keys are found.
            if found_sizes.is_empty() {
                debug!("get_secondary_index_key_size: key not found in the secondary index.");
            }
            Ok(found_sizes)
        })
    }

    fn set_public_tpu_address(
        &self,
        meta: Self::Metadata,
        public_tpu_addr: SocketAddr,
    ) -> Result<()> {
        debug!("set_public_tpu_address rpc request received: {public_tpu_addr}");

        meta.with_post_init(|post_init| {
            post_init
                .cluster_info
                .my_contact_info()
                .tpu(Protocol::UDP)
                .map_err(|err| {
                    error!(
                        "The public TPU address isn't being published. The node is likely in \
                         repair mode. See help for --restricted-repair-only-mode for more \
                         information. {err}"
                    );
                    jsonrpc_core::error::Error::internal_error()
                })?;
            post_init
                .cluster_info
                .set_tpu(public_tpu_addr)
                .map_err(|err| {
                    error!("Failed to set public TPU address to {public_tpu_addr}: {err}");
                    jsonrpc_core::error::Error::internal_error()
                })?;
            let my_contact_info = post_init.cluster_info.my_contact_info();
            warn!(
                "Public TPU addresses set to {:?} (udp) and {:?} (quic)",
                my_contact_info.tpu(Protocol::UDP),
                my_contact_info.tpu(Protocol::QUIC),
            );
            Ok(())
        })
    }

    fn set_public_tpu_forwards_address(
        &self,
        meta: Self::Metadata,
        public_tpu_forwards_addr: SocketAddr,
    ) -> Result<()> {
        debug!("set_public_tpu_forwards_address rpc request received: {public_tpu_forwards_addr}");

        meta.with_post_init(|post_init| {
            post_init
                .cluster_info
                .my_contact_info()
                .tpu_forwards(Protocol::UDP)
                .map_err(|err| {
                    error!(
                        "The public TPU Forwards address isn't being published. The node is \
                         likely in repair mode. See help for --restricted-repair-only-mode for \
                         more information. {err}"
                    );
                    jsonrpc_core::error::Error::internal_error()
                })?;
            post_init
                .cluster_info
                .set_tpu_forwards(public_tpu_forwards_addr)
                .map_err(|err| {
                    error!("Failed to set public TPU address to {public_tpu_forwards_addr}: {err}");
                    jsonrpc_core::error::Error::internal_error()
                })?;
            let my_contact_info = post_init.cluster_info.my_contact_info();
            warn!(
                "Public TPU Forwards addresses set to {:?} (udp) and {:?} (quic)",
                my_contact_info.tpu_forwards(Protocol::UDP),
                my_contact_info.tpu_forwards(Protocol::QUIC),
            );
            Ok(())
        })
    }
}

impl AdminRpcImpl {
    fn add_authorized_voter_keypair(
        meta: AdminRpcRequestMetadata,
        authorized_voter: Keypair,
    ) -> Result<()> {
        let mut authorized_voter_keypairs = meta.authorized_voter_keypairs.write().unwrap();

        if authorized_voter_keypairs
            .iter()
            .any(|x| x.pubkey() == authorized_voter.pubkey())
        {
            Err(jsonrpc_core::error::Error::invalid_params(
                "Authorized voter already present",
            ))
        } else {
            authorized_voter_keypairs.push(Arc::new(authorized_voter));
            Ok(())
        }
    }

    fn set_identity_keypair(
        meta: AdminRpcRequestMetadata,
        identity_keypair: Keypair,
        require_tower: bool,
    ) -> Result<()> {
        meta.with_post_init(|post_init| {
            if require_tower {
                let _ = Tower::restore(meta.tower_storage.as_ref(), &identity_keypair.pubkey())
                    .map_err(|err| {
                        jsonrpc_core::error::Error::invalid_params(format!(
                            "Unable to load tower file for identity {}: {}",
                            identity_keypair.pubkey(),
                            err
                        ))
                    })?;
            }

            for n in post_init.notifies.iter() {
                if let Err(err) = n.update_key(&identity_keypair) {
                    error!("Error updating network layer keypair: {err}");
                }
            }

            solana_metrics::set_host_id(identity_keypair.pubkey().to_string());
            post_init
                .cluster_info
                .set_keypair(Arc::new(identity_keypair));
            warn!("Identity set to {}", post_init.cluster_info.id());
            Ok(())
        })
    }
}

fn rpc_account_index_from_account_index(account_index: &AccountIndex) -> RpcAccountIndex {
    match account_index {
        AccountIndex::ProgramId => RpcAccountIndex::ProgramId,
        AccountIndex::SplTokenOwner => RpcAccountIndex::SplTokenOwner,
        AccountIndex::SplTokenMint => RpcAccountIndex::SplTokenMint,
    }
}

// Start the Admin RPC interface
pub fn run(ledger_path: &Path, metadata: AdminRpcRequestMetadata) {
    let admin_rpc_path = admin_rpc_path(ledger_path);

    let event_loop = tokio::runtime::Builder::new_multi_thread()
        .thread_name("solAdminRpcEl")
        .worker_threads(3) // Three still seems like a lot, and better than the default of available core count
        .enable_all()
        .build()
        .unwrap();

    Builder::new()
        .name("solAdminRpc".to_string())
        .spawn(move || {
            let mut io = MetaIoHandler::default();
            io.extend_with(AdminRpcImpl.to_delegate());

            let validator_exit = metadata.validator_exit.clone();
            let server = ServerBuilder::with_meta_extractor(io, move |_req: &RequestContext| {
                metadata.clone()
            })
            .event_loop_executor(event_loop.handle().clone())
            .start(&format!("{}", admin_rpc_path.display()));

            match server {
                Err(err) => {
                    warn!("Unable to start admin rpc service: {:?}", err);
                }
                Ok(server) => {
                    info!("started admin rpc service!");
                    let close_handle = server.close_handle();
                    validator_exit
                        .write()
                        .unwrap()
                        .register_exit(Box::new(move || {
                            close_handle.close();
                        }));

                    server.wait();
                }
            }
        })
        .unwrap();
}

fn admin_rpc_path(ledger_path: &Path) -> PathBuf {
    #[cfg(target_family = "windows")]
    {
        // More information about the wackiness of pipe names over at
        // https://docs.microsoft.com/en-us/windows/win32/ipc/pipe-names
        if let Some(ledger_filename) = ledger_path.file_name() {
            PathBuf::from(format!(
                "\\\\.\\pipe\\{}-admin.rpc",
                ledger_filename.to_string_lossy()
            ))
        } else {
            PathBuf::from("\\\\.\\pipe\\admin.rpc")
        }
    }
    #[cfg(not(target_family = "windows"))]
    {
        ledger_path.join("admin.rpc")
    }
}

// Connect to the Admin RPC interface
pub async fn connect(ledger_path: &Path) -> std::result::Result<gen_client::Client, RpcError> {
    let admin_rpc_path = admin_rpc_path(ledger_path);
    if !admin_rpc_path.exists() {
        Err(RpcError::Client(format!(
            "{} does not exist",
            admin_rpc_path.display()
        )))
    } else {
        ipc::connect::<_, gen_client::Client>(&format!("{}", admin_rpc_path.display())).await
    }
}

pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name("solAdminRpcRt")
        .enable_all()
        .build()
        .expect("new tokio runtime")
}

#[derive(Default, Deserialize, Clone)]
pub struct StakedNodesOverrides {
    #[serde(deserialize_with = "deserialize_pubkey_map")]
    pub staked_map_id: HashMap<Pubkey, u64>,
}

pub fn deserialize_pubkey_map<'de, D>(des: D) -> std::result::Result<HashMap<Pubkey, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let container: HashMap<String, u64> = serde::Deserialize::deserialize(des)?;
    let mut container_typed: HashMap<Pubkey, u64> = HashMap::new();
    for (key, value) in container.iter() {
        let typed_key = Pubkey::try_from(key.as_str())
            .map_err(|_| serde::de::Error::invalid_type(serde::de::Unexpected::Map, &"PubKey"))?;
        container_typed.insert(typed_key, *value);
    }
    Ok(container_typed)
}

pub fn load_staked_nodes_overrides(
    path: &String,
) -> std::result::Result<StakedNodesOverrides, Box<dyn error::Error>> {
    debug!("Loading staked nodes overrides configuration from {}", path);
    if Path::new(&path).exists() {
        let file = std::fs::File::open(path)?;
        Ok(serde_yaml::from_reader(file)?)
    } else {
        Err(format!("Staked nodes overrides provided '{path}' a non-existing file path.").into())
    }
}
