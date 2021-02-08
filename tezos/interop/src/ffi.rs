// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;
use std::sync::Once;

use crypto::hash::{ContextHash, ProtocolHash};
use ocaml_interop::{ocaml_frame, to_ocaml, OCaml, OCamlRuntime, ToOCaml};

use tezos_api::ffi::*;
use tezos_api::ocaml_conv::FfiPath;

use crate::runtime;

type TzResult<T> = Result<T, TezosErrorTrace>;

mod tezos_ffi {
    use ocaml_interop::{ocaml, OCamlBytes, OCamlInt, OCamlInt32, OCamlList};

    use tezos_api::{
        ffi::{
            ApplyBlockRequest, ApplyBlockResponse, BeginApplicationRequest,
            BeginApplicationResponse, BeginConstructionRequest, HelpersPreapplyBlockRequest,
            HelpersPreapplyResponse, PrevalidatorWrapper, ProtocolRpcError, ProtocolRpcRequest,
            ProtocolRpcResponse, ValidateOperationRequest, ValidateOperationResponse,
        },
        ocaml_conv::{OCamlOperationHash, OCamlProtocolHash},
    };
    use tezos_messages::p2p::encoding::operations_for_blocks::Path;

    use super::TzResult;

    ocaml! {
        pub fn apply_block(
            apply_block_request: ApplyBlockRequest
        ) -> TzResult<ApplyBlockResponse>;
        pub fn begin_application(
            begin_application_request: BeginApplicationRequest
        ) -> TzResult<BeginApplicationResponse>;
        pub fn begin_construction(
            begin_construction_request: BeginConstructionRequest
        ) -> TzResult<PrevalidatorWrapper>;
        pub fn validate_operation(
            validate_operation_request: ValidateOperationRequest
        ) -> TzResult<ValidateOperationResponse>;
        pub fn call_protocol_rpc(
            request: ProtocolRpcRequest
        ) -> Result<ProtocolRpcResponse, ProtocolRpcError>;
        pub fn helpers_preapply_operations(
            request: ProtocolRpcRequest
        ) -> TzResult<HelpersPreapplyResponse>;
        pub fn helpers_preapply_block(
            request: HelpersPreapplyBlockRequest
        ) -> TzResult<HelpersPreapplyResponse>;
        pub fn change_runtime_configuration(
            log_enabled: bool, debug_mode: bool
        );
        pub fn init_protocol_context(
            data_dir: String,
            genesis: (OCamlBytes, OCamlBytes, OCamlBytes),
            protocol_override: (OCamlList<(OCamlInt32, OCamlBytes)>,
                                OCamlList<(OCamlBytes, OCamlBytes)>),
            configuration: (bool, bool, bool),
            sandbox_json_patch_context: Option<(OCamlBytes, OCamlBytes)>
        ) -> TzResult<(OCamlList<OCamlBytes>, Option<OCamlBytes>)>;
        pub fn genesis_result_data(
            context_hash: OCamlBytes,
            chain_id: OCamlBytes,
            protocol_hash: OCamlBytes,
            genesis_max_operations_ttl: OCamlInt
        ) -> TzResult<(OCamlBytes, OCamlBytes, OCamlBytes)>;
        pub fn decode_context_data(
            protocol_hash: OCamlBytes,
            key: OCamlList<OCamlBytes>,
            data: OCamlBytes
        ) -> TzResult<Option<OCamlBytes>>;
        pub fn compute_path(
            request: OCamlList<OCamlList<OCamlOperationHash>>
        ) -> TzResult<OCamlList<Path>>;
        pub fn assert_encoding_for_protocol_data(
            protocol_hash: OCamlProtocolHash,
            protocol_data: OCamlBytes
        ) -> TzResult<()>;
    }
}

/// Initializes the ocaml runtime and the tezos-ffi callback mechanism.
pub fn setup() -> OCamlRuntime {
    static INIT: Once = Once::new();
    let ocaml_runtime = OCamlRuntime::init();

    INIT.call_once(|| {
        tezos_interop_callback::initialize_callbacks();
    });

    ocaml_runtime
}

pub fn shutdown() {
    runtime::shutdown()
}

pub fn change_runtime_configuration(
    settings: TezosRuntimeConfiguration,
) -> Result<(), TezosRuntimeConfigurationError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        tezos_ffi::change_runtime_configuration(
            rt,
            &OCaml::of_bool(settings.log_enabled),
            &OCaml::of_bool(settings.debug_mode),
        );
    })
    .map_err(
        |p| TezosRuntimeConfigurationError::ChangeConfigurationError {
            message: p.to_string(),
        },
    )
}

pub fn init_protocol_context(
    storage_data_dir: String,
    genesis: GenesisChain,
    protocol_overrides: ProtocolOverrides,
    commit_genesis: bool,
    enable_testchain: bool,
    readonly: bool,
    patch_context: Option<PatchContext>,
) -> Result<InitProtocolContextResult, TezosStorageInitError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(
            rt,
            (
                genesis_tuple,
                protocol_overrides_tuple,
                configuration,
                patch_context_tuple,
                storage_data_dir_root
            ),
            {
                // genesis configuration
                let genesis_tuple = to_ocaml!(
                    rt,
                    (genesis.time, genesis.block, genesis.protocol),
                    genesis_tuple
                );

                // protocol overrides
                let protocol_overrides_tuple = to_ocaml!(
                    rt,
                    (
                        protocol_overrides.user_activated_upgrades,
                        protocol_overrides.user_activated_protocol_overrides,
                    ),
                    protocol_overrides_tuple
                );

                // configuration
                let configuration = to_ocaml!(
                    rt,
                    (commit_genesis, enable_testchain, readonly),
                    configuration
                );

                // patch context
                let patch_context_tuple = to_ocaml!(
                    rt,
                    patch_context.map(|pc| (pc.key, pc.json)),
                    patch_context_tuple
                );

                let storage_data_dir = to_ocaml!(rt, storage_data_dir, storage_data_dir_root);
                let result = tezos_ffi::init_protocol_context(
                    rt,
                    storage_data_dir,
                    genesis_tuple,
                    protocol_overrides_tuple,
                    configuration,
                    patch_context_tuple,
                )
                .to_result();

                match result {
                    Ok(result) => {
                        let (supported_protocol_hashes, genesis_commit_hash): (
                            Vec<RustBytes>,
                            Option<RustBytes>,
                        ) = result.to_rust();
                        let supported_protocol_hashes = supported_protocol_hashes
                            .into_iter()
                            .map(|h| ProtocolHash::try_from(h))
                            .collect::<Result<_, _>>()?;
                        let genesis_commit_hash = genesis_commit_hash
                            .map(|bytes| ContextHash::try_from(bytes.to_vec()))
                            .map_or(Ok(None), |r| r.map(Some))?;
                        Ok(InitProtocolContextResult {
                            supported_protocol_hashes,
                            genesis_commit_hash,
                        })
                    }
                    Err(e) => Err(TezosStorageInitError::from(e.to_rust::<TezosErrorTrace>())),
                }
            }
        )
    })
    .unwrap_or_else(|p| {
        Err(TezosStorageInitError::InitializeError {
            message: p.to_string(),
        })
    })
}

pub fn genesis_result_data(
    context_hash: RustBytes,
    chain_id: RustBytes,
    protocol_hash: RustBytes,
    genesis_max_operations_ttl: u16,
) -> Result<CommitGenesisResult, GetDataError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(
            rt,
            (context_hash_root, chain_id_root, protocol_hash_root),
            {
                let context_hash = to_ocaml!(rt, context_hash, context_hash_root);
                let chain_id = to_ocaml!(rt, chain_id, chain_id_root);
                let protocol_hash = to_ocaml!(rt, protocol_hash, protocol_hash_root);
                let genesis_max_operations_ttl = OCaml::of_i32(genesis_max_operations_ttl as i32);

                let result = tezos_ffi::genesis_result_data(
                    rt,
                    context_hash,
                    chain_id,
                    protocol_hash,
                    &genesis_max_operations_ttl,
                )
                .to_result();
                match result {
                    Ok(result) => {
                        let (
                            block_header_proto_json,
                            block_header_proto_metadata_json,
                            operations_proto_metadata_json,
                        ) = result.to_rust();
                        Ok(CommitGenesisResult {
                            block_header_proto_json,
                            block_header_proto_metadata_json,
                            operations_proto_metadata_json,
                        })
                    }
                    Err(e) => Err(GetDataError::from(e.to_rust::<TezosErrorTrace>())),
                }
            }
        )
    })
    .unwrap_or_else(|p| {
        Err(GetDataError::ReadError {
            message: p.to_string(),
        })
    })
}

macro_rules! call_helper {
    (tezos_ffi::$f:ident($request:ident)) => {
        runtime::execute(move |rt: &mut OCamlRuntime| {
            ocaml_frame!(rt, (request_root), {
                let ocaml_request = to_ocaml!(rt, $request, request_root);
                let result = tezos_ffi::$f(rt, ocaml_request).to_result();
                match result {
                    Ok(response) => Ok(response.to_rust()),
                    Err(e) => Err(CallError::from(e.to_rust::<TezosErrorTrace>())),
                }
            })
        })
        .unwrap_or_else(|p| {
            Err(CallError::FailedToCall {
                error_id: "@OCamlBlockPanic".to_owned(),
                trace_message: p.to_string(),
            })
        })
    };
}

/// Applies block to context
pub fn apply_block(request: ApplyBlockRequest) -> Result<ApplyBlockResponse, CallError> {
    call_helper!(tezos_ffi::apply_block(request))
}

/// Begin construction initializes prevalidator and context for new operations based on current head
pub fn begin_application(
    request: BeginApplicationRequest,
) -> Result<BeginApplicationResponse, CallError> {
    call_helper!(tezos_ffi::begin_application(request))
}

/// Begin construction initializes prevalidator and context for new operations based on current head
pub fn begin_construction(
    request: BeginConstructionRequest,
) -> Result<PrevalidatorWrapper, CallError> {
    call_helper!(tezos_ffi::begin_construction(request))
}

/// Validate operation - used with prevalidator for validation of operation
pub fn validate_operation(
    request: ValidateOperationRequest,
) -> Result<ValidateOperationResponse, CallError> {
    call_helper!(tezos_ffi::validate_operation(request))
}

pub fn call_protocol_rpc(
    request: ProtocolRpcRequest,
) -> Result<ProtocolRpcResponse, ProtocolRpcError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (request_root), {
            let request = to_ocaml!(rt, request, request_root);
            let result = tezos_ffi::call_protocol_rpc(rt, request);
            // TODO: should call_protocol_rpc be Result<_, OCamlErrorTrace> instead?
            // looks like not, but verify and add a catch-all for unhandled cases
            result.to_rust()
        })
    })
    .unwrap_or_else(|p| Err(ProtocolRpcError::FailedToCallProtocolRpc(p.to_string())))
}

/// Call helpers_preapply_operations shell service
pub fn helpers_preapply_operations(
    request: ProtocolRpcRequest,
) -> Result<HelpersPreapplyResponse, CallError> {
    call_helper!(tezos_ffi::helpers_preapply_operations(request))
}

/// Call helpers_preapply_block shell service
pub fn helpers_preapply_block(
    request: HelpersPreapplyBlockRequest,
) -> Result<HelpersPreapplyResponse, CallError> {
    call_helper!(tezos_ffi::helpers_preapply_block(request))
}

/// Call compute path
pub fn compute_path(request: ComputePathRequest) -> Result<ComputePathResponse, CallError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (operations_root), {
            let operations = to_ocaml!(rt, request.operations, operations_root);
            let result = tezos_ffi::compute_path(rt, operations).to_result();
            match result {
                Ok(response) => {
                    let operations_hashes_path: Vec<FfiPath> = response.to_rust();
                    let operations_hashes_path = operations_hashes_path
                        .into_iter()
                        .map(|path| path.0)
                        .collect();
                    Ok(ComputePathResponse {
                        operations_hashes_path,
                    })
                }
                Err(e) => Err(CallError::from(e.to_rust::<TezosErrorTrace>())),
            }
        })
    })
    .unwrap_or_else(|p| {
        Err(CallError::FailedToCall {
            error_id: "@exception".to_owned(),
            trace_message: p.to_string(),
        })
    })
}

pub fn decode_context_data(
    protocol_hash: RustBytes,
    key: Vec<String>,
    data: RustBytes,
) -> Result<Option<String>, ContextDataError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (protocol_hash_root, key_list_root, data_root), {
            let protocol_hash = to_ocaml!(rt, protocol_hash, protocol_hash_root);
            let key_list = to_ocaml!(rt, key, key_list_root);
            let data = to_ocaml!(rt, data, data_root);

            let result =
                tezos_ffi::decode_context_data(rt, protocol_hash, key_list, data).to_result();

            match result {
                Ok(decoded_data) => Ok(decoded_data.to_rust()),
                Err(e) => Err(ContextDataError::from(e.to_rust::<TezosErrorTrace>())),
            }
        })
    })
    .unwrap_or_else(|p| {
        Err(ContextDataError::DecodeError {
            message: p.to_string(),
        })
    })
}

pub fn assert_encoding_for_protocol_data(
    protocol_hash: RustBytes,
    protocol_data: RustBytes,
) -> Result<(), ProtocolDataError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (protocol_hash_root, data_root), {
            let protocol_hash = ProtocolHash::try_from(protocol_hash)?;
            let protocol_hash = to_ocaml!(rt, protocol_hash, protocol_hash_root);
            let data = to_ocaml!(rt, protocol_data, data_root);

            let result =
                tezos_ffi::assert_encoding_for_protocol_data(rt, protocol_hash, data).to_result();

            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(ProtocolDataError::from(e.to_rust::<TezosErrorTrace>())),
            }
        })
    })
    .unwrap_or_else(|p| {
        Err(ProtocolDataError::DecodeError {
            message: p.to_string(),
        })
    })
}
