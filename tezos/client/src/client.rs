// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use crypto::hash::{ChainId, ContextHash, ProtocolHash};
use tezos_api::ffi::{
    ApplyBlockError, ApplyBlockRequest, ApplyBlockResponse, BeginApplicationError,
    BeginApplicationRequest, BeginApplicationResponse, BeginConstructionError,
    BeginConstructionRequest, CommitGenesisResult, ComputePathError, ComputePathRequest,
    ComputePathResponse, ContextDataError, GenesisChain, GetDataError, HelpersPreapplyBlockRequest,
    HelpersPreapplyError, HelpersPreapplyResponse, InitProtocolContextResult, PatchContext,
    PrevalidatorWrapper, ProtocolDataError, ProtocolOverrides, ProtocolRpcError,
    ProtocolRpcRequest, ProtocolRpcResponse, TezosRuntimeConfiguration,
    TezosRuntimeConfigurationError, TezosStorageInitError, ValidateOperationError,
    ValidateOperationRequest, ValidateOperationResponse,
};
use tezos_interop::ffi;

/// Override runtime configuration for OCaml runtime
pub fn change_runtime_configuration(
    settings: TezosRuntimeConfiguration,
) -> Result<(), TezosRuntimeConfigurationError> {
    ffi::change_runtime_configuration(settings).map_err(|e| {
        TezosRuntimeConfigurationError::ChangeConfigurationError {
            message: format!("FFI 'change_runtime_configuration' failed! Reason: {:?}", e),
        }
    })
}

/// Initializes context for Tezos ocaml protocol
pub fn init_protocol_context(
    storage_data_dir: String,
    genesis: GenesisChain,
    protocol_overrides: ProtocolOverrides,
    commit_genesis: bool,
    enable_testchain: bool,
    readonly: bool,
    patch_context: Option<PatchContext>,
) -> Result<InitProtocolContextResult, TezosStorageInitError> {
    ffi::init_protocol_context(
        storage_data_dir,
        genesis,
        protocol_overrides,
        commit_genesis,
        enable_testchain,
        readonly,
        patch_context,
    ).map_err(|e| {
        TezosStorageInitError::InitializeError {
            message: format!("FFI 'init_protocol_context' failed! Initialization of Tezos context failed, this storage is required, we can do nothing without that! Reason: {:?}", e)
        }
    })
}

/// Gets data for genesis
pub fn genesis_result_data(
    context_hash: &ContextHash,
    chain_id: &ChainId,
    protocol_hash: &ProtocolHash,
    genesis_max_operations_ttl: u16,
) -> Result<CommitGenesisResult, GetDataError> {
    ffi::genesis_result_data(
        context_hash.as_ref().clone(),
        chain_id.as_ref().clone(),
        protocol_hash.as_ref().clone(),
        genesis_max_operations_ttl,
    )
    .map_err(|e| GetDataError::ReadError {
        message: format!("FFI 'genesis_result_data' failed! Reason: {:?}", e),
    })
}

/// Applies new block to Tezos ocaml storage, means:
/// - block and operations are decoded by the protocol
/// - block and operations data are correctly stored in Tezos chain/storage
/// - new current head is evaluated
/// - returns validation_result.message
pub fn apply_block(request: ApplyBlockRequest) -> Result<ApplyBlockResponse, ApplyBlockError> {
    // check operations count by validation_pass
    if (request.block_header.validation_pass() as usize) != request.operations.len() {
        return Err(ApplyBlockError::IncompleteOperations {
            expected: request.block_header.validation_pass() as usize,
            actual: request.operations.len(),
        });
    }

    ffi::apply_block(request).map_err(ApplyBlockError::from)
}

/// Begin application
pub fn begin_application(
    request: BeginApplicationRequest,
) -> Result<BeginApplicationResponse, BeginApplicationError> {
    ffi::begin_application(request).map_err(BeginApplicationError::from)
}

/// Begin construction
pub fn begin_construction(
    request: BeginConstructionRequest,
) -> Result<PrevalidatorWrapper, BeginConstructionError> {
    ffi::begin_construction(request).map_err(BeginConstructionError::from)
}

/// Validate operation
pub fn validate_operation(
    request: ValidateOperationRequest,
) -> Result<ValidateOperationResponse, ValidateOperationError> {
    ffi::validate_operation(request).map_err(ValidateOperationError::from)
}

/// Call protocol rpc - general service
pub fn call_protocol_rpc(
    request: ProtocolRpcRequest,
) -> Result<ProtocolRpcResponse, ProtocolRpcError> {
    ffi::call_protocol_rpc(request)
}

/// Call compute path
/// TODO: TE-207 Implement in Rust
pub fn compute_path(request: ComputePathRequest) -> Result<ComputePathResponse, ComputePathError> {
    ffi::compute_path(request).map_err(|e| ComputePathError::PathError {
        message: format!("Path computation failed! Reason: {:?}", e),
    })
}

/// Call helpers_preapply_operations shell service
pub fn helpers_preapply_operations(
    request: ProtocolRpcRequest,
) -> Result<HelpersPreapplyResponse, HelpersPreapplyError> {
    ffi::helpers_preapply_operations(request).map_err(HelpersPreapplyError::from)
}

/// Call helpers_preapply_block shell service
pub fn helpers_preapply_block(
    request: HelpersPreapplyBlockRequest,
) -> Result<HelpersPreapplyResponse, HelpersPreapplyError> {
    ffi::helpers_preapply_block(request).map_err(HelpersPreapplyError::from)
}

/// Decode protocoled context data
pub fn decode_context_data(
    protocol_hash: ProtocolHash,
    key: Vec<String>,
    data: Vec<u8>,
) -> Result<Option<String>, ContextDataError> {
    ffi::decode_context_data(protocol_hash.into(), key, data).map_err(|e| {
        ContextDataError::DecodeError {
            message: format!("FFI 'decode_context_data' failed! Reason: {:?}", e),
        }
    })
}

/// Decode protocoled context data
pub fn assert_encoding_for_protocol_data(
    protocol_hash: ProtocolHash,
    protocol_data: Vec<u8>,
) -> Result<(), ProtocolDataError> {
    ffi::assert_encoding_for_protocol_data(protocol_hash.into(), protocol_data).map_err(|e| {
        ProtocolDataError::DecodeError {
            message: format!(
                "FFI 'assert_encoding_for_protocol_data' failed! Reason: {:?}",
                e
            ),
        }
    })
}

/// Shutdown the OCaml runtime
pub fn shutdown_runtime() {
    ffi::shutdown()
}
