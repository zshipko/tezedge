// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::fmt::Debug;
/// Rust implementation of messages required for Rust <-> OCaml FFI communication.
use std::{convert::TryFrom, fmt};

use derive_builder::Builder;
use failure::Fail;
use serde::{Deserialize, Serialize};

use crypto::hash::{
    BlockHash, BlockMetadataHash, ChainId, ContextHash, FromBytesError, OperationHash,
    OperationMetadataHash, OperationMetadataListListHash, ProtocolHash,
};
use tezos_messages::base::rpc_support::{RpcJsonMap, UniversalValue};
use tezos_messages::p2p::binary_message::{MessageHash, MessageHashError};
use tezos_messages::p2p::encoding::block_header::{display_fitness, Fitness};
use tezos_messages::p2p::encoding::prelude::{
    BlockHeader, Operation, OperationsForBlocksMessage, Path,
};

pub type RustBytes = Vec<u8>;

/// Genesis block information structure
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GenesisChain {
    pub time: String,
    pub block: String,
    pub protocol: String,
}

/// Voted protocol overrides
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProtocolOverrides {
    pub user_activated_upgrades: Vec<(i32, String)>,
    pub user_activated_protocol_overrides: Vec<(String, String)>,
}

impl ProtocolOverrides {
    pub fn user_activated_upgrades_to_rpc_json(&self) -> Vec<RpcJsonMap> {
        self.user_activated_upgrades
            .iter()
            .map(|(level, protocol)| {
                let mut json = RpcJsonMap::new();
                json.insert("level", UniversalValue::num(*level));
                json.insert(
                    "replacement_protocol",
                    UniversalValue::string(protocol.to_string()),
                );
                json
            })
            .collect::<Vec<RpcJsonMap>>()
    }

    pub fn user_activated_protocol_overrides_to_rpc_json(&self) -> Vec<RpcJsonMap> {
        self.user_activated_protocol_overrides
            .iter()
            .map(|(replaced_protocol, replacement_protocol)| {
                let mut json = RpcJsonMap::new();
                json.insert(
                    "replaced_protocol",
                    UniversalValue::string(replaced_protocol.to_string()),
                );
                json.insert(
                    "replacement_protocol",
                    UniversalValue::string(replacement_protocol.to_string()),
                );
                json
            })
            .collect::<Vec<RpcJsonMap>>()
    }
}

/// Patch_context key json
#[derive(Clone, Serialize, Deserialize)]
pub struct PatchContext {
    pub key: String,
    pub json: String,
}

impl fmt::Debug for PatchContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(key: {}, json: {})", &self.key, &self.json)
    }
}

/// Test chain information
#[derive(Debug, Serialize, Deserialize)]
pub struct TestChain {
    pub chain_id: RustBytes,
    pub protocol_hash: RustBytes,
    pub expiration_date: String,
}

/// Holds configuration for OCaml runtime - e.g. arguments which are passed to OCaml and can be change in runtime
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TezosRuntimeConfiguration {
    pub log_enabled: bool,
    pub debug_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct ApplyBlockRequest {
    pub chain_id: ChainId,
    pub block_header: BlockHeader,
    pub pred_header: BlockHeader,

    pub max_operations_ttl: i32,
    pub operations: Vec<Vec<Operation>>,

    pub predecessor_block_metadata_hash: Option<BlockMetadataHash>,
    pub predecessor_ops_metadata_hash: Option<OperationMetadataListListHash>,
}

impl ApplyBlockRequest {
    pub fn convert_operations(
        block_operations: Vec<OperationsForBlocksMessage>,
    ) -> Vec<Vec<Operation>> {
        block_operations.into_iter().map(|ops| ops.into()).collect()
    }
}

/// Application block result
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ApplyBlockResponse {
    pub validation_result_message: String,
    pub context_hash: ContextHash,
    pub block_header_proto_json: String,
    pub block_header_proto_metadata_json: String,
    pub operations_proto_metadata_json: String,
    pub max_operations_ttl: i32,
    pub last_allowed_fork_level: i32,
    pub forking_testchain: bool,
    pub forking_testchain_data: Option<ForkingTestchainData>,
    pub block_metadata_hash: Option<BlockMetadataHash>,
    pub ops_metadata_hashes: Option<Vec<Vec<OperationMetadataHash>>>,
    // TODO: TE-207 - not needed, can be calculated from ops_metadata_hashes
    /// Note: This is calculated from ops_metadata_hashes - we need this in request
    ///       This is calculated as merkle tree hash, like operation paths
    pub ops_metadata_hash: Option<OperationMetadataListListHash>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct PrevalidatorWrapper {
    pub chain_id: ChainId,
    pub protocol: ProtocolHash,
    pub context_fitness: Option<Fitness>,
}

impl fmt::Debug for PrevalidatorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrevalidatorWrapper[chain_id: {}, protocol: {}, context_fitness: {}]",
            self.chain_id.to_base58_check(),
            self.protocol.to_base58_check(),
            match &self.context_fitness {
                Some(fitness) => display_fitness(fitness),
                None => "-none-".to_string(),
            },
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct BeginApplicationRequest {
    pub chain_id: ChainId,
    pub pred_header: BlockHeader,
    pub block_header: BlockHeader,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct BeginApplicationResponse {
    pub result: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct BeginConstructionRequest {
    pub chain_id: ChainId,
    pub predecessor: BlockHeader,
    pub protocol_data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct ValidateOperationRequest {
    pub prevalidator: PrevalidatorWrapper,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct ValidateOperationResponse {
    pub prevalidator: PrevalidatorWrapper,
    pub result: ValidateOperationResult,
}

pub type OperationProtocolDataJson = String;
pub type ErrorListJson = String;

#[derive(Serialize, Deserialize, Clone, Builder, PartialEq)]
pub struct OperationProtocolDataJsonWithErrorListJson {
    pub protocol_data_json: OperationProtocolDataJson,
    pub error_json: ErrorListJson,
}

impl fmt::Debug for OperationProtocolDataJsonWithErrorListJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[error_json: {}, protocol_data_json: (-stripped-)]",
            &self.error_json,
        )
    }
}

trait HasOperationHash {
    fn operation_hash(&self) -> &OperationHash;
}

#[derive(Serialize, Deserialize, Clone, Builder, PartialEq)]
pub struct Applied {
    pub hash: OperationHash,
    pub protocol_data_json: OperationProtocolDataJson,
}

impl HasOperationHash for Applied {
    fn operation_hash(&self) -> &OperationHash {
        &self.hash
    }
}

impl fmt::Debug for Applied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[hash: {}, protocol_data_json: {}]",
            self.hash.to_base58_check(),
            &self.protocol_data_json
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Builder, PartialEq)]
pub struct Errored {
    pub hash: OperationHash,
    pub is_endorsement: Option<bool>,
    pub protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson,
}

impl HasOperationHash for Errored {
    fn operation_hash(&self) -> &OperationHash {
        &self.hash
    }
}

impl fmt::Debug for Errored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[hash: {}, protocol_data_json_with_error_json: {:?}]",
            self.hash.to_base58_check(),
            &self.protocol_data_json_with_error_json
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Default)]
pub struct ValidateOperationResult {
    pub applied: Vec<Applied>,
    pub refused: Vec<Errored>,
    pub branch_refused: Vec<Errored>,
    pub branch_delayed: Vec<Errored>,
    // TODO: outedate?
}

impl ValidateOperationResult {
    /// Merges result with new one, and returns `true/false` if something was changed
    pub fn merge(&mut self, new_result: ValidateOperationResult) -> bool {
        let mut changed = Self::merge_items(&mut self.applied, new_result.applied);
        changed |= Self::merge_items(&mut self.refused, new_result.refused);
        changed |= Self::merge_items(&mut self.branch_refused, new_result.branch_refused);
        changed |= Self::merge_items(&mut self.branch_delayed, new_result.branch_delayed);
        changed
    }

    fn merge_items<ITEM: HasOperationHash>(
        result_items: &mut Vec<ITEM>,
        new_items: Vec<ITEM>,
    ) -> bool {
        let mut changed = false;
        let mut added = false;

        for new_item in new_items {
            // check if present
            let old_value = result_items
                .iter()
                .position(|old_item| old_item.operation_hash().eq(new_item.operation_hash()));

            // replace or add
            if let Some(idx) = old_value {
                // replace
                result_items[idx] = new_item;
                changed |= true;
            } else {
                // add
                result_items.push(new_item);
                added |= true;
            }
        }

        added || changed
    }
}

/// Init protocol context result
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct InitProtocolContextResult {
    pub supported_protocol_hashes: Vec<ProtocolHash>,
    /// Presents only if was genesis commited to context
    pub genesis_commit_hash: Option<ContextHash>,
}

impl fmt::Debug for InitProtocolContextResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let genesis_commit_hash = match &self.genesis_commit_hash {
            Some(hash) => hash.to_base58_check(),
            None => "-none-".to_string(),
        };
        let supported_protocol_hashes = self
            .supported_protocol_hashes
            .iter()
            .map(|ph| ph.to_base58_check())
            .collect::<Vec<String>>();
        write!(
            f,
            "genesis_commit_hash: {}, supported_protocol_hashes: {:?}",
            &genesis_commit_hash, &supported_protocol_hashes
        )
    }
}

/// Commit genesis result
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitGenesisResult {
    pub block_header_proto_json: String,
    pub block_header_proto_metadata_json: String,
    pub operations_proto_metadata_json: String,
}

/// Forking test chain data
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ForkingTestchainData {
    pub forking_block_hash: BlockHash,
    pub test_chain_id: ChainId,
}

/// Represents a trace of errors produced by Tezos.
///
/// `head_error_id` is the id of the main error in the trace, useful for mapping into a Rust error.
/// `trace_json` is json of the trace.
pub struct TezosErrorTrace {
    pub head_error_id: String,
    pub trace_json: String,
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum CallError {
    #[fail(display = "Failed to call - message: {:?}!", trace_message)]
    FailedToCall {
        error_id: String,
        trace_message: String,
    },
    #[fail(display = "Invalid request data - message: {}!", message)]
    InvalidRequestData { message: String },
    #[fail(display = "Invalid response data - message: {}!", message)]
    InvalidResponseData { message: String },
}

impl From<TezosErrorTrace> for CallError {
    fn from(error: TezosErrorTrace) -> Self {
        CallError::FailedToCall {
            error_id: error.head_error_id.clone(),
            trace_message: error.trace_json,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail)]
pub enum TezosRuntimeConfigurationError {
    #[fail(display = "Change OCaml settings failed, message: {}!", message)]
    ChangeConfigurationError { message: String },
}

impl From<TezosErrorTrace> for TezosRuntimeConfigurationError {
    fn from(error: TezosErrorTrace) -> Self {
        TezosRuntimeConfigurationError::ChangeConfigurationError {
            message: error.trace_json,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail)]
pub enum TezosStorageInitError {
    #[fail(display = "OCaml storage init failed, message: {}!", message)]
    InitializeError { message: String },
}

impl From<TezosErrorTrace> for TezosStorageInitError {
    fn from(error: TezosErrorTrace) -> Self {
        TezosStorageInitError::InitializeError {
            message: error.trace_json,
        }
    }
}

impl From<FromBytesError> for TezosStorageInitError {
    fn from(error: FromBytesError) -> Self {
        TezosStorageInitError::InitializeError {
            message: format!("Error constructing hash from bytes: {:?}", error),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail)]
pub enum GetDataError {
    #[fail(display = "OCaml failed to get data, message: {}!", message)]
    ReadError { message: String },
}

impl From<TezosErrorTrace> for GetDataError {
    fn from(error: TezosErrorTrace) -> Self {
        GetDataError::ReadError {
            message: error.trace_json,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum ApplyBlockError {
    #[fail(
        display = "Incomplete operations, exptected: {}, has actual: {}!",
        expected, actual
    )]
    IncompleteOperations { expected: usize, actual: usize },
    #[fail(display = "Failed to apply block - message: {}!", message)]
    FailedToApplyBlock { message: String },
    #[fail(
        display = "Unknown predecessor context - try to apply predecessor at first message: {}!",
        message
    )]
    UnknownPredecessorContext { message: String },
    #[fail(display = "Predecessor does not match - message: {}!", message)]
    PredecessorMismatch { message: String },
    #[fail(display = "Invalid request/response data - message: {}!", message)]
    InvalidRequestResponseData { message: String },
}

impl From<CallError> for ApplyBlockError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall {
                error_id,
                trace_message,
            } => match error_id.as_str() {
                "ffi.unknown_predecessor_context" => ApplyBlockError::UnknownPredecessorContext {
                    message: trace_message,
                },
                "ffi.predecessor_mismatch" => ApplyBlockError::PredecessorMismatch {
                    message: trace_message,
                },
                _ => ApplyBlockError::FailedToApplyBlock {
                    message: trace_message,
                },
            },
            CallError::InvalidRequestData { message } => {
                ApplyBlockError::InvalidRequestResponseData { message }
            }
            CallError::InvalidResponseData { message } => {
                ApplyBlockError::InvalidRequestResponseData { message }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum BeginApplicationError {
    #[fail(display = "Failed to begin application - message: {}!", message)]
    FailedToBeginApplication { message: String },
    #[fail(
        display = "Unknown predecessor context - try to apply predecessor at first message: {}!",
        message
    )]
    UnknownPredecessorContext { message: String },
    #[fail(display = "Invalid request/response data - message: {}!", message)]
    InvalidRequestResponseData { message: String },
}

impl From<CallError> for BeginApplicationError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall {
                error_id,
                trace_message,
            } => match error_id.as_str() {
                "ffi.unknown_predecessor_context" => {
                    BeginApplicationError::UnknownPredecessorContext {
                        message: trace_message,
                    }
                }
                _ => BeginApplicationError::FailedToBeginApplication {
                    message: trace_message,
                },
            },
            CallError::InvalidRequestData { message } => {
                BeginApplicationError::InvalidRequestResponseData { message }
            }
            CallError::InvalidResponseData { message } => {
                BeginApplicationError::InvalidRequestResponseData { message }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum BeginConstructionError {
    #[fail(display = "Failed to begin construction - message: {}!", message)]
    FailedToBeginConstruction { message: String },
    #[fail(
        display = "Unknown predecessor context - try to apply predecessor at first message: {}!",
        message
    )]
    UnknownPredecessorContext { message: String },
    #[fail(display = "Invalid request/response data - message: {}!", message)]
    InvalidRequestResponseData { message: String },
}

impl From<CallError> for BeginConstructionError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall {
                error_id,
                trace_message,
            } => match error_id.as_str() {
                "ffi.unknown_predecessor_context" => {
                    BeginConstructionError::UnknownPredecessorContext {
                        message: trace_message,
                    }
                }
                _ => BeginConstructionError::FailedToBeginConstruction {
                    message: trace_message,
                },
            },
            CallError::InvalidRequestData { message } => {
                BeginConstructionError::InvalidRequestResponseData { message }
            }
            CallError::InvalidResponseData { message } => {
                BeginConstructionError::InvalidRequestResponseData { message }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum ValidateOperationError {
    #[fail(display = "Failed to validate operation - message: {}!", message)]
    FailedToValidateOperation { message: String },
    #[fail(display = "Invalid request/response data - message: {}!", message)]
    InvalidRequestResponseData { message: String },
}

impl From<CallError> for ValidateOperationError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall { trace_message, .. } => {
                ValidateOperationError::FailedToValidateOperation {
                    message: trace_message,
                }
            }
            CallError::InvalidRequestData { message } => {
                ValidateOperationError::InvalidRequestResponseData { message }
            }
            CallError::InvalidResponseData { message } => {
                ValidateOperationError::InvalidRequestResponseData { message }
            }
        }
    }
}

// XXX: UNUSED
#[derive(Debug, Fail)]
pub enum BlockHeaderError {
    #[fail(display = "BlockHeader cannot be read from storage: {}!", message)]
    ReadError { message: String },
    #[fail(display = "BlockHeader was expected, but was not found!")]
    ExpectedButNotFound,
}

impl From<TezosErrorTrace> for BlockHeaderError {
    fn from(error: TezosErrorTrace) -> Self {
        BlockHeaderError::ReadError {
            message: error.trace_json,
        }
    }
}

// XXX: used by decode_context_data, which is unused at the moment
#[derive(Debug, Fail)]
pub enum ContextDataError {
    #[fail(display = "Resolve/decode context data failed to decode: {}!", message)]
    DecodeError { message: String },
}

impl From<TezosErrorTrace> for ContextDataError {
    fn from(error: TezosErrorTrace) -> Self {
        ContextDataError::DecodeError {
            message: error.trace_json,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Fail)]
pub enum ProtocolDataError {
    #[fail(display = "Resolve/decode context data failed to decode: {}!", message)]
    DecodeError { message: String },
}

impl From<TezosErrorTrace> for ProtocolDataError {
    fn from(error: TezosErrorTrace) -> Self {
        ProtocolDataError::DecodeError {
            message: error.trace_json,
        }
    }
}

impl From<FromBytesError> for ProtocolDataError {
    fn from(error: FromBytesError) -> Self {
        ProtocolDataError::DecodeError {
            message: format!("Error constructing hash from bytes: {:?}", error),
        }
    }
}

pub type Json = String;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RpcRequest {
    pub body: Json,
    pub context_path: String,
    pub meth: RpcMethod,
    pub content_type: Option<String>,
    pub accept: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HelpersPreapplyBlockRequest {
    pub protocol_rpc_request: ProtocolRpcRequest,
    pub predecessor_block_metadata_hash: Option<BlockMetadataHash>,
    pub predecessor_ops_metadata_hash: Option<OperationMetadataListListHash>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HelpersPreapplyResponse {
    pub body: Json,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ProtocolRpcResponse {
    RPCConflict(Option<String>),
    RPCCreated(Option<String>),
    RPCError(Option<String>),
    RPCForbidden(Option<String>),
    RPCGone(Option<String>),
    RPCNoContent,
    RPCNotFound(Option<String>),
    RPCOk(String),
    RPCUnauthorized,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RpcMethod {
    DELETE,
    GET,
    PATCH,
    POST,
    PUT,
}

impl TryFrom<&str> for RpcMethod {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let upper = s.to_uppercase();
        match upper.as_ref() {
            "DELETE" => Ok(RpcMethod::DELETE),
            "GET" => Ok(RpcMethod::GET),
            "PATCH" => Ok(RpcMethod::PATCH),
            "POST" => Ok(RpcMethod::POST),
            "PUT" => Ok(RpcMethod::PUT),
            other => Err(format!("Invalid RPC method: {:?}", other)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RpcArgDesc {
    pub name: String,
    pub descr: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Fail, Clone, PartialEq)]
pub enum ProtocolRpcError {
    #[fail(display = "RPC: cannot parse body: {}", _0)]
    RPCErrorCannotParseBody(String),
    #[fail(
        display = "RPC: cannot parse path: {:?}, arg_desc={:?}, message: {}",
        _0, _1, _2
    )]
    RPCErrorCannotParsePath(Vec<String>, RpcArgDesc, String),
    #[fail(display = "RPC: cannot parse query: {}", _0)]
    RPCErrorCannotParseQuery(String),
    #[fail(display = "RPC: invalid method string: {}", _0)]
    RPCErrorInvalidMethodString(String),
    #[fail(display = "RPC: method not allowed: {:?}", _0)]
    RPCErrorMethodNotAllowed(Vec<RpcMethod>),
    #[fail(display = "RPC: service not found")]
    RPCErrorServiceNotFound,
    #[fail(display = "RPC: Failed to call protocol RPC - message: {}!", _0)]
    FailedToCallProtocolRpc(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq)]
pub struct ProtocolRpcRequest {
    pub block_header: BlockHeader,
    pub chain_arg: String,
    pub chain_id: ChainId,

    pub request: RpcRequest,
}

#[derive(Serialize, Deserialize, Debug, Fail, PartialEq)]
pub enum HelpersPreapplyError {
    #[fail(display = "Failed to call protocol rpc - message: {}!", message)]
    FailedToCallProtocolRpc { message: String },
    #[fail(display = "Invalid request data - message: {}!", message)]
    InvalidRequestData { message: String },
    #[fail(display = "Invalid response data - message: {}!", message)]
    InvalidResponseData { message: String },
}

impl From<CallError> for HelpersPreapplyError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall { trace_message, .. } => {
                HelpersPreapplyError::FailedToCallProtocolRpc {
                    message: trace_message,
                }
            }
            CallError::InvalidRequestData { message } => {
                HelpersPreapplyError::InvalidRequestData { message }
            }
            CallError::InvalidResponseData { message } => {
                HelpersPreapplyError::InvalidResponseData { message }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ComputePathRequest {
    pub operations: Vec<Vec<OperationHash>>,
}

impl TryFrom<&Vec<Vec<Operation>>> for ComputePathRequest {
    type Error = MessageHashError;

    fn try_from(ops: &Vec<Vec<Operation>>) -> Result<Self, Self::Error> {
        let mut operation_hashes = Vec::with_capacity(ops.len());
        for inner_ops in ops {
            let mut iophs = Vec::with_capacity(inner_ops.len());
            for op in inner_ops {
                iophs.push(OperationHash::try_from(op.message_hash()?)?);
            }
            operation_hashes.push(iophs);
        }

        Ok(ComputePathRequest {
            operations: operation_hashes,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ComputePathResponse {
    pub operations_hashes_path: Vec<Path>,
}

#[derive(Serialize, Deserialize, Debug, Fail)]
pub enum ComputePathError {
    #[fail(display = "Path computation failed, message: {}!", message)]
    PathError { message: String },
    #[fail(display = "Path computation failed, message: {}!", message)]
    InvalidRequestResponseData { message: String },
}

impl From<CallError> for ComputePathError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::FailedToCall { trace_message, .. } => ComputePathError::PathError {
                message: trace_message,
            },
            CallError::InvalidRequestData { message } => {
                ComputePathError::InvalidRequestResponseData { message }
            }
            CallError::InvalidResponseData { message } => {
                ComputePathError::InvalidRequestResponseData { message }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use assert_json_diff::assert_json_eq;

    use super::*;

    #[test]
    fn test_validate_operation_result_merge() {
        let mut validate_result1 = validate_operation_result(
            "onvN8U6QJ6DGJKVYkHXYRtFm3tgBJScj9P5bbPjSZUuFaGzwFuJ",
            "opVUxMhZttd858HXEHCgchknnnZFmUExtHrbmVSh1G9Pg24X1Pj",
        );
        assert_eq!(2, validate_result1.applied.len());
        assert_eq!(2, validate_result1.refused.len());
        assert_eq!(2, validate_result1.branch_delayed.len());
        assert_eq!(2, validate_result1.branch_refused.len());

        // merge empty -> no change
        assert_eq!(
            false,
            validate_result1.merge(ValidateOperationResult {
                applied: vec![],
                refused: vec![],
                branch_refused: vec![],
                branch_delayed: vec![],
            })
        );
        assert_eq!(2, validate_result1.applied.len());
        assert_eq!(2, validate_result1.refused.len());
        assert_eq!(2, validate_result1.branch_delayed.len());
        assert_eq!(2, validate_result1.branch_refused.len());

        // merge
        let validate_result2 = validate_operation_result(
            "onvN8U6QJ6DGJKVYkHXYRtFm3tgBJScj9P5bbPjSZUuFaGzwFuJ",
            "opJ4FdKumPfykAP9ZqwY7rNB8y1SiMupt44RqBDMWL7cmb4xbNr",
        );
        assert!(validate_result1.merge(validate_result2));
        assert_eq!(3, validate_result1.applied.len());
        assert_eq!(3, validate_result1.refused.len());
        assert_eq!(3, validate_result1.branch_delayed.len());
        assert_eq!(3, validate_result1.branch_refused.len());
    }

    #[test]
    fn test_validate_operation_result_merge_items() -> Result<(), failure::Error> {
        let mut validate_result = ValidateOperationResult {
            applied: vec![],
            refused: vec![],
            branch_refused: vec![],
            branch_delayed: vec![],
        };
        assert_eq!(0, validate_result.applied.len());
        assert_eq!(
            false,
            ValidateOperationResult::merge_items(&mut validate_result.applied, vec![])
        );

        assert!(ValidateOperationResult::merge_items(
            &mut validate_result.applied,
            vec![Applied {
                hash: "onvN8U6QJ6DGJKVYkHXYRtFm3tgBJScj9P5bbPjSZUuFaGzwFuJ".try_into()?,
                protocol_data_json: "protocol_data_json1".to_string(),
            },],
        ));
        assert_eq!(1, validate_result.applied.len());
        assert_eq!(
            "protocol_data_json1",
            validate_result.applied[0].protocol_data_json
        );

        // merge the same -> test change
        assert!(ValidateOperationResult::merge_items(
            &mut validate_result.applied,
            vec![Applied {
                hash: "onvN8U6QJ6DGJKVYkHXYRtFm3tgBJScj9P5bbPjSZUuFaGzwFuJ".try_into()?,
                protocol_data_json: "protocol_data_json2".to_string(),
            },],
        ));
        assert_eq!(1, validate_result.applied.len());
        assert_eq!(
            "protocol_data_json2",
            validate_result.applied[0].protocol_data_json
        );

        // merge another new one
        assert!(ValidateOperationResult::merge_items(
            &mut validate_result.applied,
            vec![Applied {
                hash: "opJ4FdKumPfykAP9ZqwY7rNB8y1SiMupt44RqBDMWL7cmb4xbNr".try_into()?,
                protocol_data_json: "protocol_data_json2".to_string(),
            },],
        ));
        assert_eq!(2, validate_result.applied.len());

        Ok(())
    }

    fn validate_operation_result(op1: &str, op2: &str) -> ValidateOperationResult {
        let applied = vec![
            Applied {
                hash: op1.try_into().expect("Error"),
                protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
            },
            Applied {
                hash: op2.try_into().expect("Error"),
                protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
            }
        ];

        let branch_delayed = vec![
            Errored {
                hash: op1.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            },
            Errored {
                hash: op2.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            }
        ];

        let branch_refused = vec![
            Errored {
                hash: op1.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            },
            Errored {
                hash: op2.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            }
        ];

        let refused = vec![
            Errored {
                hash: op1.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            },
            Errored {
                hash: op2.try_into().expect("Error"),
                is_endorsement: None,
                protocol_data_json_with_error_json: OperationProtocolDataJsonWithErrorListJson {
                    protocol_data_json: "{ \"contents\": [ { \"kind\": \"endorsement\", \"level\": 459020 } ],\n  \"signature\":\n    \"siguKbKFVDkXo2m1DqZyftSGg7GZRq43EVLSutfX5yRLXXfWYG5fegXsDT6EUUqawYpjYE1GkyCVHfc2kr3hcaDAvWSAhnV9\" }".to_string(),
                    error_json: "[ { \"kind\": \"temporary\",\n    \"id\": \"proto.005-PsBabyM1.operation.wrong_endorsement_predecessor\",\n    \"expected\": \"BMDb9PfcJmiibDDEbd6bEEDj4XNG4C7QACG6TWqz29c9FxNgDLL\",\n    \"provided\": \"BLd8dLs4X5Ve6a8B37kUu7iJkRycWzfSF5MrskY4z8YaideQAp4\" } ]".to_string(),
                },
            }
        ];

        ValidateOperationResult {
            applied,
            branch_delayed,
            branch_refused,
            refused,
        }
    }

    #[test]
    fn test_rpc_format_user_activated_upgrades() -> Result<(), failure::Error> {
        let expected_json = serde_json::json!(
            [
              {
                "level": 28082,
                "replacement_protocol": "PsYLVpVvgbLhAhoqAkMFUo6gudkJ9weNXhUYCiLDzcUpFpkk8Wt"
              },
              {
                "level": 204761,
                "replacement_protocol": "PsddFKi32cMJ2qPjf43Qv5GDWLDPZb3T3bF6fLKiF5HtvHNU7aP"
              }
            ]
        );

        let protocol_overrides = ProtocolOverrides {
            user_activated_upgrades: vec![
                (
                    28082_i32,
                    "PsYLVpVvgbLhAhoqAkMFUo6gudkJ9weNXhUYCiLDzcUpFpkk8Wt".to_string(),
                ),
                (
                    204761_i32,
                    "PsddFKi32cMJ2qPjf43Qv5GDWLDPZb3T3bF6fLKiF5HtvHNU7aP".to_string(),
                ),
            ],
            user_activated_protocol_overrides: vec![],
        };

        assert_json_eq!(
            expected_json,
            serde_json::to_value(protocol_overrides.user_activated_upgrades_to_rpc_json())?
        );
        Ok(())
    }

    #[test]
    fn test_rpc_format_user_activated_protocol_overrides() -> Result<(), failure::Error> {
        let expected_json = serde_json::json!(
            [
              {
                "replaced_protocol": "PsBABY5HQTSkA4297zNHfsZNKtxULfL18y95qb3m53QJiXGmrbU",
                "replacement_protocol": "PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS"
              }
            ]
        );

        let protocol_overrides = ProtocolOverrides {
            user_activated_upgrades: vec![],
            user_activated_protocol_overrides: vec![(
                "PsBABY5HQTSkA4297zNHfsZNKtxULfL18y95qb3m53QJiXGmrbU".to_string(),
                "PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS".to_string(),
            )],
        };

        assert_json_eq!(
            expected_json,
            serde_json::to_value(
                protocol_overrides.user_activated_protocol_overrides_to_rpc_json()
            )?
        );
        Ok(())
    }
}
