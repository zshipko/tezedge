// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! This module encapsulates p2p communication between peers.
//!
//! It provides message packaging from/to binary format, encryption, message nonce handling.

use std::convert::TryInto;
use std::marker::PhantomData;

use failure::{Error, Fail};
use failure::_core::time::Duration;
use slog::{FnValue, Logger, o, trace};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::prelude::*;

use crypto::crypto_box::{CryptoError, decrypt, encrypt, PrecomputedKey};
use crypto::nonce::Nonce;
use tezos_encoding::binary_reader::BinaryReaderError;
use tezos_messages::p2p::{
    binary_message::{BinaryChunk, BinaryChunkError, BinaryMessage, CONTENT_LENGTH_FIELD_BYTES},
    encoding::peer::PeerMessageResponse,
};

use crate::p2p::peer::PeerId;

/// Max allowed content length in bytes when taking into account extra data added by encryption
pub const CONTENT_LENGTH_MAX: usize = tezos_messages::p2p::binary_message::CONTENT_LENGTH_MAX - crypto::crypto_box::BOX_ZERO_BYTES;

/// This is common error that might happen when communicating with peer over the network.
#[derive(Debug, Fail)]
pub enum StreamError {
    #[fail(display = "Failed to encrypt message")]
    FailedToEncryptMessage {
        error: CryptoError
    },
    #[fail(display = "Failed to decrypt message")]
    FailedToDecryptMessage {
        error: CryptoError
    },
    #[fail(display = "Message serialization error")]
    SerializationError {
        error: tezos_encoding::ser::Error
    },
    #[fail(display = "Message de-serialization error: {:?}", error)]
    DeserializationError {
        error: BinaryReaderError
    },
    #[fail(display = "Network error: {}, cause: {}", message, error)]
    NetworkError {
        message: &'static str,
        error: Error,
    },
}

impl From<tezos_encoding::ser::Error> for StreamError {
    fn from(error: tezos_encoding::ser::Error) -> Self {
        StreamError::SerializationError { error }
    }
}

impl From<std::io::Error> for StreamError {
    fn from(error: std::io::Error) -> Self {
        StreamError::NetworkError { error: error.into(), message: "Stream error" }
    }
}

impl From<BinaryChunkError> for StreamError {
    fn from(error: BinaryChunkError) -> Self {
        StreamError::NetworkError { error: error.into(), message: "Binary chunk error" }
    }
}

impl From<BinaryReaderError> for StreamError {
    fn from(error: BinaryReaderError) -> Self {
        StreamError::DeserializationError { error }
    }
}

impl slog::Value for StreamError {
    fn serialize(&self, _record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}


/// Holds read and write parts of the message stream.
pub struct MessageStream {
    reader: MessageReader,
    writer: MessageWriter,
}

impl MessageStream {
    fn new(stream: TcpStream) -> MessageStream {
        let _ = stream.set_linger(Some(Duration::from_secs(2)));
        let _ = stream.set_nodelay(true);

        let (rx, tx) = tokio::io::split(stream);
        MessageStream {
            reader: MessageReader { stream: rx, buffer: Vec::new() },
            writer: MessageWriter { stream: tx },
        }
    }

    #[inline]
    pub fn split(self) -> (MessageReader, MessageWriter) {
        (self.reader, self.writer)
    }
}

impl From<TcpStream> for MessageStream {
    fn from(stream: TcpStream) -> Self {
        MessageStream::new(stream)
    }
}

/// Reader of the TCP/IP connection.
pub struct MessageReader {
    /// reader part or the TCP/IP network stream
    stream: ReadHalf<TcpStream>,
    /// buffer containing bytes of partially received chunk
    buffer: Vec<u8>,
}

impl MessageReader {
    /// Read only one chunk from network and return its content in a form of bytes.
    pub async fn read_single_chunk(&mut self) -> Result<BinaryChunk, StreamError> {
        loop {
            match self.next() {
                Some(m) => break Ok(m),
                None => {
                    let _ = self.fill_buffer().await?;
                },
            }
        }
    }

    fn next(&mut self) -> Option<BinaryChunk> {
        if self.buffer.len() >= CONTENT_LENGTH_FIELD_BYTES {
            let len = u16::from_be_bytes(self.buffer[0..CONTENT_LENGTH_FIELD_BYTES].try_into().unwrap()) as usize;
            if self.buffer.len() >= CONTENT_LENGTH_FIELD_BYTES + len {
                let rest = self.buffer.split_off(CONTENT_LENGTH_FIELD_BYTES + len);
                let raw_chunk = std::mem::replace(&mut self.buffer, rest);
                Some(raw_chunk.try_into().unwrap())
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn fill_buffer(&mut self) -> Result<usize, StreamError> {
        let mut buf = [0; 0x10000];
        let read = self.stream.read(buf.as_mut()).await?;
        self.buffer.extend_from_slice(&buf[..read]);
        Ok(read)
    }
}

pub struct MessageWriter {
    stream: WriteHalf<TcpStream>
}

impl MessageWriter {
    /// Construct and write message to network stream.
    ///
    /// # Arguments
    /// * `bytes` - A message contents represented ab bytes
    ///
    /// In case all bytes are successfully written to network stream a raw binary
    /// message is returned as a result.
    #[inline]
    pub async fn write_message(&mut self, bytes: &Vec<u8>) -> Result<(), StreamError> {
        Ok(self.stream.write_all(bytes.as_ref()).await?)
    }
}

/// The `EncryptedMessageWriter` encapsulates process of the encrypted outgoing message transmission.
/// This process involves (not only) nonce increment, encryption and network transmission.
pub struct EncryptedMessageWriter {
    /// Precomputed key is created from merge of peer public key and our secret key.
    /// It's used to speedup of crypto operations.
    precomputed_key: PrecomputedKey,
    /// Nonce used to encrypt outgoing messages
    nonce_local: Nonce,
    /// Outgoing message writer
    tx: MessageWriter,
    /// Logger
    log: Logger,
}

impl EncryptedMessageWriter {
    pub fn new(tx: MessageWriter, precomputed_key: PrecomputedKey, nonce_local: Nonce, peer_id: PeerId, log: Logger) -> Self {
        let log = log.new(o!("peer" => peer_id));
        EncryptedMessageWriter { tx, precomputed_key, nonce_local, log }
    }

    pub async fn write_peer_response(&mut self, message: &PeerMessageResponse) -> Result<(), StreamError> {
        match message.messages().len() {
            0 => Ok(()),
            _ => {
                let mut all_bytes = Vec::new();
                for message in message.messages() {
                    let message = PeerMessageResponse::new(vec![message.clone()]);
                    let mut bytes = self.encrypt_message(&message)?;
                    all_bytes.append(&mut bytes);
                }
                self.tx.write_message(&all_bytes).await
            }
        }
    }

    pub fn encrypt_message<'a>(&'a mut self, message: &'a impl BinaryMessage) -> Result<Vec<u8>, StreamError> {
        let message_bytes = message.as_bytes()?;
        trace!(self.log, "Writing message"; "message" => FnValue(|_| hex::encode(&message_bytes)));

        let mut bytes = Vec::new();
        for chunk_content_bytes in message_bytes.chunks(CONTENT_LENGTH_MAX) {
            // encrypt
            let message_bytes_encrypted = match encrypt(chunk_content_bytes, &self.nonce_fetch_increment(), &self.precomputed_key) {
                Ok(msg) => msg,
                Err(error) => return Err(StreamError::FailedToEncryptMessage { error })
            };

            let chunk = BinaryChunk::from_content(&message_bytes_encrypted)?;
            bytes.extend_from_slice(chunk.raw());
        }

        Ok(bytes)
    }

    pub async fn write_message<'a>(&'a mut self, message: &'a impl BinaryMessage) -> Result<(), StreamError> {
        let bytes = self.encrypt_message(message)?;
        self.tx.write_message(&bytes).await
    }

    #[inline]
    fn nonce_fetch_increment(&mut self) -> Nonce {
        let incremented = self.nonce_local.increment();
        std::mem::replace(&mut self.nonce_local, incremented)
    }
}

/// The `MessageReceiver` encapsulates process of the encrypted incoming message transmission.
/// This process involves (not only) nonce increment, encryption and network transmission.
pub struct EncryptedMessageReader {
    /// Precomputed key is created from merge of peer public key and our secret key.
    /// It's used to speedup of crypto operations.
    precomputed_key: PrecomputedKey,
    /// Nonce used to decrypt received messages
    nonce_remote: Nonce,
    /// Incoming message reader
    rx: MessageReader,
    /// Logger
    log: Logger,
}

/// Contains bytes of partially received message
struct MessageBuffer<M> {
    input_remaining: usize,
    input_data: Vec<u8>,
    phantom_data: PhantomData<M>,
}

impl<M> MessageBuffer<M>
where
    M: BinaryMessage,
{
    pub fn new() -> Self {
        MessageBuffer {
            input_remaining: 0,
            input_data: Vec::new(),
            phantom_data: PhantomData,
        }
    }

    pub fn push(&mut self, logger: &Logger, mut decrypted: Vec<u8>) -> Result<Option<M>, StreamError> {
        trace!(logger, "Message received"; "message" => FnValue(|_| hex::encode(&decrypted)));
        if self.input_remaining >= decrypted.len() {
            self.input_remaining -= decrypted.len();
        } else {
            // here should be a warning
            self.input_remaining = 0;
        }

        self.input_data.append(&mut decrypted);

        if self.input_remaining == 0 {
            match M::from_bytes(&self.input_data) {
                Ok(message) => {
                    self.input_data = Vec::new();
                    Ok(Some(message))
                },
                Err(BinaryReaderError::Underflow { bytes }) => {
                    self.input_remaining += bytes;
                    Ok(None)
                },
                Err(e) => Err(e.into()),
            }
        } else {
            Ok(None)
        }
    }
}

impl EncryptedMessageReader {
    /// Create new encrypted message from async reader and peer data
    pub fn new(rx: MessageReader, precomputed_key: PrecomputedKey, nonce_remote: Nonce, peer_id: PeerId, log: Logger) -> Self {
        let log = log.new(o!("peer" => peer_id));
        EncryptedMessageReader { rx, precomputed_key, nonce_remote, log }
    }

    pub async fn read_peer_response(&mut self) -> Result<PeerMessageResponse, StreamError> {
        let mut full_message = Vec::new();
        let mut buffer = MessageBuffer::<PeerMessageResponse>::new();

        loop {
            if let Some(encrypted) = self.rx.next() {
                let decrypted = decrypt(encrypted.content(), &self.nonce_fetch_increment(), &self.precomputed_key)
                    .map_err(|error| StreamError::FailedToDecryptMessage { error })?;
                if let Some(message) = buffer.push(&self.log, decrypted)? {
                    full_message.push(message);
                    if self.rx.buffer.is_empty() {
                        break;
                    }
                }
            } else {
                self.rx.fill_buffer().await?;
            }
        }

        Ok(PeerMessageResponse::flatten(full_message))
    }

    pub async fn read_message<M>(&mut self) -> Result<M, StreamError>
    where
        M: BinaryMessage,
    {
        let mut input_remaining = 0;
        let mut input_data = vec![];

        loop {
            // read
            let message_encrypted = self.rx.read_single_chunk().await?;

            // decrypt
            match decrypt(message_encrypted.content(), &self.nonce_fetch_increment(), &self.precomputed_key) {
                Ok(mut message_decrypted) => {
                    trace!(self.log, "Message received"; "message" => FnValue(|_| hex::encode(&message_decrypted)));
                    if input_remaining >= message_decrypted.len() {
                        input_remaining -= message_decrypted.len();
                    } else {
                        input_remaining = 0;
                    }

                    input_data.append(&mut message_decrypted);

                    if input_remaining == 0 {
                        match M::from_bytes(&input_data) {
                            Ok(message) => break Ok(message),
                            Err(BinaryReaderError::Underflow { bytes }) => input_remaining += bytes,
                            Err(e) => break Err(e.into()),
                        }
                    }
                }
                Err(error) => {
                    break Err(StreamError::FailedToDecryptMessage { error });
                }
            }
        }
    }

    #[inline]
    fn nonce_fetch_increment(&mut self) -> Nonce {
        let incremented = self.nonce_remote.increment();
        std::mem::replace(&mut self.nonce_remote, incremented)
    }

    pub fn unsplit(self, tx: EncryptedMessageWriter) -> TcpStream {
        self.rx.stream.unsplit(tx.tx.stream)
    }
}