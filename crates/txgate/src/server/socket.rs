//! Unix socket server for the `TxGate` signing service.
//!
//! This module provides a Unix domain socket server that accepts JSON-RPC 2.0
//! requests for transaction signing operations.
//!
//! # Features
//!
//! - Line-delimited JSON-RPC 2.0 protocol
//! - Configurable socket permissions for security
//! - Graceful shutdown support
//! - Concurrent connection handling
//! - Policy enforcement and audit logging
//!
//! # Example
//!
//! ```no_run
//! use txgate::server::socket::{ServerConfig, TxGateServer};
//! use txgate_crypto::signer::Secp256k1Signer;
//! use txgate_policy::engine::DefaultPolicyEngine;
//! use txgate_policy::config::PolicyConfig;
//! use txgate_chain::EthereumParser;
//! use std::path::PathBuf;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a signer
//!     let signer = Secp256k1Signer::generate();
//!
//!     // Create policy engine
//!     let config = PolicyConfig::new();
//!     let policy_engine = DefaultPolicyEngine::new(config)?;
//!
//!     // Create parser
//!     let parser = EthereumParser::new();
//!
//!     // Create server config
//!     let server_config = ServerConfig {
//!         socket_path: PathBuf::from("/tmp/txgate.sock"),
//!         socket_permissions: 0o600,
//!     };
//!
//!     // Create and run the server
//!     let server = TxGateServer::new(
//!         server_config,
//!         signer,
//!         policy_engine,
//!         parser,
//!         None, // No audit logger
//!     );
//!
//!     // Run with shutdown signal
//!     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
//!     server.run(shutdown_rx).await?;
//!
//!     Ok(())
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Semaphore};
use txgate_chain::{Chain, EthereumParser};
use txgate_core::types::{ParsedTx, PolicyResult};
use txgate_crypto::signer::{Chain as SignerChain, Signer};
use txgate_policy::engine::{DefaultPolicyEngine, PolicyEngine};

use super::protocol::{
    GetAddressResult, GetStatusResult, JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse,
    Method, SignParams, SignResult, TransactionDetails,
};
use crate::audit::{AuditLogger, PolicyResultInput, SignEvent};

/// Maximum size of a single JSON-RPC request line (1 MiB).
const MAX_REQUEST_SIZE: u64 = 1024 * 1024;

/// Maximum number of concurrent client connections.
const MAX_CONNECTIONS: usize = 64;

/// Per-connection idle timeout before the server closes it.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Backoff duration after an accept error.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Server configuration for the Unix socket server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Path to the Unix socket file.
    pub socket_path: PathBuf,

    /// Unix file permissions for the socket (default: 0o600).
    ///
    /// Common values:
    /// - `0o600` - Owner read/write only (most secure)
    /// - `0o660` - Owner and group read/write
    /// - `0o666` - World read/write (least secure)
    pub socket_permissions: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/tmp/txgate.sock"),
            socket_permissions: 0o600,
        }
    }
}

/// Unix socket signing server.
///
/// This server accepts JSON-RPC 2.0 requests over a Unix domain socket
/// and provides transaction signing, address retrieval, and status queries.
///
/// # Type Parameters
///
/// * `S` - The signer implementation (must implement `Signer + Send + Sync + 'static`)
///
/// # Thread Safety
///
/// The server is designed for concurrent use:
/// - Multiple connections can be handled simultaneously
/// - The signer, policy engine, and parser are shared via `Arc`
/// - Audit logging is thread-safe
pub struct TxGateServer<S: Signer + Send + Sync + 'static> {
    /// Server configuration.
    config: ServerConfig,

    /// The cryptographic signer.
    signer: Arc<S>,

    /// The policy engine for transaction validation.
    policy_engine: Arc<DefaultPolicyEngine>,

    /// The transaction parser.
    parser: Arc<EthereumParser>,

    /// Optional audit logger for security events.
    audit_logger: Option<Arc<AuditLogger>>,
}

impl<S: Signer + Send + Sync + 'static> std::fmt::Debug for TxGateServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxGateServer")
            .field("config", &self.config)
            .field("audit_logger", &self.audit_logger.is_some())
            .finish_non_exhaustive()
    }
}

/// Errors that can occur during server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to bind to the socket.
    #[error("failed to bind socket at {path}: {source}")]
    Bind {
        /// The socket path that failed to bind.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to set socket permissions.
    #[error("failed to set socket permissions on {path}: {source}")]
    Permissions {
        /// The socket path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Connection error during client handling.
    #[error("connection error: {0}")]
    Connection(#[source] std::io::Error),

    /// Error reading from the socket.
    #[error("read error: {0}")]
    Read(#[source] std::io::Error),

    /// Error writing to the socket.
    #[error("write error: {0}")]
    Write(#[source] std::io::Error),

    /// Error parsing JSON-RPC request.
    #[error("parse error: {0}")]
    Parse(String),

    /// Internal server error (e.g. task join failure).
    #[error("internal error: {0}")]
    Internal(String),
}

/// RAII guard that removes the socket file when dropped.
///
/// Ensures the socket is cleaned up on all exit paths, including
/// early returns from `set_permissions` or panics.
struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Disarm the guard so it does NOT remove the file on drop.
    /// Call this when cleanup is handled explicitly (e.g. after normal shutdown).
    fn disarm(mut self) {
        self.path = PathBuf::new();
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() && self.path.exists() {
            if let Err(e) = std::fs::remove_file(&self.path) {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "Failed to remove socket file during cleanup"
                );
            }
        }
    }
}

impl<S: Signer + Send + Sync + 'static> TxGateServer<S> {
    /// Create a new server instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `signer` - The cryptographic signer
    /// * `policy_engine` - The policy engine for transaction validation
    /// * `parser` - The transaction parser
    /// * `audit_logger` - Optional audit logger for security events
    ///
    /// # Example
    ///
    /// ```no_run
    /// use txgate::server::socket::{ServerConfig, TxGateServer};
    /// use txgate_crypto::signer::Secp256k1Signer;
    /// use txgate_policy::engine::DefaultPolicyEngine;
    /// use txgate_policy::config::PolicyConfig;
    /// use txgate_chain::EthereumParser;
    ///
    /// let signer = Secp256k1Signer::generate();
    /// let config = PolicyConfig::new();
    /// let policy_engine = DefaultPolicyEngine::new(config).unwrap();
    /// let parser = EthereumParser::new();
    /// let server_config = ServerConfig::default();
    ///
    /// let server = TxGateServer::new(
    ///     server_config,
    ///     signer,
    ///     policy_engine,
    ///     parser,
    ///     None,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        config: ServerConfig,
        signer: S,
        policy_engine: DefaultPolicyEngine,
        parser: EthereumParser,
        audit_logger: Option<AuditLogger>,
    ) -> Self {
        Self {
            config,
            signer: Arc::new(signer),
            policy_engine: Arc::new(policy_engine),
            parser: Arc::new(parser),
            audit_logger: audit_logger.map(Arc::new),
        }
    }

    /// Run the server until a shutdown signal is received.
    ///
    /// This method:
    /// 1. Removes any existing socket file
    /// 2. Binds to the Unix socket
    /// 3. Sets socket permissions
    /// 4. Accepts connections until shutdown
    /// 5. Cleans up the socket file on exit
    ///
    /// # Arguments
    ///
    /// * `shutdown` - A oneshot receiver that signals when to shut down
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if:
    /// - The socket cannot be bound
    /// - Socket permissions cannot be set
    ///
    /// # Example
    ///
    /// ```no_run
    /// use txgate::server::socket::{ServerConfig, TxGateServer};
    /// use txgate_crypto::signer::Secp256k1Signer;
    /// use txgate_policy::engine::DefaultPolicyEngine;
    /// use txgate_policy::config::PolicyConfig;
    /// use txgate_chain::EthereumParser;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let signer = Secp256k1Signer::generate();
    ///     let config = PolicyConfig::new();
    ///     let policy_engine = DefaultPolicyEngine::new(config)?;
    ///     let parser = EthereumParser::new();
    ///     let server_config = ServerConfig::default();
    ///
    ///     let server = TxGateServer::new(
    ///         server_config,
    ///         signer,
    ///         policy_engine,
    ///         parser,
    ///         None,
    ///     );
    ///
    ///     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    ///
    ///     // In another task: shutdown_tx.send(()).unwrap();
    ///     server.run(shutdown_rx).await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn run(self, shutdown: oneshot::Receiver<()>) -> Result<(), ServerError> {
        // Remove existing socket file if present
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path).map_err(|e| ServerError::Bind {
                path: self.config.socket_path.clone(),
                source: e,
            })?;
        }

        // Bind to the socket
        let listener =
            UnixListener::bind(&self.config.socket_path).map_err(|e| ServerError::Bind {
                path: self.config.socket_path.clone(),
                source: e,
            })?;

        // RAII guard ensures socket file is cleaned up on all exit paths
        let guard = SocketGuard::new(self.config.socket_path.clone());

        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(self.config.socket_permissions);
            std::fs::set_permissions(&self.config.socket_path, permissions).map_err(|e| {
                ServerError::Permissions {
                    path: self.config.socket_path.clone(),
                    source: e,
                }
            })?;
        }

        tracing::info!(
            socket_path = %self.config.socket_path.display(),
            permissions = format!("{:#o}", self.config.socket_permissions),
            "Server started"
        );

        // Create Arc-wrapped self for sharing across tasks
        let server = Arc::new(self);

        // Connection limiter
        let connection_semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        // Accept connections until shutdown
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let Ok(permit) = connection_semaphore.clone().try_acquire_owned() else {
                                tracing::warn!("Connection limit reached ({MAX_CONNECTIONS}), rejecting");
                                drop(stream);
                                continue;
                            };
                            let server_clone = Arc::clone(&server);
                            tokio::spawn(async move {
                                let result = tokio::time::timeout(
                                    CONNECTION_TIMEOUT,
                                    Arc::clone(&server_clone).handle_connection(stream),
                                ).await;
                                match result {
                                    Ok(Err(e)) => tracing::warn!(error = %e, "Connection error"),
                                    Err(_) => tracing::debug!("Connection timed out"),
                                    Ok(Ok(())) => {}
                                }
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Accept error");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        }
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
            }
        }

        // Explicit cleanup — guard handles it, then disarm so we don't double-remove
        guard.disarm();
        if server.config.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&server.config.socket_path) {
                tracing::warn!(
                    error = %e,
                    path = %server.config.socket_path.display(),
                    "Failed to remove socket file"
                );
            }
        }

        tracing::info!("Server stopped");
        Ok(())
    }

    /// Handle a single client connection.
    ///
    /// Reads line-delimited JSON-RPC requests and writes responses.
    /// Each line should be a complete JSON-RPC request object.
    ///
    /// CPU-bound work (parsing, policy checks, signing) is offloaded
    /// to the blocking thread pool via `spawn_blocking` so the async runtime
    /// stays responsive for I/O under heavy load.
    async fn handle_connection(self: Arc<Self>, stream: UnixStream) -> Result<(), ServerError> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();

            // Read a line (request)
            let bytes_read = reader
                .read_line(&mut line)
                .await
                .map_err(ServerError::Read)?;

            if bytes_read == 0 {
                // Connection closed
                break;
            }

            // Reject oversized requests to prevent memory exhaustion
            if line.len() as u64 > MAX_REQUEST_SIZE {
                tracing::warn!(
                    size = line.len(),
                    limit = MAX_REQUEST_SIZE,
                    "Request exceeds size limit, disconnecting"
                );
                let error_response = r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Request too large"},"id":null}"#;
                let _ = writer.write_all(error_response.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
                let _ = writer.flush().await;
                break;
            }

            // Trim the line
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Offload CPU-bound request processing to blocking thread pool
            let request_str = trimmed.to_owned();
            let server = Arc::clone(&self);
            let response =
                tokio::task::spawn_blocking(move || server.process_request(&request_str))
                    .await
                    .map_err(|e| {
                        ServerError::Internal(format!("spawn_blocking join error: {e}"))
                    })?;

            // Serialize and write response
            let response_json = serde_json::to_string(&response)
                .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error: failed to serialize response"},"id":null}"#.to_string());

            writer
                .write_all(response_json.as_bytes())
                .await
                .map_err(ServerError::Write)?;
            writer.write_all(b"\n").await.map_err(ServerError::Write)?;
            writer.flush().await.map_err(ServerError::Write)?;
        }

        Ok(())
    }

    /// Process a JSON-RPC request and return a response.
    fn process_request(&self, request_str: &str) -> JsonRpcResponse {
        // Parse the JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(request_str) {
            Ok(req) => req,
            Err(e) => {
                return JsonRpcResponse::error(
                    JsonRpcId::Null,
                    JsonRpcError::parse_error(&e.to_string()),
                );
            }
        };

        // Validate the request
        if let Err(e) = request.validate() {
            return JsonRpcResponse::error(request.id, e);
        }

        // Parse the method
        let Ok(method) = request.method.parse::<Method>() else {
            return JsonRpcResponse::error(
                request.id,
                JsonRpcError::method_not_found(&request.method),
            );
        };

        // Dispatch to the appropriate handler
        match method {
            Method::Sign => self.handle_sign(&request),
            Method::GetAddress => self.handle_get_address(&request),
            Method::GetStatus => self.handle_get_status(&request),
        }
    }

    /// Handle a `sign` request.
    #[allow(clippy::too_many_lines)]
    fn handle_sign(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        // Parse sign parameters
        let params: SignParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::invalid_params(&e.to_string()),
                );
            }
        };

        // Decode the transaction hex
        let tx_hex = params
            .transaction
            .strip_prefix("0x")
            .unwrap_or(&params.transaction);
        let tx_bytes = match hex::decode(tx_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::invalid_params(&format!("invalid transaction hex: {e}")),
                );
            }
        };

        // Parse the transaction
        let parsed_tx = match self.parser.parse(&tx_bytes) {
            Ok(tx) => tx,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::invalid_params(&format!("failed to parse transaction: {e}")),
                );
            }
        };

        // Check policy
        let policy_result = match self.policy_engine.check(&parsed_tx) {
            Ok(result) => result,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::internal_error(&format!("policy check failed: {e}")),
                );
            }
        };

        // Handle policy denial
        if let PolicyResult::Denied { rule, reason } = &policy_result {
            // Log the denial
            self.log_sign_event(
                &parsed_tx,
                PolicyResultInput::Denied {
                    rule: rule.clone(),
                    reason: reason.clone(),
                },
                None,
            );

            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError::policy_denied(&format!("{rule}: {reason}")),
            );
        }

        // Sign the transaction hash
        let signature = match self.signer.sign(&parsed_tx.hash) {
            Ok(sig) => sig,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::signing_error(&e.to_string()),
                );
            }
        };

        // Extract signature components (65 bytes: r || s || v)
        let Some(r) = signature.get(0..32) else {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError::signing_error("invalid signature length: missing r component"),
            );
        };
        let Some(s) = signature.get(32..64) else {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError::signing_error("invalid signature length: missing s component"),
            );
        };
        let v = signature.get(64).copied().unwrap_or(0);

        // Assemble signed transaction (best-effort; not all chains support this)
        let signed_transaction = match self.parser.assemble_signed(&tx_bytes, &signature) {
            Ok(bytes) => Some(format!("0x{}", hex::encode(&bytes))),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to assemble signed transaction");
                None
            }
        };

        // Build the sign result
        let sign_result = SignResult {
            tx_hash: format!("0x{}", hex::encode(parsed_tx.hash)),
            r: format!("0x{}", hex::encode(r)),
            s: format!("0x{}", hex::encode(s)),
            v,
            signature: format!("0x{}", hex::encode(&signature)),
            signed_transaction,
            transaction: TransactionDetails {
                tx_type: parsed_tx.tx_type.as_str().to_string(),
                recipient: parsed_tx.recipient.clone(),
                amount: parsed_tx
                    .amount
                    .map_or_else(|| "0".to_string(), |a| a.to_string()),
                token: parsed_tx.token_address.clone(),
                nonce: parsed_tx.nonce.unwrap_or(0),
                chain_id: parsed_tx.chain_id.unwrap_or(1),
            },
        };

        // Log the successful signing event
        let sig_bytes: Option<[u8; 64]> = signature.get(0..64).map(|bytes| {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(bytes);
            arr
        });
        self.log_sign_event(&parsed_tx, PolicyResultInput::Allowed, sig_bytes);

        JsonRpcResponse::success(request.id.clone(), sign_result)
    }

    /// Handle a `getAddress` request.
    fn handle_get_address(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        // Get the Ethereum address
        let address = match self.signer.address(SignerChain::Ethereum) {
            Ok(addr) => addr,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::internal_error(&format!("failed to get address: {e}")),
                );
            }
        };

        let result = GetAddressResult { address };
        JsonRpcResponse::success(request.id.clone(), result)
    }

    /// Handle a `getStatus` request.
    #[allow(clippy::unused_self)]
    fn handle_get_status(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let result = GetStatusResult {
            initialized: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_chains: vec!["ethereum".to_string()],
        };

        JsonRpcResponse::success(request.id.clone(), result)
    }

    /// Log a signing event to the audit logger.
    fn log_sign_event(
        &self,
        parsed_tx: &ParsedTx,
        policy_result: PolicyResultInput,
        signature: Option<[u8; 64]>,
    ) {
        let Some(audit_logger) = &self.audit_logger else {
            return;
        };

        // Convert recipient to bytes if present
        let recipient_bytes: Option<[u8; 20]> = parsed_tx.recipient.as_ref().and_then(|r| {
            let r = r.strip_prefix("0x").unwrap_or(r);
            hex::decode(r).ok().and_then(|bytes| {
                if bytes.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
        });

        // Convert token address to bytes if present
        let token_bytes: Option<[u8; 20]> = parsed_tx.token_address.as_ref().and_then(|t| {
            let t = t.strip_prefix("0x").unwrap_or(t);
            hex::decode(t).ok().and_then(|bytes| {
                if bytes.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
        });

        let event = SignEvent {
            correlation_id: format!("tx-{}", hex::encode(&parsed_tx.hash[0..8])),
            chain: parsed_tx.chain.clone(),
            tx_hash: parsed_tx.hash,
            recipient: recipient_bytes,
            amount: parsed_tx
                .amount
                .map_or_else(|| "0".to_string(), |a| a.to_string()),
            token: token_bytes,
            tx_type: parsed_tx.tx_type.as_str().to_string(),
            policy_result,
            signature,
        };

        if let Err(e) = audit_logger.log_sign_event(event) {
            tracing::warn!(error = %e, "Failed to log audit event");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::uninlined_format_args,
        clippy::io_other_error
    )]

    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use txgate_crypto::signer::Secp256k1Signer;
    use txgate_policy::config::PolicyConfig;

    /// Helper to create a test server
    fn create_test_server(socket_path: PathBuf) -> TxGateServer<Secp256k1Signer> {
        let signer = Secp256k1Signer::generate();
        let config = PolicyConfig::new();
        let policy_engine = DefaultPolicyEngine::new(config).expect("policy engine");
        let parser = EthereumParser::new();

        let server_config = ServerConfig {
            socket_path,
            socket_permissions: 0o600,
        };

        TxGateServer::new(server_config, signer, policy_engine, parser, None)
    }

    /// Helper to send a JSON-RPC request and get response
    async fn send_request(stream: &mut UnixStream, request: &str) -> String {
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        // Write request
        writer.write_all(request.as_bytes()).await.expect("write");
        writer.write_all(b"\n").await.expect("write newline");
        writer.flush().await.expect("flush");

        // Read response
        let mut response = String::new();
        reader.read_line(&mut response).await.expect("read");
        response
    }

    // =========================================================================
    // ServerConfig Tests
    // =========================================================================

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/txgate.sock"));
        assert_eq!(config.socket_permissions, 0o600);
    }

    #[test]
    fn test_server_config_debug() {
        let config = ServerConfig::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("ServerConfig"));
        assert!(debug_str.contains("socket_path"));
    }

    // =========================================================================
    // TxGateServer Creation Tests
    // =========================================================================

    #[test]
    fn test_server_new() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());

        assert_eq!(server.config.socket_path, socket_path);
        assert!(server.audit_logger.is_none());
    }

    #[test]
    fn test_server_debug() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");
        let server = create_test_server(socket_path);

        let debug_str = format!("{server:?}");
        assert!(debug_str.contains("TxGateServer"));
        assert!(debug_str.contains("config"));
    }

    // =========================================================================
    // Server Startup and Shutdown Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_startup_and_shutdown() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start server in background
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify socket exists
        assert!(socket_path.exists(), "socket file should exist");

        // Send shutdown signal
        shutdown_tx.send(()).expect("send shutdown");

        // Wait for server to stop
        let result = tokio::time::timeout(Duration::from_secs(5), server_handle)
            .await
            .expect("server should stop")
            .expect("join handle");

        assert!(result.is_ok(), "server should shut down cleanly");
    }

    #[tokio::test]
    async fn test_server_removes_existing_socket() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        // Create a dummy file at the socket path
        std::fs::write(&socket_path, "dummy").expect("write dummy");
        assert!(socket_path.exists());

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Socket should be a valid socket now
        assert!(socket_path.exists());

        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    // =========================================================================
    // JSON-RPC Request Handling Tests
    // =========================================================================

    #[tokio::test]
    async fn test_get_status_request() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect to server
        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        // Send getStatus request
        let request = r#"{"jsonrpc":"2.0","method":"getStatus","id":1}"#;
        let response = send_request(&mut stream, request).await;

        // Parse response
        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_none(), "should not have error");
        assert!(response.result.is_some(), "should have result");

        let result = response.result.unwrap();
        assert_eq!(result["initialized"], true);
        assert!(result["version"].is_string());
        assert!(result["supported_chains"].is_array());

        // Cleanup
        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn test_get_address_request() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        let request = r#"{"jsonrpc":"2.0","method":"getAddress","id":2}"#;
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_none(), "should not have error");
        assert!(response.result.is_some(), "should have result");

        let result = response.result.unwrap();
        let address = result["address"].as_str().expect("address string");
        assert!(address.starts_with("0x"), "address should start with 0x");
        assert_eq!(address.len(), 42, "address should be 42 chars");

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn test_invalid_json_request() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        let request = "not valid json";
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_some(), "should have error");
        assert!(response.result.is_none(), "should not have result");

        let error = response.error.unwrap();
        assert_eq!(error.code, -32700, "should be parse error code");

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        let request = r#"{"jsonrpc":"2.0","method":"unknownMethod","id":3}"#;
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_some(), "should have error");
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601, "should be method not found code");

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn test_invalid_jsonrpc_version() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        let request = r#"{"jsonrpc":"1.0","method":"getStatus","id":4}"#;
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_some(), "should have error");
        let error = response.error.unwrap();
        assert_eq!(error.code, -32600, "should be invalid request code");

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    // =========================================================================
    // Sign Request Tests
    // =========================================================================

    #[tokio::test]
    async fn test_sign_invalid_params() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        // Missing required 'transaction' field
        let request = r#"{"jsonrpc":"2.0","method":"sign","params":{},"id":5}"#;
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_some(), "should have error");
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602, "should be invalid params code");

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    #[tokio::test]
    async fn test_sign_invalid_transaction_hex() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

        // Invalid hex
        let request =
            r#"{"jsonrpc":"2.0","method":"sign","params":{"transaction":"not-hex"},"id":6}"#;
        let response = send_request(&mut stream, request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse response");

        assert!(response.error.is_some(), "should have error");
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602, "should be invalid params code");
        assert!(error.message.contains("invalid transaction hex"));

        drop(stream);
        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    // =========================================================================
    // Concurrent Connection Tests
    // =========================================================================

    #[tokio::test]
    async fn test_multiple_concurrent_connections() {
        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let server = create_test_server(socket_path.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn multiple concurrent clients
        let mut handles = vec![];
        for i in 0..5 {
            let path = socket_path.clone();
            let handle = tokio::spawn(async move {
                let mut stream = UnixStream::connect(&path).await.expect("connect");
                let request = format!(r#"{{"jsonrpc":"2.0","method":"getStatus","id":{}}}"#, i);
                let response = send_request(&mut stream, &request).await;
                let response: JsonRpcResponse =
                    serde_json::from_str(&response).expect("parse response");
                assert!(response.error.is_none(), "should not have error");
            });
            handles.push(handle);
        }

        // Wait for all clients to complete
        for handle in handles {
            handle.await.expect("client task");
        }

        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    // =========================================================================
    // Socket Permission Tests
    // =========================================================================

    #[cfg(unix)]
    #[tokio::test]
    async fn test_socket_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().expect("temp dir");
        let socket_path = temp_dir.path().join("txgate.sock");

        let signer = Secp256k1Signer::generate();
        let config = PolicyConfig::new();
        let policy_engine = DefaultPolicyEngine::new(config).expect("policy engine");
        let parser = EthereumParser::new();

        let server_config = ServerConfig {
            socket_path: socket_path.clone(),
            socket_permissions: 0o660, // Custom permissions
        };

        let server = TxGateServer::new(server_config, signer, policy_engine, parser, None);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check permissions
        let metadata = std::fs::metadata(&socket_path).expect("metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket should have 0o660 permissions");

        shutdown_tx.send(()).expect("send shutdown");
        server_handle.await.expect("join").expect("server result");
    }

    // =========================================================================
    // ServerError Tests
    // =========================================================================

    #[test]
    fn test_server_error_display() {
        let bind_error = ServerError::Bind {
            path: PathBuf::from("/tmp/test.sock"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        };
        let display = format!("{bind_error}");
        assert!(display.contains("failed to bind socket"));
        assert!(display.contains("/tmp/test.sock"));

        let perm_error = ServerError::Permissions {
            path: PathBuf::from("/tmp/test.sock"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        };
        let display = format!("{perm_error}");
        assert!(display.contains("failed to set socket permissions"));

        let conn_error =
            ServerError::Connection(std::io::Error::new(std::io::ErrorKind::Other, "conn error"));
        let display = format!("{conn_error}");
        assert!(display.contains("connection error"));

        let read_error =
            ServerError::Read(std::io::Error::new(std::io::ErrorKind::Other, "read error"));
        let display = format!("{read_error}");
        assert!(display.contains("read error"));

        let write_error = ServerError::Write(std::io::Error::new(
            std::io::ErrorKind::Other,
            "write error",
        ));
        let display = format!("{write_error}");
        assert!(display.contains("write error"));

        let parse_error = ServerError::Parse("invalid json".to_string());
        let display = format!("{parse_error}");
        assert!(display.contains("parse error"));
    }
}
