//! # Server Module
//!
//! HTTP/gRPC signing server for `TxGate`.
//!
//! ## Submodules
//!
//! - [`protocol`] - JSON-RPC 2.0 protocol types for Unix socket communication
//! - [`socket`] - Unix domain socket server implementation
//!
//! ## Submodules (planned)
//!
//! - `http` - HTTP API server (REST)
//! - `grpc` - gRPC API server
//! - `routes` - API route handlers
//! - `middleware` - Authentication, logging, rate limiting
//! - `state` - Server state management
//!
//! ## API Endpoints (planned)
//!
//! - `POST /v1/sign` - Sign a transaction
//! - `POST /v1/verify` - Verify a signature
//! - `GET /v1/health` - Health check
//! - `GET /v1/keys` - List available signing keys
//! - `GET /v1/policies` - List active policies

pub mod protocol;
pub mod socket;

// Re-export commonly used protocol types for convenience
// These will be used when the Unix socket server implementation is complete
#[allow(unused_imports)]
pub use protocol::{
    error_codes, GetAddressResult, GetStatusResult, JsonRpcError, JsonRpcId, JsonRpcRequest,
    JsonRpcResponse, Method, ParseMethodError, SignParams, SignResult, TransactionDetails,
};

// Re-export socket server types for convenience
pub use socket::{ServerConfig, ServerError, TxGateServer};

// Placeholder for future submodules
// pub mod http;
// pub mod grpc;
// pub mod routes;
// pub mod middleware;
// pub mod state;
