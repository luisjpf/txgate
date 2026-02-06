//! # JSON-RPC 2.0 Protocol Types
//!
//! This module defines request/response types for JSON-RPC 2.0 protocol
//! communication over Unix sockets.
//!
//! ## Overview
//!
//! The JSON-RPC 2.0 specification defines a lightweight remote procedure call
//! protocol encoded in JSON. This implementation provides:
//!
//! - Standard JSON-RPC 2.0 request/response types
//! - Error codes (standard and `TxGate`-specific)
//! - `TxGate`-specific method parameters and results
//!
//! ## Example
//!
//! ```rust
//! use txgate::server::protocol::{JsonRpcRequest, JsonRpcResponse, JsonRpcId};
//!
//! let request = JsonRpcRequest {
//!     jsonrpc: "2.0".to_string(),
//!     method: "sign".to_string(),
//!     params: serde_json::json!({"transaction": "0x..."}),
//!     id: JsonRpcId::Number(1),
//! };
//!
//! // Validate the request
//! assert!(request.validate().is_ok());
//! ```

// Allow dead code temporarily - these types will be used when the
// Unix socket server implementation is complete (SELLO-031+)
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Standard JSON-RPC 2.0 error codes and `TxGate`-specific error codes.
pub mod error_codes {
    /// Parse error - Invalid JSON was received by the server.
    pub const PARSE_ERROR: i32 = -32700;

    /// Invalid Request - The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;

    /// Method not found - The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;

    /// Invalid params - Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;

    /// Internal error - Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;

    // Custom TxGate errors (-32000 to -32099)

    /// Policy denied - The signing policy rejected the transaction.
    pub const POLICY_DENIED: i32 = -32001;

    /// Signing error - An error occurred during transaction signing.
    pub const SIGNING_ERROR: i32 = -32002;

    /// Key not found - The requested signing key was not found.
    pub const KEY_NOT_FOUND: i32 = -32003;

    /// Not initialized - The `TxGate` service has not been initialized.
    pub const NOT_INITIALIZED: i32 = -32004;
}

/// JSON-RPC ID type.
///
/// Per the JSON-RPC 2.0 specification, an ID can be a string, number, or null.
/// The server must reply with the same ID that the client provided.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// Numeric identifier
    Number(i64),
    /// String identifier
    String(String),
    /// Null identifier (for notifications that don't expect a response)
    #[default]
    Null,
}

/// JSON-RPC 2.0 request object.
///
/// A request object represents a remote procedure call. It contains:
/// - `jsonrpc`: Protocol version (must be "2.0")
/// - `method`: The name of the method to invoke
/// - `params`: Parameters to pass to the method
/// - `id`: Request identifier for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version (must be "2.0")
    pub jsonrpc: String,

    /// The name of the method to be invoked
    pub method: String,

    /// Parameters for the method (defaults to null/empty)
    #[serde(default)]
    pub params: serde_json::Value,

    /// Request identifier for correlating requests and responses
    pub id: JsonRpcId,
}

impl JsonRpcRequest {
    /// Validates that this request conforms to JSON-RPC 2.0 specification.
    ///
    /// # Errors
    ///
    /// Returns a `JsonRpcError` if:
    /// - The `jsonrpc` field is not "2.0"
    /// - The `method` field is empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate::server::protocol::{JsonRpcRequest, JsonRpcId};
    ///
    /// let valid_request = JsonRpcRequest {
    ///     jsonrpc: "2.0".to_string(),
    ///     method: "sign".to_string(),
    ///     params: serde_json::Value::Null,
    ///     id: JsonRpcId::Number(1),
    /// };
    /// assert!(valid_request.validate().is_ok());
    ///
    /// let invalid_request = JsonRpcRequest {
    ///     jsonrpc: "1.0".to_string(),
    ///     method: "sign".to_string(),
    ///     params: serde_json::Value::Null,
    ///     id: JsonRpcId::Number(1),
    /// };
    /// assert!(invalid_request.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), JsonRpcError> {
        if self.jsonrpc != "2.0" {
            return Err(JsonRpcError::invalid_request(
                "jsonrpc version must be \"2.0\"",
            ));
        }

        if self.method.is_empty() {
            return Err(JsonRpcError::invalid_request("method cannot be empty"));
        }

        Ok(())
    }
}

/// JSON-RPC 2.0 response object.
///
/// A response object is sent in reply to a request. It contains either
/// a `result` (on success) or an `error` (on failure), but never both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC protocol version (always "2.0")
    pub jsonrpc: String,

    /// The result of the method invocation (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error information (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,

    /// Request identifier (matches the request's id)
    pub id: JsonRpcId,
}

impl JsonRpcResponse {
    /// Creates a successful response with the given result.
    ///
    /// # Arguments
    ///
    /// * `id` - The request ID to correlate with
    /// * `result` - The result value (must be serializable)
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate::server::protocol::{JsonRpcResponse, JsonRpcId};
    ///
    /// let response = JsonRpcResponse::success(
    ///     JsonRpcId::Number(1),
    ///     serde_json::json!({"signature": "0x..."})
    /// );
    /// assert!(response.result.is_some());
    /// assert!(response.error.is_none());
    /// ```
    pub fn success(id: JsonRpcId, result: impl Serialize) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::to_value(result).unwrap_or(serde_json::Value::Null)),
            error: None,
            id,
        }
    }

    /// Creates an error response.
    ///
    /// # Arguments
    ///
    /// * `id` - The request ID to correlate with
    /// * `error` - The error information
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate::server::protocol::{JsonRpcResponse, JsonRpcError, JsonRpcId};
    ///
    /// let response = JsonRpcResponse::error(
    ///     JsonRpcId::Number(1),
    ///     JsonRpcError::method_not_found("unknown_method")
    /// );
    /// assert!(response.result.is_none());
    /// assert!(response.error.is_some());
    /// ```
    #[must_use]
    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// JSON-RPC 2.0 error object.
///
/// When a call encounters an error, the response contains this error object
/// with details about what went wrong.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    /// Error code indicating the type of error
    pub code: i32,

    /// Human-readable error message
    pub message: String,

    /// Additional error data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// Creates a parse error response.
    ///
    /// Use this when invalid JSON was received by the server.
    #[must_use]
    pub fn parse_error(message: &str) -> Self {
        Self {
            code: error_codes::PARSE_ERROR,
            message: format!("Parse error: {message}"),
            data: None,
        }
    }

    /// Creates an invalid request error response.
    ///
    /// Use this when the JSON sent is not a valid Request object.
    #[must_use]
    pub fn invalid_request(message: &str) -> Self {
        Self {
            code: error_codes::INVALID_REQUEST,
            message: format!("Invalid request: {message}"),
            data: None,
        }
    }

    /// Creates a method not found error response.
    ///
    /// Use this when the requested method does not exist.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: error_codes::METHOD_NOT_FOUND,
            message: format!("Method not found: {method}"),
            data: None,
        }
    }

    /// Creates an invalid params error response.
    ///
    /// Use this when the method parameters are invalid.
    #[must_use]
    pub fn invalid_params(message: &str) -> Self {
        Self {
            code: error_codes::INVALID_PARAMS,
            message: format!("Invalid params: {message}"),
            data: None,
        }
    }

    /// Creates an internal error response.
    ///
    /// Use this for internal JSON-RPC errors.
    #[must_use]
    pub fn internal_error(message: &str) -> Self {
        Self {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Internal error: {message}"),
            data: None,
        }
    }

    /// Creates a policy denied error response.
    ///
    /// Use this when the signing policy rejected the transaction.
    #[must_use]
    pub fn policy_denied(reason: &str) -> Self {
        Self {
            code: error_codes::POLICY_DENIED,
            message: format!("Policy denied: {reason}"),
            data: None,
        }
    }

    /// Creates a signing error response.
    ///
    /// Use this when an error occurs during transaction signing.
    #[must_use]
    pub fn signing_error(message: &str) -> Self {
        Self {
            code: error_codes::SIGNING_ERROR,
            message: format!("Signing error: {message}"),
            data: None,
        }
    }

    /// Creates a key not found error response.
    ///
    /// Use this when the requested signing key was not found.
    #[must_use]
    pub fn key_not_found(key_id: &str) -> Self {
        Self {
            code: error_codes::KEY_NOT_FOUND,
            message: format!("Key not found: {key_id}"),
            data: None,
        }
    }

    /// Creates a not initialized error response.
    ///
    /// Use this when the `TxGate` service has not been initialized.
    #[must_use]
    pub fn not_initialized(message: &str) -> Self {
        Self {
            code: error_codes::NOT_INITIALIZED,
            message: format!("Not initialized: {message}"),
            data: None,
        }
    }
}

/// Available JSON-RPC methods supported by `TxGate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Sign a transaction
    Sign,
    /// Get the signing address
    GetAddress,
    /// Get the service status
    GetStatus,
}

/// Error returned when parsing an unknown method name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMethodError {
    /// The unknown method name that failed to parse.
    pub method: String,
}

impl std::fmt::Display for ParseMethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown method: {}", self.method)
    }
}

impl std::error::Error for ParseMethodError {}

impl std::str::FromStr for Method {
    type Err = ParseMethodError;

    /// Parses a method name string into a Method enum.
    ///
    /// # Errors
    ///
    /// Returns a `ParseMethodError` if the method name is not recognized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate::server::protocol::Method;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(Method::from_str("sign"), Ok(Method::Sign));
    /// assert_eq!(Method::from_str("getAddress"), Ok(Method::GetAddress));
    /// assert_eq!(Method::from_str("getStatus"), Ok(Method::GetStatus));
    /// assert!(Method::from_str("unknown").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sign" => Ok(Self::Sign),
            "getAddress" | "get_address" => Ok(Self::GetAddress),
            "getStatus" | "get_status" => Ok(Self::GetStatus),
            _ => Err(ParseMethodError {
                method: s.to_string(),
            }),
        }
    }
}

impl Method {
    /// Returns the canonical method name string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::GetAddress => "getAddress",
            Self::GetStatus => "getStatus",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Default chain identifier for sign requests.
fn default_chain() -> String {
    "ethereum".to_string()
}

/// Parameters for the `sign` method.
///
/// Contains the transaction data and optional chain identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignParams {
    /// Raw transaction hex (with or without 0x prefix)
    pub transaction: String,

    /// Chain identifier (default: "ethereum")
    #[serde(default = "default_chain")]
    pub chain: String,
}

/// Result of the `sign` method.
///
/// Contains the signature components and parsed transaction details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// Transaction hash
    pub tx_hash: String,

    /// Signature r value (hex encoded)
    pub r: String,

    /// Signature s value (hex encoded)
    pub s: String,

    /// Recovery id (v)
    pub v: u8,

    /// Full signature hex (65 bytes: r || s || v)
    pub signature: String,

    /// Fully assembled signed transaction (hex encoded), ready for broadcast.
    /// Only present for chains that support transaction assembly (e.g., Ethereum).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_transaction: Option<String>,

    /// Parsed transaction details
    pub transaction: TransactionDetails,
}

/// Parsed transaction details included in sign response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetails {
    /// Transaction type (e.g., "legacy", "eip1559", "eip2930")
    pub tx_type: String,

    /// Recipient address (None for contract creation)
    pub recipient: Option<String>,

    /// Transaction value/amount in wei (as string to preserve precision)
    pub amount: String,

    /// Token contract address for token transfers (None for native transfers)
    pub token: Option<String>,

    /// Transaction nonce
    pub nonce: u64,

    /// Chain ID
    pub chain_id: u64,
}

/// Result of the `getAddress` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAddressResult {
    /// The signing address (hex encoded with 0x prefix)
    pub address: String,
}

/// Result of the `getStatus` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusResult {
    /// Whether the service is initialized and ready
    pub initialized: bool,

    /// Service version
    pub version: String,

    /// Supported chains
    pub supported_chains: Vec<String>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::manual_string_new,
        clippy::assertions_on_constants,
        clippy::stable_sort_primitive
    )]

    use super::*;
    use serde_json::json;

    mod json_rpc_id {
        use super::*;

        #[test]
        fn test_serialize_number_id() {
            let id = JsonRpcId::Number(42);
            let json = serde_json::to_string(&id).expect("should serialize");
            assert_eq!(json, "42");
        }

        #[test]
        fn test_serialize_string_id() {
            let id = JsonRpcId::String("test-123".to_string());
            let json = serde_json::to_string(&id).expect("should serialize");
            assert_eq!(json, "\"test-123\"");
        }

        #[test]
        fn test_serialize_null_id() {
            let id = JsonRpcId::Null;
            let json = serde_json::to_string(&id).expect("should serialize");
            assert_eq!(json, "null");
        }

        #[test]
        fn test_deserialize_number_id() {
            let id: JsonRpcId = serde_json::from_str("42").expect("should deserialize");
            assert_eq!(id, JsonRpcId::Number(42));
        }

        #[test]
        fn test_deserialize_string_id() {
            let id: JsonRpcId = serde_json::from_str("\"test-123\"").expect("should deserialize");
            assert_eq!(id, JsonRpcId::String("test-123".to_string()));
        }

        #[test]
        fn test_deserialize_null_id() {
            let id: JsonRpcId = serde_json::from_str("null").expect("should deserialize");
            assert_eq!(id, JsonRpcId::Null);
        }

        #[test]
        fn test_default_is_null() {
            assert_eq!(JsonRpcId::default(), JsonRpcId::Null);
        }
    }

    mod json_rpc_request {
        use super::*;

        #[test]
        fn test_serialize_request() {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "sign".to_string(),
                params: json!({"transaction": "0xabc"}),
                id: JsonRpcId::Number(1),
            };

            let json = serde_json::to_value(&request).expect("should serialize");
            assert_eq!(json["jsonrpc"], "2.0");
            assert_eq!(json["method"], "sign");
            assert_eq!(json["params"]["transaction"], "0xabc");
            assert_eq!(json["id"], 1);
        }

        #[test]
        fn test_deserialize_request() {
            let json =
                r#"{"jsonrpc":"2.0","method":"sign","params":{"transaction":"0xabc"},"id":1}"#;
            let request: JsonRpcRequest = serde_json::from_str(json).expect("should deserialize");

            assert_eq!(request.jsonrpc, "2.0");
            assert_eq!(request.method, "sign");
            assert_eq!(request.params["transaction"], "0xabc");
            assert_eq!(request.id, JsonRpcId::Number(1));
        }

        #[test]
        fn test_deserialize_request_without_params() {
            let json = r#"{"jsonrpc":"2.0","method":"getStatus","id":"abc"}"#;
            let request: JsonRpcRequest = serde_json::from_str(json).expect("should deserialize");

            assert_eq!(request.jsonrpc, "2.0");
            assert_eq!(request.method, "getStatus");
            assert!(request.params.is_null());
            assert_eq!(request.id, JsonRpcId::String("abc".to_string()));
        }

        #[test]
        fn test_validate_valid_request() {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "sign".to_string(),
                params: json!({}),
                id: JsonRpcId::Number(1),
            };

            assert!(request.validate().is_ok());
        }

        #[test]
        fn test_validate_wrong_version() {
            let request = JsonRpcRequest {
                jsonrpc: "1.0".to_string(),
                method: "sign".to_string(),
                params: json!({}),
                id: JsonRpcId::Number(1),
            };

            let err = request.validate().expect_err("should fail validation");
            assert_eq!(err.code, error_codes::INVALID_REQUEST);
            assert!(err.message.contains("2.0"));
        }

        #[test]
        fn test_validate_empty_method() {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "".to_string(),
                params: json!({}),
                id: JsonRpcId::Number(1),
            };

            let err = request.validate().expect_err("should fail validation");
            assert_eq!(err.code, error_codes::INVALID_REQUEST);
            assert!(err.message.contains("empty"));
        }
    }

    mod json_rpc_response {
        use super::*;

        #[test]
        fn test_success_response() {
            let response = JsonRpcResponse::success(JsonRpcId::Number(1), json!({"result": "ok"}));

            assert_eq!(response.jsonrpc, "2.0");
            assert!(response.result.is_some());
            assert!(response.error.is_none());
            assert_eq!(response.id, JsonRpcId::Number(1));
        }

        #[test]
        fn test_error_response() {
            let response = JsonRpcResponse::error(
                JsonRpcId::Number(1),
                JsonRpcError::method_not_found("unknown"),
            );

            assert_eq!(response.jsonrpc, "2.0");
            assert!(response.result.is_none());
            assert!(response.error.is_some());
            assert_eq!(response.id, JsonRpcId::Number(1));
        }

        #[test]
        fn test_serialize_success_response_excludes_error() {
            let response = JsonRpcResponse::success(JsonRpcId::Number(1), json!({"value": 42}));
            let json = serde_json::to_value(&response).expect("should serialize");

            assert!(json.get("result").is_some());
            assert!(json.get("error").is_none());
        }

        #[test]
        fn test_serialize_error_response_excludes_result() {
            let response =
                JsonRpcResponse::error(JsonRpcId::Number(1), JsonRpcError::internal_error("test"));
            let json = serde_json::to_value(&response).expect("should serialize");

            assert!(json.get("result").is_none());
            assert!(json.get("error").is_some());
        }
    }

    mod json_rpc_error {
        use super::*;

        #[test]
        fn test_parse_error() {
            let err = JsonRpcError::parse_error("invalid JSON");
            assert_eq!(err.code, error_codes::PARSE_ERROR);
            assert!(err.message.contains("invalid JSON"));
        }

        #[test]
        fn test_invalid_request() {
            let err = JsonRpcError::invalid_request("missing field");
            assert_eq!(err.code, error_codes::INVALID_REQUEST);
            assert!(err.message.contains("missing field"));
        }

        #[test]
        fn test_method_not_found() {
            let err = JsonRpcError::method_not_found("unknownMethod");
            assert_eq!(err.code, error_codes::METHOD_NOT_FOUND);
            assert!(err.message.contains("unknownMethod"));
        }

        #[test]
        fn test_invalid_params() {
            let err = JsonRpcError::invalid_params("missing transaction");
            assert_eq!(err.code, error_codes::INVALID_PARAMS);
            assert!(err.message.contains("missing transaction"));
        }

        #[test]
        fn test_internal_error() {
            let err = JsonRpcError::internal_error("database failure");
            assert_eq!(err.code, error_codes::INTERNAL_ERROR);
            assert!(err.message.contains("database failure"));
        }

        #[test]
        fn test_policy_denied() {
            let err = JsonRpcError::policy_denied("amount exceeds limit");
            assert_eq!(err.code, error_codes::POLICY_DENIED);
            assert!(err.message.contains("amount exceeds limit"));
        }

        #[test]
        fn test_signing_error() {
            let err = JsonRpcError::signing_error("key unavailable");
            assert_eq!(err.code, error_codes::SIGNING_ERROR);
            assert!(err.message.contains("key unavailable"));
        }

        #[test]
        fn test_key_not_found() {
            let err = JsonRpcError::key_not_found("default");
            assert_eq!(err.code, error_codes::KEY_NOT_FOUND);
            assert!(err.message.contains("default"));
        }

        #[test]
        fn test_not_initialized() {
            let err = JsonRpcError::not_initialized("run txgate init first");
            assert_eq!(err.code, error_codes::NOT_INITIALIZED);
            assert!(err.message.contains("run txgate init first"));
        }

        #[test]
        fn test_serialize_error_with_data() {
            let mut err = JsonRpcError::invalid_params("validation failed");
            err.data = Some(json!({"field": "transaction", "reason": "too short"}));

            let json = serde_json::to_value(&err).expect("should serialize");
            assert!(json.get("data").is_some());
            assert_eq!(json["data"]["field"], "transaction");
        }

        #[test]
        fn test_serialize_error_without_data_excludes_field() {
            let err = JsonRpcError::invalid_params("validation failed");
            let json = serde_json::to_value(&err).expect("should serialize");

            assert!(json.get("data").is_none());
        }
    }

    mod error_codes_tests {
        use super::error_codes::{
            INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, KEY_NOT_FOUND, METHOD_NOT_FOUND,
            NOT_INITIALIZED, PARSE_ERROR, POLICY_DENIED, SIGNING_ERROR,
        };

        #[test]
        fn test_standard_error_codes() {
            assert_eq!(PARSE_ERROR, -32700);
            assert_eq!(INVALID_REQUEST, -32600);
            assert_eq!(METHOD_NOT_FOUND, -32601);
            assert_eq!(INVALID_PARAMS, -32602);
            assert_eq!(INTERNAL_ERROR, -32603);
        }

        #[test]
        fn test_txgate_error_codes_in_custom_range() {
            // Custom error codes must be in -32000 to -32099 range
            assert!(POLICY_DENIED >= -32099 && POLICY_DENIED <= -32000);
            assert!(SIGNING_ERROR >= -32099 && SIGNING_ERROR <= -32000);
            assert!(KEY_NOT_FOUND >= -32099 && KEY_NOT_FOUND <= -32000);
            assert!(NOT_INITIALIZED >= -32099 && NOT_INITIALIZED <= -32000);
        }

        #[test]
        fn test_txgate_error_codes_are_unique() {
            let codes = [POLICY_DENIED, SIGNING_ERROR, KEY_NOT_FOUND, NOT_INITIALIZED];
            let mut unique_codes = codes.to_vec();
            unique_codes.sort();
            unique_codes.dedup();
            assert_eq!(
                codes.len(),
                unique_codes.len(),
                "error codes must be unique"
            );
        }
    }

    mod method {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn test_from_str_sign() {
            assert_eq!(Method::from_str("sign"), Ok(Method::Sign));
        }

        #[test]
        fn test_from_str_get_address() {
            assert_eq!(Method::from_str("getAddress"), Ok(Method::GetAddress));
            assert_eq!(Method::from_str("get_address"), Ok(Method::GetAddress));
        }

        #[test]
        fn test_from_str_get_status() {
            assert_eq!(Method::from_str("getStatus"), Ok(Method::GetStatus));
            assert_eq!(Method::from_str("get_status"), Ok(Method::GetStatus));
        }

        #[test]
        fn test_from_str_unknown() {
            assert!(Method::from_str("unknown").is_err());
            assert!(Method::from_str("").is_err());
            assert!(Method::from_str("Sign").is_err()); // case sensitive
        }

        #[test]
        fn test_parse_method_error_display() {
            let err = ParseMethodError {
                method: "unknown".to_string(),
            };
            assert!(err.to_string().contains("unknown"));
        }

        #[test]
        fn test_as_str() {
            assert_eq!(Method::Sign.as_str(), "sign");
            assert_eq!(Method::GetAddress.as_str(), "getAddress");
            assert_eq!(Method::GetStatus.as_str(), "getStatus");
        }

        #[test]
        fn test_display() {
            assert_eq!(format!("{}", Method::Sign), "sign");
            assert_eq!(format!("{}", Method::GetAddress), "getAddress");
            assert_eq!(format!("{}", Method::GetStatus), "getStatus");
        }
    }

    mod sign_params {
        use super::*;

        #[test]
        fn test_deserialize_with_chain() {
            let json = r#"{"transaction":"0xabc123","chain":"polygon"}"#;
            let params: SignParams = serde_json::from_str(json).expect("should deserialize");

            assert_eq!(params.transaction, "0xabc123");
            assert_eq!(params.chain, "polygon");
        }

        #[test]
        fn test_deserialize_default_chain() {
            let json = r#"{"transaction":"0xabc123"}"#;
            let params: SignParams = serde_json::from_str(json).expect("should deserialize");

            assert_eq!(params.transaction, "0xabc123");
            assert_eq!(params.chain, "ethereum");
        }

        #[test]
        fn test_serialize() {
            let params = SignParams {
                transaction: "0xabc".to_string(),
                chain: "ethereum".to_string(),
            };

            let json = serde_json::to_value(&params).expect("should serialize");
            assert_eq!(json["transaction"], "0xabc");
            assert_eq!(json["chain"], "ethereum");
        }
    }

    mod sign_result {
        use super::*;

        #[test]
        fn test_serialize() {
            let result = SignResult {
                tx_hash: "0xabc123".to_string(),
                r: "0x1234".to_string(),
                s: "0x5678".to_string(),
                v: 27,
                signature: "0x123456789...".to_string(),
                signed_transaction: Some("0xsigned".to_string()),
                transaction: TransactionDetails {
                    tx_type: "eip1559".to_string(),
                    recipient: Some("0xrecipient".to_string()),
                    amount: "1000000000000000000".to_string(),
                    token: None,
                    nonce: 5,
                    chain_id: 1,
                },
            };

            let json = serde_json::to_value(&result).expect("should serialize");
            assert_eq!(json["tx_hash"], "0xabc123");
            assert_eq!(json["v"], 27);
            assert_eq!(json["signed_transaction"], "0xsigned");
            assert_eq!(json["transaction"]["tx_type"], "eip1559");
            assert_eq!(json["transaction"]["nonce"], 5);
        }

        #[test]
        fn test_deserialize() {
            let json = r#"{
                "tx_hash": "0xabc",
                "r": "0x1",
                "s": "0x2",
                "v": 28,
                "signature": "0xfull",
                "transaction": {
                    "tx_type": "legacy",
                    "recipient": null,
                    "amount": "0",
                    "token": "0xtoken",
                    "nonce": 0,
                    "chain_id": 137
                }
            }"#;

            let result: SignResult = serde_json::from_str(json).expect("should deserialize");
            assert_eq!(result.tx_hash, "0xabc");
            assert_eq!(result.v, 28);
            assert!(result.signed_transaction.is_none());
            assert!(result.transaction.recipient.is_none());
            assert_eq!(result.transaction.token, Some("0xtoken".to_string()));
            assert_eq!(result.transaction.chain_id, 137);
        }

        #[test]
        fn test_signed_transaction_none_omitted_in_json() {
            let result = SignResult {
                tx_hash: "0xabc".to_string(),
                r: "0x1".to_string(),
                s: "0x2".to_string(),
                v: 0,
                signature: "0xfull".to_string(),
                signed_transaction: None,
                transaction: TransactionDetails {
                    tx_type: "legacy".to_string(),
                    recipient: None,
                    amount: "0".to_string(),
                    token: None,
                    nonce: 0,
                    chain_id: 1,
                },
            };

            let json = serde_json::to_value(&result).expect("should serialize");
            assert!(
                json.get("signed_transaction").is_none(),
                "None signed_transaction should be omitted from JSON"
            );
        }
    }

    mod transaction_details {
        use super::*;

        #[test]
        fn test_serialize_with_optional_fields() {
            let details = TransactionDetails {
                tx_type: "eip1559".to_string(),
                recipient: Some("0xabc".to_string()),
                amount: "1000".to_string(),
                token: Some("0xtoken".to_string()),
                nonce: 10,
                chain_id: 1,
            };

            let json = serde_json::to_value(&details).expect("should serialize");
            assert_eq!(json["recipient"], "0xabc");
            assert_eq!(json["token"], "0xtoken");
        }

        #[test]
        fn test_serialize_without_optional_fields() {
            let details = TransactionDetails {
                tx_type: "legacy".to_string(),
                recipient: None,
                amount: "0".to_string(),
                token: None,
                nonce: 0,
                chain_id: 1,
            };

            let json = serde_json::to_value(&details).expect("should serialize");
            assert!(json["recipient"].is_null());
            assert!(json["token"].is_null());
        }
    }

    mod get_address_result {
        use super::*;

        #[test]
        fn test_serialize() {
            let result = GetAddressResult {
                address: "0x1234567890abcdef".to_string(),
            };

            let json = serde_json::to_value(&result).expect("should serialize");
            assert_eq!(json["address"], "0x1234567890abcdef");
        }
    }

    mod get_status_result {
        use super::*;

        #[test]
        fn test_serialize() {
            let result = GetStatusResult {
                initialized: true,
                version: "1.0.0".to_string(),
                supported_chains: vec!["ethereum".to_string(), "polygon".to_string()],
            };

            let json = serde_json::to_value(&result).expect("should serialize");
            assert_eq!(json["initialized"], true);
            assert_eq!(json["version"], "1.0.0");
            assert_eq!(json["supported_chains"].as_array().unwrap().len(), 2);
        }
    }
}
