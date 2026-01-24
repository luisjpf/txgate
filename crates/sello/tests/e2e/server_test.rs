//! Server integration tests for concurrent requests and stress testing.
//!
//! These tests verify the Unix socket server handles concurrent connections,
//! multiple simultaneous signing requests, and graceful shutdown.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args
)]

use alloy_primitives::U256;
use sello::server::protocol::{JsonRpcId, JsonRpcResponse};
use sello::server::socket::{SelloServer, ServerConfig};
use sello_chain::EthereumParser;
use sello_crypto::signer::Secp256k1Signer;
use sello_policy::config::PolicyConfig;
use sello_policy::engine::DefaultPolicyEngine;
use sello_policy::history::TransactionHistory;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use super::test_utils::{addresses, create_test_transaction, ONE_ETH};

/// Helper to create a test server with custom policy.
fn create_test_server_with_policy(
    socket_path: PathBuf,
    policy_config: PolicyConfig,
    history: Arc<TransactionHistory>,
) -> SelloServer<Secp256k1Signer> {
    let signer = Secp256k1Signer::generate();
    let policy_engine = DefaultPolicyEngine::new(policy_config, history).expect("policy engine");
    let parser = EthereumParser::new();

    let server_config = ServerConfig {
        socket_path,
        socket_permissions: 0o600,
    };

    SelloServer::new(server_config, signer, policy_engine, parser, None)
}

/// Helper to create a test server with default policy.
fn create_test_server(socket_path: PathBuf) -> SelloServer<Secp256k1Signer> {
    let history = Arc::new(TransactionHistory::in_memory().expect("history"));
    let policy_config = PolicyConfig::new();
    create_test_server_with_policy(socket_path, policy_config, history)
}

/// Helper to send a JSON-RPC request and get response.
async fn send_request(stream: &mut UnixStream, request: &str) -> String {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    writer.write_all(request.as_bytes()).await.expect("write");
    writer.write_all(b"\n").await.expect("write newline");
    writer.flush().await.expect("flush");

    let mut response = String::new();
    reader.read_line(&mut response).await.expect("read");
    response
}

// =============================================================================
// Concurrent Connection Tests
// =============================================================================

#[tokio::test]
async fn test_many_concurrent_connections() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn 20 concurrent clients
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for i in 0..20 {
        let path = socket_path.clone();
        let counter = Arc::clone(&success_count);

        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&path).await.expect("connect");
            let request = format!(r#"{{"jsonrpc":"2.0","method":"getStatus","id":{}}}"#, i);
            let response = send_request(&mut stream, &request).await;

            let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse");
            if response.error.is_none() && response.result.is_some() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("client task");
    }

    assert_eq!(success_count.load(Ordering::SeqCst), 20);

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}

#[tokio::test]
async fn test_concurrent_sign_requests() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    // Create server with no limits for this test
    let history = Arc::new(TransactionHistory::in_memory().expect("history"));
    let policy_config = PolicyConfig::new();
    let server = create_test_server_with_policy(socket_path.clone(), policy_config, history);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create test transaction
    let tx_bytes = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    // Send 10 concurrent sign requests (same tx is fine, different nonces would be better in real use)
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for i in 0..10 {
        let path = socket_path.clone();
        let tx = tx_hex.clone();
        let counter = Arc::clone(&success_count);

        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&path).await.expect("connect");
            let request = format!(
                r#"{{"jsonrpc":"2.0","method":"sign","params":{{"transaction":"{}"}},"id":{}}}"#,
                tx, i
            );
            let response = send_request(&mut stream, &request).await;

            let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse");
            if response.error.is_none() && response.result.is_some() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("client task");
    }

    // All requests should succeed
    assert_eq!(success_count.load(Ordering::SeqCst), 10);

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}

#[tokio::test]
async fn test_rapid_connect_disconnect() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Rapidly connect and disconnect 50 times
    for _ in 0..50 {
        let stream = UnixStream::connect(&socket_path).await.expect("connect");
        drop(stream);
    }

    // Server should still be responsive
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
    let request = r#"{"jsonrpc":"2.0","method":"getStatus","id":999}"#;
    let response = send_request(&mut stream, request).await;

    let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse");
    assert!(response.error.is_none());

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}

#[tokio::test]
async fn test_multiple_requests_same_connection() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Single connection, multiple requests
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    for i in 0..10 {
        let request = format!(r#"{{"jsonrpc":"2.0","method":"getStatus","id":{}}}"#, i);
        let response = send_request(&mut stream, &request).await;

        let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse");
        assert!(response.error.is_none());
        assert_eq!(response.id, JsonRpcId::Number(i));
    }

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}

// =============================================================================
// Stress Tests
// =============================================================================

#[tokio::test]
async fn test_sustained_load() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let success_count = Arc::new(AtomicUsize::new(0));

    // Run sustained load for 2 seconds
    let start = std::time::Instant::now();
    let mut handles = vec![];

    while start.elapsed() < Duration::from_secs(2) {
        let path = socket_path.clone();
        let counter = Arc::clone(&success_count);

        let handle = tokio::spawn(async move {
            if let Ok(mut stream) = UnixStream::connect(&path).await {
                let request = r#"{"jsonrpc":"2.0","method":"getStatus","id":1}"#;
                if send_request(&mut stream, request)
                    .await
                    .contains("initialized")
                {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);

        // Small delay to avoid overwhelming the system
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for handle in handles {
        let _ = handle.await;
    }

    // Should have processed many requests successfully
    let count = success_count.load(Ordering::SeqCst);
    assert!(count > 50, "Expected many successful requests, got {count}");

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}

// =============================================================================
// Graceful Shutdown Tests
// =============================================================================

#[tokio::test]
async fn test_graceful_shutdown_with_active_connections() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish some connections
    let _conn1 = UnixStream::connect(&socket_path).await.expect("connect");
    let _conn2 = UnixStream::connect(&socket_path).await.expect("connect");

    // Send shutdown while connections are active
    shutdown_tx.send(()).expect("send shutdown");

    // Server should shut down cleanly
    let result = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server should stop in time")
        .expect("join handle");

    assert!(result.is_ok(), "server should shut down cleanly");

    // Socket file should be cleaned up
    assert!(!socket_path.exists(), "socket file should be removed");
}

#[tokio::test]
async fn test_shutdown_removes_socket_file() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify socket exists
    assert!(socket_path.exists());

    // Shutdown
    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");

    // Socket should be gone
    assert!(!socket_path.exists());
}

// =============================================================================
// Error Handling Under Load
// =============================================================================

#[tokio::test]
async fn test_invalid_requests_dont_affect_valid_ones() {
    let temp_dir = TempDir::new().expect("temp dir");
    let socket_path = temp_dir.path().join("sello.sock");

    let server = create_test_server(socket_path.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let success_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Mix of valid and invalid requests
    for i in 0..20 {
        let path = socket_path.clone();
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);

        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&path).await.expect("connect");

            let request = if i % 3 == 0 {
                // Invalid request
                "not valid json".to_string()
            } else {
                // Valid request
                format!(r#"{{"jsonrpc":"2.0","method":"getStatus","id":{}}}"#, i)
            };

            let response = send_request(&mut stream, &request).await;
            let response: JsonRpcResponse = serde_json::from_str(&response).expect("parse");

            if response.error.is_some() {
                errors.fetch_add(1, Ordering::SeqCst);
            } else {
                success.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("client task");
    }

    // Should have both successes and errors
    let successes = success_count.load(Ordering::SeqCst);
    let errors = error_count.load(Ordering::SeqCst);

    assert!(successes > 0, "should have successful requests");
    assert!(
        errors > 0,
        "should have error responses for invalid requests"
    );
    assert_eq!(successes + errors, 20, "all requests should be processed");

    shutdown_tx.send(()).expect("send shutdown");
    server_handle.await.expect("join").expect("server result");
}
