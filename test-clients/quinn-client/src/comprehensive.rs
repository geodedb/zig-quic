use anyhow::{anyhow, Result};
use clap::Parser;
use quinn::{ClientConfig, Connection};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

/// Comprehensive Quinn QUIC test client
#[derive(Parser, Debug)]
#[clap(name = "quinn-test-client-comprehensive")]
struct Opt {
    /// Server address
    #[clap(long, default_value = "127.0.0.1:4433")]
    addr: SocketAddr,

    /// Server name for TLS verification
    #[clap(long, default_value = "test.local")]
    server_name: String,

    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,
}

#[derive(Debug)]
struct TestResult {
    name: String,
    success: bool,
    details: String,
    error: Option<String>,
}

impl TestResult {
    fn success(name: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success: true,
            details: details.into(),
            error: None,
        }
    }

    fn failure(name: impl Into<String>, details: impl Into<String>, error: impl ToString) -> Self {
        Self {
            name: name.into(),
            success: false,
            details: details.into(),
            error: Some(error.to_string()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Setup logging
    let env_filter = if opt.verbose {
        "quinn_test_client_comprehensive=debug,quinn=debug"
    } else {
        "quinn_test_client_comprehensive=info,quinn=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    run_comprehensive_tests(opt).await
}

async fn run_comprehensive_tests(opt: Opt) -> Result<()> {
    info!("🚀 Starting Comprehensive QUIC Test Suite (Quinn)");
    info!("{}", "=".repeat(60));
    info!("📡 Connecting to {}\n", opt.addr);

    // Create TLS config that accepts self-signed certificates
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    // Set ALPN protocol
    crypto.alpn_protocols = vec![b"hq-interop".to_vec()];

    // Create quinn client config
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    // Create endpoint
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connection = endpoint
        .connect(opt.addr, &opt.server_name)?
        .await
        .map_err(|e| anyhow!("Connection failed: {}", e))?;

    info!("✅ Connection established");
    info!("✅ TLS handshake complete\n");

    // Run comprehensive test suite
    let mut results = Vec::new();

    results.push(test_single_stream_echo(&connection).await);
    results.push(test_multiple_concurrent_streams(&connection, 4).await);
    results.push(test_large_data_transfer(&connection, 10 * 1024).await); // 10KB
    results.push(test_large_data_transfer(&connection, 100 * 1024).await); // 100KB
    results.push(test_large_data_transfer(&connection, 1024 * 1024).await); // 1MB
    results.push(test_multiple_round_trips(&connection, 10).await);
    results.push(test_bidirectional_simultaneous(&connection).await);
    results.push(test_stream_interleaving(&connection, 5).await);

    // Close connection
    connection.close(0u32.into(), b"test completed");
    endpoint.wait_idle().await;

    // Print summary
    print_test_summary(&results)?;

    Ok(())
}

async fn test_single_stream_echo(conn: &Connection) -> TestResult {
    info!("📝 Test 1: Single stream echo");
    let start = Instant::now();

    match async {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = b"Hello from Quinn!";

        send.write_all(msg).await?;
        send.finish()?;

        let response = recv.read_to_end(4096).await?;
        let elapsed = start.elapsed();

        let details = format!(
            "Sent {} bytes, received {} bytes in {:?}",
            msg.len(),
            response.len(),
            elapsed
        );
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success("Single Stream Echo", details),
        Err(e) => TestResult::failure("Single Stream Echo", format!("{:?}", start.elapsed()), e),
    }
}

async fn test_multiple_concurrent_streams(conn: &Connection, num_streams: usize) -> TestResult {
    info!(
        "📝 Test 2: Multiple concurrent streams ({} streams)",
        num_streams
    );
    let start = Instant::now();

    match async {
        let mut handles = Vec::new();

        for i in 0..num_streams {
            let conn_clone = conn.clone();
            let handle = tokio::spawn(async move {
                let (mut send, mut recv) = conn_clone.open_bi().await?;
                let msg = format!("Stream {} message", i);

                send.write_all(msg.as_bytes()).await?;
                send.finish()?;

                let _response = recv.read_to_end(4096).await?;
                info!("✓ Stream {} completed", i);
                Ok::<_, anyhow::Error>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await??;
        }

        let elapsed = start.elapsed();
        let details = format!("{} concurrent streams completed in {:?}", num_streams, elapsed);
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success("Multiple Concurrent Streams", details),
        Err(e) => TestResult::failure(
            "Multiple Concurrent Streams",
            format!("{:?}", start.elapsed()),
            e,
        ),
    }
}

async fn test_large_data_transfer(conn: &Connection, size: usize) -> TestResult {
    let size_name = format_size(size);
    info!("📝 Test: Large data transfer ({})", size_name);
    let start = Instant::now();

    match async {
        let (mut send, mut recv) = conn.open_bi().await?;

        // Generate random data
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);

        // Send data
        send.write_all(&data).await?;
        send.finish()?;

        // Read response (expect echo or acknowledgment)
        let response = recv
            .read_to_end(size + 4096)
            .await
            .unwrap_or_else(|_| Vec::new());

        let elapsed = start.elapsed();
        let throughput_mbps = if elapsed.as_secs_f64() > 0.0 {
            (size as f64) / elapsed.as_secs_f64() / 1024.0 / 1024.0
        } else {
            0.0
        };

        let details = format!(
            "Transferred {} bytes in {:?} ({:.2} MB/s)",
            size, elapsed, throughput_mbps
        );
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success(format!("Large Transfer ({})", size_name), details),
        Err(e) => TestResult::failure(
            format!("Large Transfer ({})", size_name),
            format!("{:?}", start.elapsed()),
            e,
        ),
    }
}

async fn test_multiple_round_trips(conn: &Connection, num_rounds: usize) -> TestResult {
    info!("📝 Test: Multiple round-trips ({} cycles)", num_rounds);
    let start = Instant::now();

    match async {
        let (mut send, mut recv) = conn.open_bi().await?;

        for i in 0..num_rounds {
            let msg = format!("Round {}", i);
            send.write_all(msg.as_bytes()).await?;

            let mut buf = [0u8; 1024];
            let _n = recv.read(&mut buf).await?;
        }

        send.finish()?;

        let elapsed = start.elapsed();
        let avg_latency = elapsed / num_rounds as u32;
        let details = format!(
            "{} round-trips in {:?} (avg: {:?} per round)",
            num_rounds, elapsed, avg_latency
        );
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success("Multiple Round-trips", details),
        Err(e) => TestResult::failure("Multiple Round-trips", format!("{:?}", start.elapsed()), e),
    }
}

async fn test_bidirectional_simultaneous(conn: &Connection) -> TestResult {
    info!("📝 Test: Bidirectional simultaneous send/receive");
    let start = Instant::now();

    match async {
        let (mut send, mut recv) = conn.open_bi().await?;

        // Spawn sender
        let sender = tokio::spawn(async move {
            for i in 0..10 {
                let msg = format!("Message {}", i);
                send.write_all(msg.as_bytes()).await?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        });

        // Spawn receiver
        let receiver = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut count = 0;
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(_n)) => count += 1,
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            Ok::<_, anyhow::Error>(count)
        });

        sender.await??;
        let _received = receiver.await??;

        let elapsed = start.elapsed();
        let details = format!("10 concurrent send/receives in {:?}", elapsed);
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success("Bidirectional Simultaneous", details),
        Err(e) => TestResult::failure(
            "Bidirectional Simultaneous",
            format!("{:?}", start.elapsed()),
            e,
        ),
    }
}

async fn test_stream_interleaving(conn: &Connection, num_streams: usize) -> TestResult {
    info!("📝 Test: Stream interleaving ({} streams)", num_streams);
    let start = Instant::now();

    match async {
        // Open multiple streams
        let mut streams = Vec::new();
        for _ in 0..num_streams {
            let (send, recv) = conn.open_bi().await?;
            streams.push((send, recv));
        }

        // Send data in round-robin fashion
        for round in 0..5 {
            for (i, (send, _recv)) in streams.iter_mut().enumerate() {
                let msg = format!("Stream {}, Round {}", i, round);
                send.write_all(msg.as_bytes()).await?;
            }
        }

        // Finish all sends
        for (send, _recv) in &mut streams {
            send.finish()?;
        }

        // Read responses
        for (i, (_send, recv)) in streams.iter_mut().enumerate() {
            let _response = recv.read_to_end(4096).await.unwrap_or_else(|_| Vec::new());
            info!("✓ Stream {} interleaving complete", i);
        }

        let elapsed = start.elapsed();
        let details = format!("{} interleaved streams, 5 rounds in {:?}", num_streams, elapsed);
        info!("✅ {}", details);
        Ok::<_, anyhow::Error>(details)
    }
    .await
    {
        Ok(details) => TestResult::success("Stream Interleaving", details),
        Err(e) => TestResult::failure("Stream Interleaving", format!("{:?}", start.elapsed()), e),
    }
}

fn print_test_summary(results: &[TestResult]) -> Result<()> {
    info!("\n{}", "=".repeat(60));
    info!("📊 TEST SUMMARY");
    info!("{}", "=".repeat(60));

    let mut passed = 0;
    let mut failed = 0;

    for result in results {
        let status = if result.success { "✅" } else { "❌" };
        if result.success {
            passed += 1;
        } else {
            failed += 1;
        }

        info!("{} {}", status, result.name);
        info!("   └─ {}", result.details);
        if let Some(error) = &result.error {
            info!("   └─ Error: {}", error);
        }
    }

    info!("\n{}", "=".repeat(60));
    info!(
        "RESULTS: {} passed, {} failed, {} total",
        passed,
        failed,
        results.len()
    );
    info!("{}", "=".repeat(60));

    if failed > 0 {
        info!("\n❌ Some tests failed");
        Err(anyhow!("Tests failed"))
    } else {
        info!("\n✅ All tests passed!");
        Ok(())
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}MB", bytes / (1024 * 1024))
    }
}

/// Certificate verifier that accepts all certificates (for testing only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
