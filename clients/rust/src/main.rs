use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let server_addr = if args.len() > 1 {
        args[1].parse().context("Invalid server address")?
    } else {
        "127.0.0.1:4433".parse().unwrap()
    };

    info!("Connecting to {}", server_addr);

    // Run the test
    match run_test(server_addr).await {
        Ok(_) => {
            info!("✅ Test completed successfully!");
            Ok(())
        }
        Err(e) => {
            warn!("❌ Test failed: {}", e);
            Err(e)
        }
    }
}

async fn run_test(server_addr: SocketAddr) -> Result<()> {
    // Create client endpoint with insecure configuration (skip certificate verification)
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    // Configure client to skip certificate verification (for testing only)
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?));

    // Set ALPN protocol
    client_config.transport_config(Arc::new({
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
        transport
    }));

    endpoint.set_default_client_config(client_config);

    // Connect to server
    info!("Initiating connection...");
    let connection = endpoint
        .connect(server_addr, "localhost")?
        .await
        .context("Failed to connect")?;

    info!("✓ Connection established");
    info!("✓ TLS handshake complete");

    // Open a bidirectional stream
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("Failed to open bidirectional stream")?;

    info!("✓ Bidirectional stream opened");

    // Send a test message
    let message = b"Hello from Rust quinn client!\n";
    send.write_all(message)
        .await
        .context("Failed to write to stream")?;
    send.finish()?;

    info!("✓ Sent message: {:?}", String::from_utf8_lossy(message));

    // Try to read response (with timeout)
    match tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024)).await {
        Ok(Ok(response)) => {
            info!("✓ Received response ({} bytes)", response.len());
            if !response.is_empty() {
                info!("Response: {}", String::from_utf8_lossy(&response));
            }
        }
        Ok(Err(e)) => {
            warn!("Failed to read response: {}", e);
        }
        Err(_) => {
            warn!("Timeout waiting for response (this is expected if server doesn't respond)");
        }
    }

    // Close the connection
    connection.close(0u32.into(), b"done");

    // Wait a bit for the close to be sent
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

// Skip server certificate verification (for testing only - DO NOT USE IN PRODUCTION)
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
