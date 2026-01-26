use anyhow::{Result, anyhow};
use clap::Parser;
use quinn::ClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

/// Simple Quinn QUIC test client
#[derive(Parser, Debug)]
#[clap(name = "quinn-test-client")]
struct Opt {
    /// Server address
    #[clap(long, default_value = "127.0.0.1:3141")]
    addr: SocketAddr,

    /// Server name for TLS verification
    #[clap(long, default_value = "localhost")]
    server_name: String,

    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Setup logging
    let env_filter = if opt.verbose {
        "quinn_test_client=debug,quinn=debug"
    } else {
        "quinn_test_client=info,quinn=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    run_test(opt).await
}

async fn run_test(opt: Opt) -> Result<()> {
    info!("Connecting to {} with server name: {}", opt.addr, opt.server_name);

    // Create TLS config that accepts self-signed certificates
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    // Set ALPN protocol (hq-interop is the standard QUIC interop protocol)
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

    info!("✓ Connection established");
    info!("✓ TLS handshake complete");

    // Open bidirectional stream
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow!("Failed to open stream: {}", e))?;

    info!("✓ Stream opened");

    // Send HTTP/0.9 request
    let request = b"GET /\r\n";
    send.write_all(request)
        .await
        .map_err(|e| anyhow!("Failed to write request: {}", e))?;
    send.finish()
        .map_err(|e| anyhow!("Failed to finish stream: {}", e))?;

    info!("✓ Sent request: {:?}", std::str::from_utf8(request).unwrap());

    // Read response
    let response = recv
        .read_to_end(4096)
        .await
        .map_err(|e| anyhow!("Failed to read response: {}", e))?;

    info!("✓ Received response ({} bytes)", response.len());

    if !response.is_empty() {
        println!("\n--- Response ---");
        println!("{}", String::from_utf8_lossy(&response));
        println!("--- End ---\n");
    }

    // Close connection
    connection.close(0u32.into(), b"done");

    // Wait for connection to close gracefully
    endpoint.wait_idle().await;

    info!("✓ Test completed successfully!");

    Ok(())
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
