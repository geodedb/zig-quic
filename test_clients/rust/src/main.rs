use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{debug, error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".into()),
        )
        .init();

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let server_name = "localhost";
    let message = "Hello from Rust Quinn!";

    info!("Connecting to {} with server name {}", addr, server_name);

    // Create insecure client config that accepts any certificate
    let client_config = configure_client();

    // Create endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    info!("Establishing QUIC connection...");
    let connection = match endpoint.connect(addr, server_name) {
        Ok(connecting) => {
            match tokio::time::timeout(Duration::from_secs(10), connecting).await {
                Ok(Ok(conn)) => {
                    info!("Connection established!");
                    conn
                }
                Ok(Err(e)) => {
                    error!("Connection failed: {}", e);
                    return Err(e.into());
                }
                Err(_) => {
                    error!("Connection timeout");
                    return Err(anyhow::anyhow!("Connection timeout"));
                }
            }
        }
        Err(e) => {
            error!("Failed to start connection: {}", e);
            return Err(e.into());
        }
    };

    debug!("Connection ID: {:?}", connection.stable_id());

    // Open a bidirectional stream
    info!("Opening bidirectional stream...");
    let (mut send, mut recv) = connection.open_bi().await?;
    info!("Stream opened");

    // Send message
    info!("Sending message: {}", message);
    send.write_all(message.as_bytes()).await?;
    send.finish()?;

    // Read response
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await {
        Ok(Ok(Some(n))) => {
            let response = String::from_utf8_lossy(&buf[..n]);
            info!("Received response ({} bytes): {}", n, response);
        }
        Ok(Ok(None)) => {
            info!("Stream closed by peer");
        }
        Ok(Err(e)) => {
            error!("Failed to read response: {}", e);
        }
        Err(_) => {
            error!("Read timeout");
        }
    }

    // Close connection
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    info!("✓ QUIC connection test successful");
    Ok(())
}

fn configure_client() -> ClientConfig {
    // Create a client config that skips certificate verification
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap()
    ));

    // Configure ALPN
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    config.transport_config(Arc::new(transport));
    config
}

/// A certificate verifier that accepts any certificate
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}