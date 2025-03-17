use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::usize;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    let key_vec = std::fs::read("sniproxy_server_key.der")?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_vec));
    let cert_vec = std::fs::read("sniproxy_server_cert.der")?;
    let certs = vec![CertificateDer::from(cert_vec)];

    // todo!("in the second stage, sni certificate is not required");
    let mut proxy_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    proxy_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut proxy_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(proxy_crypto)?));
    let transport_config = Arc::get_mut(&mut proxy_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    todo!("proxy endpoint is not implemented yet");
    let endpoint = quinn::Endpoint::proxy(proxy_config, "127.0.0.1:1080".parse()?)
        .expect("failed to create server endpoint");
    println!("listening on {}", endpoint.local_addr()?);

    todo!("proxy_accept is not implemented yet");
    while let Some(conn) = endpoint.proxy_accept().await {
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                println!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}


#[allow(unreachable_code)]
async fn handle_connection(conn: quinn::Incoming) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let connection = conn.await?;
    todo!("connection peek sni is not implemented yet");
    let sni = connection.peek_sni();
    todo!("connection bridge_to sni is not implemented yet");
    connection.bridge_to(sni).await?;
    Ok(())
}
