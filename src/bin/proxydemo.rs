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

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    // hardcode the server address for test
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:4433".parse()?)
        .expect("failed to create server endpoint");
    println!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
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
    match connection.accept_bi().await {
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
            println!("connection closed");
            return Ok(());
        }
        Err(_e) => {
            println!("connection failed: {reason}", reason = _e.to_string());
            return Ok(());
        }
        Ok((send, recv)) => {

            let (mut send, mut recv) = (send, recv);
            let buf = recv.read_to_end(usize::MAX).await?;
            println!("Received: {}", String::from_utf8_lossy(&buf));

            send.write_all(b"Hello, client!").await?;
            send.finish().expect("cannot finish server send");

            connection.closed().await;
            return Ok(());
        }
    };
    
    Ok(())
}
