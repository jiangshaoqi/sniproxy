use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use std::error::Error;
use std::fs;
use std::net::ToSocketAddrs;
use std::sync::Arc;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    // prepare ca root store
    let ca_path = "sniproxy_ca_cert.der";
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(ca_path)?)).expect("failed to add ca cert for client root store");
    

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    // Create a QUIC client endpoint
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // hardcode the server address for test
    let server_addr = "127.0.0.1:4433".to_socket_addrs()?.next().unwrap();
    let connection = endpoint.connect(server_addr, "whatcanisni")?.await.expect("cannot connect to server");
    println!("Connected to {}", connection.remote_address());

    // Open a bi-directional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send a message
    send.write_all(b"Hello, server!").await?;
    send.finish().expect("cannot finish client send");

    // Receive a response
    let buf = recv.read_to_end(usize::MAX).await?;
    println!("Received: {}", String::from_utf8_lossy(&buf));

    // Close the connection
    connection.close(0u32.into(), b"Goodbye!");

    Ok(())
}