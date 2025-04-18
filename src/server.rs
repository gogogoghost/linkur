use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use env_logger::Builder;
use log::info;
use quinn::{
    Connection, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::QuicServerConfig,
    default_runtime,
    rustls::{self, pki_types::pem::PemObject},
};
use tappers::{AddAddressV4, tokio::AsyncTap};
use tokio::io::AsyncReadExt;

async fn handle_connection(conn: Connection) {
    info!("Incoming connect from: {}", conn.remote_address());
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    let mut buf = [0u8; 65536];
    // 读取22字节 2+16+6
    recv.read_exact(&mut buf[0..24]).await.unwrap();

    let key = &buf[2..18];
    let mac = &buf[18..24];

    loop {
        println!("read");

        let size = recv.read(&mut buf).await.unwrap().unwrap();
        // println!("recv: {}", String::from_utf8_lossy(&buf[0..size]))
        println!("recv: {}", size)
    }
}

#[tokio::main]
async fn main() -> () {
    Builder::new().filter_level(log::LevelFilter::Info).init();
    let cert = PemObject::from_pem_slice(include_bytes!("../test-cert.pem")).unwrap();
    let key = PemObject::from_pem_slice(include_bytes!("../test-key.pem")).unwrap();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"linkur".to_vec()];

    let config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));

    let socket = UdpSocket::bind("0.0.0.0:5001").unwrap();
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(config),
        socket,
        default_runtime().unwrap(),
    )
    .unwrap();

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        match conn.await {
            Ok(connection) => {
                tokio::spawn(handle_connection(connection));
            }
            _ => {}
        }
    }
}
