use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use quinn::{
    ClientConfig, Endpoint, EndpointConfig,
    crypto::rustls::QuicClientConfig,
    default_runtime,
    rustls::{
        self, RootCertStore, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    },
};
use tappers::{AddAddressV4, tokio::AsyncTap};
use tokio::time::sleep;

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }

    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}

fn get_mac_address(interface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{}/address", interface);

    let mac_str = fs::read_to_string(path).map_err(|e| e.to_string()).unwrap();
    let mac_str = mac_str.trim();

    if mac_str.len() != 17 {
        panic!("Wrong mac address: {}", mac_str);
    }

    let mut mac_bytes = [0u8; 6];
    for (i, chunk) in mac_str.split(':').enumerate() {
        mac_bytes[i] = u8::from_str_radix(chunk, 16).map_err(|e| e.to_string())?;
    }
    mac_bytes
}

#[tokio::main]
async fn main() -> () {
    let mut tap = AsyncTap::new().unwrap();
    let inter = tap.name().unwrap();
    let inter_name = inter.name();
    let tap_name = inter_name.to_string_lossy();
    let mac = get_mac_address(&tap_name);
    // let new_addr = Ipv4Addr::new(10, 100, 0, 1);
    // let mut addr_req = AddAddressV4::new(new_addr);
    // addr_req.set_netmask(24);
    // tap.add_addr(addr_req).unwrap();
    // tap.set_up().unwrap();

    sleep(Duration::from_secs(3600)).await;

    // let mut recv_buf = [0; 65536];

    // loop {
    //     let amount = tap.recv(&mut recv_buf).await?;
    //     println!("Received packet: {:?}", &recv_buf[0..amount]);
    // }
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        default_runtime().unwrap(),
    )
    .unwrap();

    let insecure = true;

    let client_config = match insecure {
        true => {
            let verifier = Arc::new(NoCertificateVerification);
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            client_crypto.alpn_protocols = vec![b"linkur".to_vec()];
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()))
        }
        false => ClientConfig::with_platform_verifier(),
    };
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect("127.0.0.1:5001".parse::<SocketAddr>().unwrap(), "localhost")
        .unwrap();
    let connection = conn.await.unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut buf = [0u8; 0xffff];
    let id = "123456";
    buf[0] = 0;
    buf[1] = 0;

    loop {
        // write hello message

        send.write_all(b"hello").await.unwrap();
        // send.finish().unwrap();
        println!("sent");
        sleep(Duration::from_secs(2)).await;
    }
}
