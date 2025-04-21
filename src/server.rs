use std::{collections::HashMap, net::UdpSocket, sync::Arc};

use base64::{Engine, engine::general_purpose};
use env_logger::Builder;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use quinn::{
    Connection, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::QuicServerConfig,
    default_runtime,
    rustls::{self, pki_types::pem::PemObject},
};
use tokio::sync::{
    Mutex,
    mpsc::{self, Sender},
};

struct User {
    id: Vec<u8>,
    ip: u32,
    netmask: u8,
}

static CONN_MAP: Lazy<Arc<Mutex<HashMap<[u8; 6], Sender<Vec<u8>>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

static USER_LIST: Lazy<Arc<Vec<User>>> = Lazy::new(|| {
    let mut list: Vec<User> = Vec::new();
    list.push(User {
        id: "123456".as_bytes().to_vec(),
        ip: 0,
        netmask: 0,
    });
    Arc::new(list)
});

async fn broadcast_frame(src_mac: &[u8; 6], frame: &[u8]) {
    let mut map = CONN_MAP.lock().await;
    for (k, v) in map.iter_mut() {
        if k == src_mac {
            continue;
        }
        v.try_send(frame.to_vec()).ok();
    }
}

async fn send_frame(src_mac: &[u8; 6], desc_mac: &[u8; 6], frame: &[u8]) {
    {
        let mut map = CONN_MAP.lock().await;
        for (k, v) in map.iter_mut() {
            if k == src_mac {
                continue;
            }
            if desc_mac == k {
                v.try_send(frame.to_vec()).ok();
                return;
            }
        }
        // lock destroy
    }
    // cannot find dest device. broadcast it.
    broadcast_frame(src_mac, frame).await;
}

async fn remove_connection(mac: &[u8; 6]) {
    let mut map = CONN_MAP.lock().await;
    map.remove(mac);
}

fn find_user_by_id<'a>(user_list: &'a Vec<User>, id: &[u8]) -> Option<&'a User> {
    for user in user_list {
        if user.id == id {
            return Some(user);
        }
    }
    return None;
}

async fn handle_connection(conn: Connection) {
    info!("Incoming connect from: {}", conn.remote_address());
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    let mut buf = [0u8; 0xffff];
    // 2 version flag
    // 6 mac
    // 32 key
    recv.read_exact(&mut buf[0..40]).await.unwrap();

    let version = buf[0];
    let flag = buf[1];
    if version != 0 {
        return;
    }
    if flag != 0 {
        return;
    }
    let mac: [u8; 6] = buf[2..8].try_into().unwrap();
    let id_length: usize = buf[8].into();
    let id = &buf[9..(9 + id_length)];
    // check id
    let user = match find_user_by_id(&USER_LIST, id) {
        Some(user) => user,
        None => {
            warn!("Cannot find user: {}", String::from_utf8_lossy(id));
            return;
        }
    };

    // send user info
    // version
    buf[0] = 0;
    // flag
    buf[1] = 0;
    // ip
    buf[2..6].copy_from_slice(&user.ip.to_be_bytes());
    // netmask
    buf[6] = user.netmask;
    send.write_all(&buf[0..7]).await.unwrap();

    // create channel
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
    //save mac and sender
    {
        let mut map = CONN_MAP.lock().await;
        map.insert(mac, tx);
    }
    // create send queue
    tokio::spawn(async move {
        while let Some(value) = rx.recv().await {
            match send.write_all(&value).await {
                Ok(_) => {}
                Err(err) => {
                    // write error
                    error!("Write error: {}", err);
                    remove_connection(&mac).await;
                    break;
                }
            }
        }
    });
    loop {
        // read length
        recv.read_exact(&mut buf[0..2]).await.unwrap();
        let length: usize = u16::from_be_bytes(buf[0..2].try_into().unwrap()).into();
        // read frame
        recv.read_exact(&mut buf[0..length]).await.unwrap();
        // get dest mac
        let dest_mac: &[u8; 6] = &buf[0..6].try_into().unwrap();
        let src_mac: &[u8; 6] = &buf[6..12].try_into().unwrap();
        if dest_mac == &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff] {
            // broadcast
            broadcast_frame(src_mac, &buf[0..length]).await;
        } else {
            send_frame(src_mac, dest_mac, &buf[0..length]).await;
        }
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
