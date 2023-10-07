use crate::rpc::{RecvMessage, SendMessage};
use base64_light::base64_decode;
use clap::ArgMatches;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;
use wireguard_uapi::netlink::Result as WgResult;
use wireguard_uapi::wireguard::{Peer, WireguardDev};

type IpMap = HashMap<Vec<u8>, (IpAddr, u8)>;

fn insert_override(ip_adds: &mut IpMap, pubkey: Vec<u8>, ipnet: &str) -> Option<()> {
    let (ip, mask) = ipnet.rsplit_once('/')?;
    ip_adds.insert(pubkey, (ip.parse().ok()?, mask.parse().ok()?));
    Some(())
}

pub fn filter_allowed_ips(peer: &mut Peer, adds: &IpMap, removes: &IpMap) {
    if let Some(ip_to_add) = adds.get(&peer.peer_key) {
        peer.allowed_ips.push(*ip_to_add);
    }

    if let Some(ip_to_remove) = removes.get(&peer.peer_key) {
        for i in 0..peer.allowed_ips.len() {
            if peer.allowed_ips[i] == *ip_to_remove {
                peer.allowed_ips.swap_remove(i);
                break;
            }
        }
    }
}

fn handle_messages(
    mut stream: &TcpStream,
    wg: &mut WireguardDev,
    ip_adds: &mut IpMap,
    ip_removes: &mut IpMap,
) -> WgResult<()> {
    let msg_stream = Deserializer::from_reader(stream).into_iter::<RecvMessage>();
    for mb_msg in msg_stream {
        let msg = match mb_msg {
            Ok(msg) => msg,
            Err(e) => {
                if Some(ErrorKind::WouldBlock) == e.io_error_kind() {
                    println!("tcp read timed out, keepalive");
                    serde_json::to_writer(stream, &SendMessage::Ping).map_err(IoError::from)?;
                    stream.flush()?;
                    continue;
                } else {
                    println!("IO Error : {:?}", e.io_error_kind());
                    return Err(IoError::from(e).into());
                }
            }
        };

        match msg {
            RecvMessage::AddPeer(mut peer) => {
                filter_allowed_ips(&mut peer, ip_adds, ip_removes);
                println!("Updating peer {:?}", peer);
                wg.set_peers([&peer])?;
            }
            RecvMessage::AddPeers(mut peer_list) => {
                wg.set_peers(peer_list.iter_mut().map(|p| {
                    filter_allowed_ips(p, ip_adds, ip_removes);
                    &*p
                }))?
            }
            RecvMessage::DeletePeer(key) => {
                println!("Removing peer {:?}", key);
                wg.remove_peer(&key)?
            }
            RecvMessage::Ping => {
                println!("Received ping back from server");
            }
            _ => println!("Unsupported message"),
        };
    }

    Ok(())
}

pub fn client_main(mut wg: WireguardDev, args: &ArgMatches) -> WgResult<()> {
    let stream = TcpStream::connect((
        args.get_one::<String>("address")
            .expect("required")
            .as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;

    stream.set_read_timeout(Some(Duration::new(10, 0))).unwrap();
    // We've just started, ask for all existing peers :
    serde_json::to_writer(&stream, &SendMessage::GetPeerList).map_err(IoError::from)?;
    (&stream).flush()?;

    let mut ip_adds = HashMap::new();
    // Pre-fill override with existing conf : (not needed with nl api)
    // wireguard::set_peers_allowed_ips(wgifname, &mut ip_adds)?;
    let mut ip_removes = HashMap::new();
    for o in args.get_many::<String>("override").into_iter().flatten() {
        if let Some((pubkey, ipnet)) = o.rsplit_once('-') {
            if insert_override(&mut ip_removes, base64_decode(pubkey), ipnet).is_none() {
                println!(
                    "Error parsing ip/mask {}, ignoring override for {}",
                    ipnet, pubkey
                );
            }

            continue;
        } else if let Some((pubkey, ipnet)) = o.rsplit_once('+') {
            if insert_override(&mut ip_adds, base64_decode(pubkey), ipnet).is_none() {
                println!(
                    "Error parsing ip/mask {}, ignoring override for {}",
                    ipnet, pubkey
                );
            }
            continue;
        }

        println!(
            "Ignored override '{}', missing +/- separator between pubkey and ip network",
            o
        );
    }

    // Listen for incoming messages
    loop {
        handle_messages(&stream, &mut wg, &mut ip_adds, &mut ip_removes)?;
    }
}
