use crate::rpc::{RecvMessage, SendMessage};
use wireguard_uapi::wireguard::{Peer, WireguardDev};
use wireguard_uapi::netlink::Result as WgResult;
use clap::ArgMatches;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::io::Error as IoError;
use base64_light::base64_decode;

fn insert_override(
    ip_adds: &mut HashMap<Vec<u8>, (IpAddr, u8)>,
    pubkey: Vec<u8>,
    ipnet: &str,
) -> Option<()> {
    let (ip, mask) = ipnet.rsplit_once('/')?;
    ip_adds.insert(pubkey, (ip.parse().ok()?, mask.parse().ok()?));
    Some(())
}

pub fn filter_allowed_ips(
    peer: &mut Peer,
    adds: &HashMap<Vec<u8>, (IpAddr, u8)>,
    removes: &HashMap<Vec<u8>, (IpAddr, u8)>,
) {
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

pub fn client_main(mut wg: WireguardDev, args: &ArgMatches) -> WgResult<()> {
    let stream = TcpStream::connect((
        args.get_one::<String>("address")
            .expect("required")
            .as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;

    // We've just started, ask for all existing peers :
    serde_json::to_writer(&stream, &SendMessage::GetPeerList).map_err(|e| IoError::from(e))?;
    let msg_stream = Deserializer::from_reader(&stream).into_iter::<RecvMessage>();

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
    for msg in msg_stream {
        match msg.map_err(|e| IoError::from(e))? {
            RecvMessage::AddPeer(mut peer) => {
                filter_allowed_ips(&mut peer, &ip_adds, &ip_removes);
                wg.set_peers([&peer])?;
            }
            RecvMessage::AddPeers(mut peer_list) => wg.set_peers(
                peer_list.iter_mut().map(|p| {
                    filter_allowed_ips(p, &ip_adds, &ip_removes);
                    &*p
                }),
            )?,
            RecvMessage::DeletePeer(key) => wg.remove_peer(&key)?,
            _ => println!("Unsupported message"),
        };
    }

    Ok(())
}
