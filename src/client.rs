use crate::rpc::{RecvMessage, SendMessage};
use crate::wireguard;
use clap::ArgMatches;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};

fn insert_override(
    ip_adds: &mut HashMap<String, (IpAddr, u8)>,
    pubkey: &str,
    ipnet: &str,
) -> Option<()> {
    let (ip, mask) = ipnet.rsplit_once('/')?;
    ip_adds.insert(String::from(pubkey), (ip.parse().ok()?, mask.parse().ok()?));
    Some(())
}

pub fn client_main(wgifname: &str, args: &ArgMatches) -> std::io::Result<()> {
    let stream = TcpStream::connect((
        args.get_one::<String>("address")
            .expect("required")
            .as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;

    // We've just started, ask for all existing peers :
    serde_json::to_writer(&stream, &SendMessage::GetPeerList)?;
    let msg_stream = Deserializer::from_reader(&stream).into_iter::<RecvMessage>();

    let mut ip_adds = HashMap::new();
    // Pre-fill override with existing conf :
    wireguard::set_peers_allowed_ips(wgifname, &mut ip_adds)?;
    let mut ip_removes = HashMap::new();
    for o in args.get_many::<String>("override").into_iter().flatten() {
        if let Some((pubkey, ipnet)) = o.rsplit_once('+') {
            if insert_override(&mut ip_adds, pubkey, ipnet).is_none() {
                println!(
                    "Error parsing ip/mask {}, ignoring override for {}",
                    ipnet, pubkey
                );
            }
            continue;
        }

        if let Some((pubkey, ipnet)) = o.rsplit_once('-') {
            if insert_override(&mut ip_removes, pubkey, ipnet).is_none() {
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
        match msg? {
            RecvMessage::AddPeer(mut peer) => {
                peer.filter_allowed_ips(&ip_adds, &ip_removes);
                wireguard::add_peers(wgifname, [&peer])?;
            }
            RecvMessage::AddPeers(mut peer_list) => wireguard::add_peers(
                wgifname,
                peer_list.iter_mut().map(|p| {
                    p.filter_allowed_ips(&ip_adds, &ip_removes);
                    &*p
                }),
            )?,
            RecvMessage::DeletePeer(key) => wireguard::delete_peer(wgifname, &key)?,
            _ => println!("Unsupported message"),
        };
    }

    Ok(())
}
