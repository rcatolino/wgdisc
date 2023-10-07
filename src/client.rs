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

struct Client {
    ip_adds: IpMap,
    ip_removes: IpMap,
    wg: WireguardDev,
    stream: TcpStream,
    is_waiting_ping: bool,
}

impl Client {
    fn new(wg: WireguardDev, args: &ArgMatches) -> WgResult<Client> {
        let stream = TcpStream::connect((
            args.get_one::<String>("address")
                .expect("required")
                .as_str(),
            *args.get_one::<u16>("port").expect("default"),
        ))?;

        stream.set_read_timeout(Some(Duration::new(60, 0))).unwrap();
        // We've just started, ask for all existing peers :
        serde_json::to_writer(&stream, &SendMessage::GetPeerList).map_err(IoError::from)?;
        (&stream).flush()?;

        // Setup allowed_ip filters
        let mut ip_adds = HashMap::new();
        let mut ip_removes = HashMap::new();
        for o in args.get_many::<String>("override").into_iter().flatten() {
            if let Some((pubkey, ipnet)) = o.rsplit_once('-') {
                if Self::insert_override(&mut ip_removes, base64_decode(pubkey), ipnet).is_none() {
                    println!(
                        "Error parsing ip/mask {}, ignoring override for {}",
                        ipnet, pubkey
                    );
                }

                continue;
            } else if let Some((pubkey, ipnet)) = o.rsplit_once('+') {
                if Self::insert_override(&mut ip_adds, base64_decode(pubkey), ipnet).is_none() {
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

        Ok(Client {
            ip_adds,
            ip_removes,
            wg,
            stream,
            is_waiting_ping: false,
        })
    }

    fn handle_messages(&mut self) -> WgResult<bool> {
        let msg_stream = Deserializer::from_reader(&self.stream).into_iter::<RecvMessage>();
        for mb_msg in msg_stream {
            let msg = match mb_msg {
                Ok(msg) => msg,
                Err(e) => {
                    if Some(ErrorKind::WouldBlock) == e.io_error_kind() && self.is_waiting_ping {
                        println!("Server ping timeout, closing connection");
                        return Err(IoError::from(e).into());
                    } else if Some(ErrorKind::WouldBlock) == e.io_error_kind() {
                        serde_json::to_writer(&self.stream, &SendMessage::Ping)
                            .map_err(IoError::from)?;
                        self.stream.flush()?;
                        self.is_waiting_ping = true;
                        return Ok(false);
                    } else {
                        println!("IO Error : {:?}", e.io_error_kind());
                        return Err(IoError::from(e).into());
                    }
                }
            };

            match msg {
                RecvMessage::AddPeer(mut peer) => {
                    Self::filter_allowed_ips(&mut peer, &self.ip_adds, &self.ip_removes);
                    println!("Updating peer {:?}", peer);
                    self.wg.set_peers([&peer])?;
                }
                RecvMessage::AddPeers(mut peer_list) => {
                    let wg = &mut self.wg;
                    wg.set_peers(peer_list.iter_mut().map(|p| {
                        Self::filter_allowed_ips(p, &self.ip_adds, &self.ip_removes);
                        &*p
                    }))?
                }
                RecvMessage::DeletePeer(key) => {
                    println!("Removing peer {:?}", key);
                    self.wg.remove_peer(&key)?
                }
                RecvMessage::Ping => {
                    println!("Received ping back from server");
                    self.is_waiting_ping = false;
                }
                _ => println!("Unsupported message"),
            };
        }

        Ok(true) // No more message, and no error. The connection must be closed.
    }

    fn filter_allowed_ips(peer: &mut Peer, ip_adds: &IpMap, ip_removes: &IpMap) {
        if let Some(ip_to_add) = ip_adds.get(&peer.peer_key) {
            peer.allowed_ips.push(*ip_to_add);
        }

        if let Some(ip_to_remove) = ip_removes.get(&peer.peer_key) {
            for i in 0..peer.allowed_ips.len() {
                if peer.allowed_ips[i] == *ip_to_remove {
                    peer.allowed_ips.swap_remove(i);
                    break;
                }
            }
        }
    }

    fn insert_override(ip_adds: &mut IpMap, pubkey: Vec<u8>, ipnet: &str) -> Option<()> {
        let (ip, mask) = ipnet.rsplit_once('/')?;
        ip_adds.insert(pubkey, (ip.parse().ok()?, mask.parse().ok()?));
        Some(())
    }
}

pub fn client_main(wg: WireguardDev, args: &ArgMatches) -> WgResult<()> {
    let mut c = Client::new(wg, args)?;
    loop {
        if c.handle_messages()? {
            println!("Server connection closed");
            break;
        }
    }

    Ok(())
}
