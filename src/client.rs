use crate::rpc::{RecvMessage, SendMessage, MsgBuf};
use base64_light::{base64_decode, base64_encode_bytes};
use clap::ArgMatches;
use mio::{Poll, Events, Interest, Token};
use nix::sys::socket::SockFlag;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::io::{Error as IoError, Write};
use std::net::{IpAddr, TcpStream as StdTcpStream};
use std::time::Duration;
use mio::net::TcpStream;
use wireguard_uapi::netlink::{Result as WgResult, NetlinkRoute};
use wireguard_uapi::wireguard::{Peer, WireguardDev};

type IpMap = HashMap<Vec<u8>, (IpAddr, u8)>;

struct Client {
    ip_adds: IpMap,
    ip_removes: IpMap,
    wg: WireguardDev,
    stream: TcpStream,
    is_waiting_ping: bool,
    start_peers: Vec<Peer>,
    buffer: MsgBuf,
}

impl Client {
    fn new(mut wg: WireguardDev, args: &ArgMatches) -> WgResult<Client> {
        let start_peers = wg.get_peers()?;
        let stream = StdTcpStream::connect((
            args.get_one::<String>("address")
                .expect("required")
                .as_str(),
            *args.get_one::<u16>("port").expect("default"),
        ))?;

        stream.set_nonblocking(true)?;
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
            stream: TcpStream::from_std(stream),
            is_waiting_ping: false,
            start_peers,
            buffer: MsgBuf::new(),
        })
    }

    fn new_data_event(&mut self) -> WgResult<bool> {
        let drained = self.buffer.drain(&mut self.stream)?;
        if drained == 0 {
            // Empty read, the socket must be closed
            return Ok(true);
        } else {
            let consumed = self.handle_messages()?;
            self.buffer.consume(consumed);
        }

        Ok(false)
    }

    fn handle_messages(&mut self) -> WgResult<usize> {
        let mut msg_stream = Deserializer::from_reader(&mut self.buffer).into_iter::<RecvMessage>();
        for mb_msg in msg_stream.by_ref() {
            match mb_msg {
                Err(e) if e.is_eof() => (), // This just means we need to wait for more data.
                Err(e) => {
                    /*
                    if Some(ErrorKind::WouldBlock) == e.io_error_kind() && self.is_waiting_ping {
                        println!("Server ping timeout, closing connection");
                        return Err(IoError::from(e).into());
                    } else if Some(ErrorKind::WouldBlock) == e.io_error_kind() {
                        serde_json::to_writer(&self.stream, &SendMessage::Ping)
                            .map_err(IoError::from)?;
                        self.stream.flush()?;
                        self.is_waiting_ping = true;
                        return Ok(0);
                    } else {
                        println!("IO Error : {:?}", e.io_error_kind());
                        return Err(IoError::from(e).into());
                    }
                    */
                    return Err(IoError::from(e).into());
                }

                Ok(RecvMessage::AddPeer(mut peer)) => {
                    Self::filter_allowed_ips(&mut peer, &self.ip_adds, &self.ip_removes);
                    println!("Updating peer {}", peer);
                    self.wg.set_peers([&peer])?;
                }
                Ok(RecvMessage::AddPeers(mut peer_list)) => {
                    let wg = &mut self.wg;
                    wg.set_peers(peer_list.iter_mut().map(|p| {
                        println!("Updating peer {}", p);
                        Self::filter_allowed_ips(p, &self.ip_adds, &self.ip_removes);
                        &*p
                    }))?
                }
                Ok(RecvMessage::DeletePeer(key)) => {
                    println!("Removing peer {}", base64_encode_bytes(key.as_slice()));
                    self.wg.remove_peer(&key)?
                }
                Ok(RecvMessage::Ping) => {
                    self.is_waiting_ping = false;
                }
                _ => println!("Unsupported message"),
            };
        }

        Ok(msg_stream.byte_offset())
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

impl Drop for Client {
    fn drop(&mut self) {
        // Restore initial state :
        if let Err(e) = self.wg.set_peers(self.start_peers.iter()) {
            println!("Warning, couldn't restore peer state on exit : {:?}", e);
        }
    }
}

pub fn client_main(filter: Option<&String>, args: &ArgMatches) -> WgResult<()> {
    let wg = WireguardDev::new(filter.map(|f| f.as_str()))?;
    let mut c = Client::new(wg, args)?;
    let mut poll = Poll::new()?;
    let nlroute = NetlinkRoute::new(SockFlag::empty());
    let mut linkevts = nlroute.subscribe_link(SockFlag::SOCK_NONBLOCK)?;

    poll.registry().register(&mut linkevts, Token(0), Interest::READABLE)?;
    poll.registry().register(&mut c.stream, Token(1), Interest::READABLE)?;
    let mut events = Events::with_capacity(128);
    'outer: loop {
        poll.poll(&mut events, Some(Duration::new(60, 0)))?;

        for event in events.iter() {
            let token = event.token().0;
            match token {
                t if t == 0 => {
                    for mb_msg in linkevts.iter_links() {
                        println!("New link event : {:?}", mb_msg);
                    }
                }
                t if t == 1 => {
                    if c.new_data_event()? {
                        println!("Server connection closed");
                        break 'outer;
                    }
                }
                _ => panic!("Unknown token"),
            }
        }

        // Timeout, send keepalive ping
        if events.is_empty() {
            if c.is_waiting_ping {
                println!("Server ping timeout, closing connection");
                break 'outer;
            }

            serde_json::to_writer(&c.stream, &SendMessage::Ping)
                .map_err(IoError::from)?;
            c.stream.flush()?;
            c.is_waiting_ping = true;
        }
    }

    Ok(())
}
