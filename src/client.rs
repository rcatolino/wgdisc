use crate::rpc::{MsgBuf, RecvMessage, SendMessage};
use base64_light::{base64_decode, base64_encode_bytes};
use clap::ArgMatches;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use nix::errno;
use nix::libc::EAGAIN;
use nix::sys::socket::SockFlag;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::io::{Error as IoError, Write};
use std::net::{IpAddr, TcpStream as StdTcpStream, Shutdown};
use std::os::fd::OwnedFd;
use std::time::Duration;
use wireguard_uapi::netlink::{Error as WgError, MsgBuffer, NetlinkRoute, Result as WgResult};
use wireguard_uapi::wireguard::{Peer, WireguardDev};

type IpMap = HashMap<Vec<u8>, (IpAddr, u8)>;

const NLLINK_TOKEN: usize = 0;
const SERVER_TOKEN: usize = 1;

struct ConnectionData {
    wg: WireguardDev,
    stream: TcpStream,
    is_waiting_ping: bool,
}

struct Client {
    ip_adds: IpMap,
    ip_removes: IpMap,
    poll: Poll,
    buffer: MsgBuf,
    con: Option<ConnectionData>,
    wgname: Option<String>,
    server_ip: String,
    server_port: u16,
}

impl Client {
    fn disconnect(&mut self) -> WgResult<()> {
        let connection = self
            .con
            .as_mut()
            .expect("Tried to disconnect but no connection is active.");

        self.poll.registry().deregister(&mut connection.stream)?;
        connection.stream.shutdown(Shutdown::Both)?;
        self.con = None;
        Ok(())
    }

    fn try_connect(&mut self) -> WgResult<()> {
        if self.con.is_some() {
            panic!("Error, tried to setup a wireguard device, but one exists already");
        }

        match WireguardDev::new(self.wgname.as_deref()) {
            Err(WgError::NoInterfaceFound) => Ok(()),
            Err(e) => Err(e),
            Ok(wg) => {
                std::thread::sleep(Duration::new(2, 0));
                let stdstream = StdTcpStream::connect((self.server_ip.as_str(), self.server_port))?;

                stdstream.set_nonblocking(true)?;
                // We've just (re-)connected, ask for all existing peers :
                serde_json::to_writer(&stdstream, &SendMessage::GetPeerList)
                    .map_err(IoError::from)?;
                (&stdstream).flush()?;

                let mut stream = TcpStream::from_std(stdstream);
                self.poll
                    .registry()
                    .register(&mut stream, Token(SERVER_TOKEN), Interest::READABLE)?;
                if self.wgname.is_none() {
                    // We didn't have an interface name specified, but in the event the interface
                    // is removed we only want to use a new interface with the same name.
                    self.wgname.replace(wg.name.clone());
                }

                self.con.replace(ConnectionData {
                    wg,
                    stream,
                    is_waiting_ping: false,
                });
                Ok(())
            }
        }
    }

    fn new(filter: Option<String>, args: &ArgMatches) -> WgResult<Client> {
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
            poll: Poll::new()?,
            con: None,
            buffer: MsgBuf::new(),
            wgname: filter,
            server_ip: args.get_one::<String>("address").expect("required").clone(),
            server_port: *args.get_one::<u16>("port").expect("default"),
        })
    }

    fn new_data_event(&mut self) -> WgResult<bool> {
        let drained = self.buffer.drain(
            &mut self
                .con
                .as_mut()
                .expect("New data event called without an active connection")
                .stream,
        )?;
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
        let connection = self
            .con
            .as_mut()
            .expect("Handling messages without an active connection");
        for mb_msg in msg_stream.by_ref() {
            match mb_msg {
                Err(e) if e.is_eof() => (), // This just means we need to wait for more data.
                Err(e) => {
                    return Err(IoError::from(e).into());
                }

                Ok(RecvMessage::AddPeer(mut peer)) => {
                    Self::filter_allowed_ips(&mut peer, &self.ip_adds, &self.ip_removes);
                    println!("Updating peer {}", peer);
                    connection.wg.set_peers([&peer])?;
                }
                Ok(RecvMessage::AddPeers(mut peer_list)) => {
                    connection.wg.set_peers(peer_list.iter_mut().map(|p| {
                        println!("Updating peer {}", p);
                        Self::filter_allowed_ips(p, &self.ip_adds, &self.ip_removes);
                        &*p
                    }))?
                }
                Ok(RecvMessage::DeletePeer(key)) => {
                    println!("Removing peer {}", base64_encode_bytes(key.as_slice()));
                    connection.wg.remove_peer(&key)?
                }
                Ok(RecvMessage::Ping) => {
                    connection.is_waiting_ping = false;
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

    fn link_change(&mut self, buffer: &mut MsgBuffer<OwnedFd>) -> WgResult<()> {
        for mb_msg in buffer.iter_links() {
            match mb_msg {
                // EAGAIN indicates that there is noting more to read from netlink
                Err(WgError::OsError(no)) if no == errno::from_i32(EAGAIN) => break,
                Ok((16, ifinfo)) => {
                    if self.con.is_some() {
                        println!("RTM_NEWLINK event ignored because we already have a device");
                    } else {
                        // self.newlink_event(ifinfo)
                        println!("RTM_NEWLINK event {:?}", ifinfo);
                        // TODO: optionally use ifinfo to help wireguard setup
                        self.try_connect()?;
                    }
                }
                Ok((17, ifinfo)) => {
                    if let Some(ref con) = self.con {
                        println!("RTM_DELLINK event, {:?}", ifinfo);
                        if con.wg.index == ifinfo.index {
                            self.disconnect()?;
                        }
                    }
                }
                Ok((msgtype, ifinfo)) => {
                    println!("Warning, unsupported link event {} : {:?}", msgtype, ifinfo);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

/*
impl Drop for Client {
    fn drop(&mut self) {
        // Restore initial state :
        if let Err(e) = self.wg.set_peers(self.start_peers.iter()) {
            println!("Warning, couldn't restore peer state on exit : {:?}", e);
        }
    }
}
*/

pub fn client_main(filter: Option<&String>, args: &ArgMatches) -> WgResult<()> {
    let mut c = Client::new(filter.cloned(), args)?;
    c.try_connect()?;

    let nlroute = NetlinkRoute::new(SockFlag::empty());
    let mut linkevts = nlroute.subscribe_link(SockFlag::SOCK_NONBLOCK)?;
    c.poll
        .registry()
        .register(&mut linkevts, Token(NLLINK_TOKEN), Interest::READABLE)?;

    let mut events = Events::with_capacity(128);
    'outer: loop {
        c.poll.poll(&mut events, Some(Duration::new(60, 0)))?;

        for event in events.iter() {
            let token = event.token().0;
            match token {
                NLLINK_TOKEN => {
                    c.link_change(&mut linkevts)?;
                }
                SERVER_TOKEN => {
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
            match c.con.as_mut() {
                Some(connection) => {
                    if connection.is_waiting_ping {
                        println!("Server ping timeout, closing connection");
                        break 'outer;
                    }

                    serde_json::to_writer(&connection.stream, &SendMessage::Ping)
                        .map_err(IoError::from)?;
                    connection.stream.flush()?;
                    connection.is_waiting_ping = true;
                }
                None => (), // TODO: check server connection and try to reconnect ?
            }
        }
    }

    Ok(())
}
