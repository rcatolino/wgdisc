use crate::cidr;
use crate::rpc::{MsgBuf, RecvMessage, SendMessage};
use base64_light::base64_encode_bytes;
use clap::ArgMatches;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use nix::errno;
use nix::ifaddrs::getifaddrs;
use nix::libc::EAGAIN;
use nix::sys::socket::SockFlag;
use serde::Serialize;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::io::{Error as IoError, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use wireguard_uapi::netlink::{Error as WgError, NetlinkRoute};
use wireguard_uapi::netlink::{
    wgdevice_attribute, AttributeIterator, AttributeType, MsgBuffer, Result as WgResult, SubHeader,
};
use wireguard_uapi::wireguard::{Peer, WireguardDev};

struct Client {
    stream: TcpStream,
    buffer: MsgBuf,
    pubkey: Vec<u8>,
    addr: SocketAddr,
}

impl Client {
    fn new_data_event(&mut self, peers: &[Peer]) -> IoResult<bool> {
        let drained = self.buffer.drain(&mut self.stream)?;
        if drained == 0 {
            // Empty read, the socket must be closed
            return Ok(true);
        } else {
            let consumed = self.handle_messages(peers)?;
            self.buffer.consume(consumed);
        }

        Ok(false)
    }

    fn handle_messages(&mut self, peers: &[Peer]) -> IoResult<usize> {
        let mut msgstream = Deserializer::from_reader(&mut self.buffer).into_iter::<RecvMessage>();
        for msg in msgstream.by_ref() {
            match msg {
                Ok(RecvMessage::Ping) => {
                    serde_json::to_writer(&mut self.stream, &SendMessage::Ping)?;
                    self.stream.flush()?;
                }
                Ok(RecvMessage::GetPeerList) => {
                    serde_json::to_writer(&mut self.stream, &SendMessage::AddPeers(peers))?;
                    self.stream.flush()?;
                }
                Err(e) if e.is_eof() => (), // This just means we need to wait
                // for more data to deserialize
                Err(e) => return Err(IoError::new(ErrorKind::Other, e.to_string())),
                Ok(m) => println!("Unsupported message {:?}", m),
            }
        }

        Ok(msgstream.byte_offset())
    }
}

struct WireguardData {
    wg: WireguardDev,
    nlstream: MsgBuffer<OwnedFd>,
    listeners: Vec<TcpListener>,
}

struct Server {
    clients: HashMap<usize, Client>,
    poll: Poll,
    count: usize,
    nltok: usize,
    wgdata: Option<WireguardData>,
}

impl Server {
    fn find_peer<'a>(peers: &'a [Peer], addr: &SocketAddr) -> Option<&'a Peer> {
        let mut best_match = None;
        let mut best_mask = None;
        for p in peers.iter() {
            for (a, mask) in p.allowed_ips.iter() {
                if cidr::ip_in_net(&addr.ip(), a, *mask) && best_mask.unwrap_or(0) <= *mask {
                    best_mask = Some(*mask);
                    best_match = Some(p);
                }
            }
        }

        best_match
    }

    fn peer_from_attr<F: AsRawFd>(&self, wgindex: i32, attributes: AttributeIterator<'_, F>) -> Option<Peer> {
        let mut peer = None;
        let mut ifindex = None;
        for a in attributes {
            match a.attribute_type {
                AttributeType::Nested(wgdevice_attribute::PEER) => {
                    peer = Peer::new(a.attributes());
                }
                AttributeType::Raw(wgdevice_attribute::IFINDEX) => {
                    ifindex = a.get::<u32>();
                }
                _ => (),
            }
        }

        if Some(wgindex as u32) == ifindex {
            peer
        } else {
            // This event isn't for the interface we are monitoring
            None
        }
    }

    // Returns Ok(None) if no peer with matching ip was found
    fn add_client(&mut self, token: usize) -> WgResult<()> {
        let wgdata = self.wgdata.as_mut().expect("Error, received tcp event, but no wireguard listener is configured.");
        let (mut stream, addr) = wgdata.listeners[token-1].accept()?;
        println!("New client with address {}", addr);
        let peers = wgdata.wg.get_peers()?;
        let peer = match Self::find_peer(&peers, &addr) {
            Some(peer) => peer,
            None => {
                println!("No client found with allowed-ip matching address {}", addr.ip());
                return Ok(());
            }
        };

        self.poll
            .registry()
            .register(&mut stream, Token(self.count), Interest::READABLE)?;

        let c = Client {
            stream,
            buffer: MsgBuf::new(),
            pubkey: peer.peer_key.clone(),
            addr,
        };

        // Update each pre-existing clients to tell them about the new peer
        self.clients.insert(self.count, c);
        self.count += 1;
        Ok(())
    }

    fn send_all_clients<T: ?Sized + Serialize>(&self, msg: &T) -> IoResult<()> {
        for c in self.clients.values() {
            let mut stream = &c.stream;
            serde_json::to_writer(stream, msg).map_err(IoError::from)?;
            stream.flush()?;
        }

        Ok(())
    }

    fn link_change(&mut self, buffer: &mut MsgBuffer<OwnedFd>) -> WgResult<()> {
        for mb_msg in buffer.iter_links() {
            let msg = match mb_msg {
                // EAGAIN indicates that there is noting more to read from netlink
                Err(WgError::OsError(no)) if no == errno::from_i32(EAGAIN) => break,
                Ok(msg) => msg,
                Err(e) => return Err(e),
            };
            println!("New link event : {:?}", msg);
        }

        Ok(())
    }

    fn recv_notifications(&mut self) -> WgResult<()> {
        let wgdata = self.wgdata.as_ref().expect("Error, received wg netlink event, but no wireguard interface is configured.");
        for mb_msg in wgdata.nlstream.recv_msgs() {
            let msg = match mb_msg {
                // EAGAIN indicates that there is noting more to read from netlink
                Err(WgError::OsError(no)) if no == errno::from_i32(EAGAIN) => break,
                Ok(msg) => msg,
                Err(e) => return Err(e),
            };

            match msg.sub_header {
                // CMD 2 : Changed endpoint
                SubHeader::Generic(genheader) if genheader.cmd == 2 => {
                    if let Some(peer) = self.peer_from_attr(wgdata.wg.index, msg.attributes()) {
                        println!("Set peer endpoint notification");
                        self.send_all_clients(&SendMessage::AddPeer(&peer))?;
                    }
                }
                // CMD 3 : Removed peer
                SubHeader::Generic(genheader) if genheader.cmd == 3 => {
                    if let Some(peer) = self.peer_from_attr(wgdata.wg.index, msg.attributes()) {
                        println!("Remove peer notification");
                        self.send_all_clients(&SendMessage::DeletePeer(&peer.peer_key))?;
                    }
                }
                // CMD 4 : Changed peer
                SubHeader::Generic(genheader) if genheader.cmd == 4 => {
                    if let Some(peer) = self.peer_from_attr(wgdata.wg.index, msg.attributes()) {
                        println!("Set peer notification");
                        self.send_all_clients(&SendMessage::AddPeer(&peer))?;
                    }
                }
                _ => println!("Unknwon wireguard notification"),
            }
        }

        Ok(())
    }
}

#[allow(clippy::manual_map)]
pub fn getsockaddrs(ifname: &str) -> impl Iterator<Item = SocketAddr> + '_ {
    getifaddrs()
        .unwrap()
        .filter(move |interface| interface.interface_name == ifname)
        .filter_map(|interface| interface.address)
        .filter_map(|address| {
            if let Some(ipv4) = address.as_sockaddr_in() {
                Some(SocketAddr::V4((*ipv4).into()))
            } else if let Some(ipv6) = address.as_sockaddr_in6() {
                Some(SocketAddr::V6((*ipv6).into()))
            } else {
                None
            }
        })
}

pub fn setup_interface(
    ifname: &str,
    registry: &Registry,
    args: &ArgMatches,
) -> WgResult<Vec<TcpListener>> {
    let mut listeners = Vec::<TcpListener>::new();
    for (index, mut addr) in getsockaddrs(ifname).enumerate() {
        let filter = args.get_one::<IpAddr>("address");
        if filter.is_some() && Some(&addr.ip()) != filter {
            continue;
        }

        addr.set_port(*args.get_one::<u16>("port").expect("default"));
        listeners.push(TcpListener::bind(addr)?);
        registry.register(&mut listeners[index], Token(index + 1), Interest::READABLE)?;
        println!(
            "Using wireguard interface {} and address {:?}",
            ifname, addr
        );
    }

    Ok(listeners)
}

pub fn server_main(filter: Option<&String>, args: &ArgMatches) -> WgResult<()> {
    let mut server = Server {
        clients: HashMap::new(),
        poll: Poll::new()?,
        count: 0,
        nltok: 0,
        wgdata: None,
    };

    let reg = server.poll.registry();

    // Register netlink route link events socket :
    let linktok = 0;
    let nlroute = NetlinkRoute::new(SockFlag::empty());
    let mut linkevts = nlroute.subscribe_link(SockFlag::SOCK_NONBLOCK)?;
    reg.register(&mut linkevts, Token(linktok), Interest::READABLE)?;

    match WireguardDev::new(filter.map(|f| f.as_str())) {
        Err(WgError::NoInterfaceFound) => (),
        Err(e) => return Err(e),
        Ok(mut wg) => {
            // Register tcp listeners for each interface address
            let listeners = setup_interface(&wg.name, reg, args)?;
            if listeners.is_empty() {
                let msg = format!("No address found for interface {}", wg.name);
                return Err(WgError::Other(msg));
            }

            // Register netlink wireguard events socket :
            let mut nlstream = wg.subscribe(SockFlag::SOCK_NONBLOCK)?;
            server.nltok = listeners.len() + 1;
            reg.register(&mut nlstream, Token(server.nltok), Interest::READABLE)?;
            server.count = server.nltok + 1;
            server.wgdata.replace(WireguardData { wg, nlstream, listeners });
        }
    }

    let mut events = Events::with_capacity(128);
    loop {
        server.poll.poll(&mut events, None)?;
        for event in events.iter() {
            let token = event.token().0;
            // match token.cmp(&listeners.len()) {
            match token {
                t if t == linktok => {
                    // Netlink event
                    server.link_change(&mut linkevts)?;
                }
                t if t > linktok && t < server.nltok => {
                    // Listener event : new client
                    server.add_client(token)?;
                }
                t if t == server.nltok => {
                    // Netlink event
                    server.recv_notifications()?;
                }
                t if t > server.nltok => {
                    // Client event
                    let client = server
                        .clients
                        .get_mut(&token)
                        .expect("Polled event from non existing client !");

                    let wgdata = server.wgdata.as_mut().expect("Error, received wg client event, but no wireguard interface is configured.");
                    let peers = wgdata.wg.get_peers()?;
                    let should_close = match client.new_data_event(&peers) {
                        Ok(should_close) => should_close,
                        Err(e) => {
                            println!(
                                "Error deserializing from client {} : {}. Terminating client.",
                                client.addr, e
                            );
                            true
                        }
                    };
                    if event.is_read_closed() || should_close {
                        println!(
                            "Closing client {}",
                            base64_encode_bytes(client.pubkey.as_slice())
                        );
                        server.poll.registry().deregister(&mut client.stream)?;
                        server.clients.remove(&token);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
