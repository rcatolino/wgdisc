use crate::cidr;
use crate::rpc::{MsgBuf, RecvMessage, SendMessage};
use base64_light::base64_encode_bytes;
use clap::ArgMatches;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use nix::errno;
use nix::ifaddrs::getifaddrs;
use nix::libc::EAGAIN;
use nix::sys::socket::SockFlag;
use serde::Serialize;
use serde_json::Deserializer;
use std::cell::Ref;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::io::{Error as IoError, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use wireguard_uapi::netlink::Error as WgError;
use wireguard_uapi::netlink::{
    wgdevice_attribute, wgpeer_attribute, AttributeIterator, AttributeType, MsgBuffer,
    Result as WgResult, SubHeader,
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
                Ok(RecvMessage::GetPeerList) => {
                    // println!("Received message GetPeerList");
                    serde_json::to_writer(&mut self.stream, &SendMessage::AddPeers(peers))?
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

struct Server {
    peers: Vec<Peer>,
    clients: HashMap<usize, Client>,
    poll: Poll,
    count: usize,
    wg: WireguardDev,
}

impl Server {
    fn find_peer(&'_ self, addr: &SocketAddr) -> Option<&'_ Peer> {
        let mut best_match = None;
        let mut best_mask = None;
        for p in self.peers.iter() {
            for (a, mask) in p.allowed_ips.iter() {
                if cidr::ip_in_net(&addr.ip(), a, *mask) && best_mask.unwrap_or(0) <= *mask {
                    best_mask = Some(*mask);
                    best_match = Some(p);
                }
            }
        }

        best_match
    }

    fn peerkey_from_attr<'a, F: AsRawFd>(
        &self,
        attributes: AttributeIterator<'a, F>,
    ) -> Option<Ref<'a, [u8]>> {
        let mut key = None;
        let mut ifindex = None;
        for a in attributes {
            match a.attribute_type {
                AttributeType::Nested(wgdevice_attribute::PEER) => {
                    key = a.attributes().find_map(|inner| match inner.attribute_type {
                        AttributeType::Raw(wgpeer_attribute::PUBLIC_KEY) => inner.get_bytes(),
                        _ => None,
                    });
                }
                AttributeType::Raw(wgdevice_attribute::IFINDEX) => {
                    ifindex = a.get::<u32>();
                }
                _ => (),
            }
        }

        if Some(self.wg.index as u32) == ifindex {
            key
        } else {
            // This event isn't for the interface we are monitoring
            None
        }
    }

    fn peer_from_attr<F: AsRawFd>(&self, attributes: AttributeIterator<'_, F>) -> Option<Peer> {
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

        if Some(self.wg.index as u32) == ifindex {
            peer
        } else {
            // This event isn't for the interface we are monitoring
            None
        }
    }

    // Returns Ok(None) if no peer with matching ip was found
    fn add_client(&mut self, mut stream: TcpStream, addr: SocketAddr) -> IoResult<Option<()>> {
        self.update_peers();
        let peer = match self.find_peer(&addr) {
            Some(peer) => peer,
            None => return Ok(None),
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
        self.send_all_clients(&SendMessage::AddPeer(peer))?;
        self.clients.insert(self.count, c);
        self.count += 1;
        Ok(Some(()))
    }

    fn update_peers(&mut self) {
        self.peers = self.wg.get_peers().unwrap();
        // .unwrap_or_else(|_| panic!("Unable to get wireguard peers for {}", &self.wg.name));
    }

    fn send_all_clients<T: ?Sized + Serialize>(&self, msg: &T) -> IoResult<()> {
        for c in self.clients.values() {
            let mut stream = &c.stream;
            serde_json::to_writer(stream, msg).map_err(IoError::from)?;
            stream.flush()?;
        }

        Ok(())
    }

    fn recv_notifications(&mut self, buffer: &mut MsgBuffer<OwnedFd>) -> WgResult<()> {
        for mb_msg in buffer.recv_msgs() {
            let msg = match mb_msg {
                Err(WgError::OsError(no)) if no == errno::from_i32(EAGAIN) => break,
                Ok(msg) => msg,
                Err(e) => return Err(e),
            };

            match msg.sub_header {
                SubHeader::Generic(genheader) if genheader.cmd == 2 => {
                    if let Some(peer) = self.peer_from_attr(msg.attributes()) {
                        println!("Set peer endpoint notification");
                        self.send_all_clients(&SendMessage::AddPeer(&peer))?;
                    }
                }
                SubHeader::Generic(genheader) if genheader.cmd == 3 => {
                    if let Some(key) = self.peerkey_from_attr(msg.attributes()) {
                        println!("Remove peer notification");
                        self.send_all_clients(&SendMessage::DeletePeer(&key))?;
                    }
                }
                SubHeader::Generic(genheader) if genheader.cmd == 4 => {
                    if let Some(peer) = self.peer_from_attr(msg.attributes()) {
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

pub fn server_main(wg: WireguardDev, args: &ArgMatches) -> WgResult<()> {
    let mut listeners = Vec::<TcpListener>::new();
    let mut server = Server {
        clients: HashMap::new(),
        peers: Vec::new(),
        poll: Poll::new()?,
        count: 0,
        wg,
    };

    for (index, mut addr) in getsockaddrs(&server.wg.name).enumerate() {
        let filter = args.get_one::<IpAddr>("address");
        if filter.is_some() && Some(&addr.ip()) != filter {
            continue;
        }

        addr.set_port(*args.get_one::<u16>("port").expect("default"));
        listeners.push(TcpListener::bind(addr)?);
        server
            .poll
            .registry()
            .register(&mut listeners[index], Token(index), Interest::READABLE)?;
        println!(
            "Using wireguard interface {} and address {:?}",
            server.wg.name, addr
        );
    }

    if listeners.is_empty() {
        let msg = format!("No address found for interface {}", server.wg.name);
        return Err(WgError::Other(msg));
    }

    let mut nlstream = server.wg.subscribe(SockFlag::SOCK_NONBLOCK)?;
    server
        .poll
        .registry()
        .register(&mut nlstream, Token(listeners.len()), Interest::READABLE)?;

    let mut events = Events::with_capacity(128);
    server.count = listeners.len() + 1;
    loop {
        server.poll.poll(&mut events, None)?;
        for event in events.iter() {
            let token = event.token().0;
            match token.cmp(&listeners.len()) {
                Ordering::Less => {
                    // Listener event : new client
                    let (s, addr) = listeners[token].accept()?;
                    println!("New client with address {}", addr);
                    if server.add_client(s, addr)?.is_none() {
                        println!(
                            "No client found with allowed-ip matching address {}",
                            addr.ip()
                        );
                    }
                }
                Ordering::Equal => {
                    // Netlink event
                    server.recv_notifications(&mut nlstream)?;
                }
                Ordering::Greater => {
                    // Client event
                    let client = server
                        .clients
                        .get_mut(&token)
                        .expect("Polled event from non existing client !");

                    let should_close = match client.new_data_event(&server.peers) {
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
                        let key = client.pubkey.clone();
                        println!(
                            "Closing client {}",
                            base64_encode_bytes(client.pubkey.as_slice())
                        );
                        server.poll.registry().deregister(&mut client.stream)?;
                        server.clients.remove(&token);
                        server.send_all_clients(&SendMessage::DeletePeer(key.as_slice()))?;
                    }
                }
            }
        }
    }
}
