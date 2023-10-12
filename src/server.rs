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
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind, Result as IoResult, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use wireguard_uapi::netlink::{
    wgdevice_attribute, AttributeIterator, AttributeType, Error as WgError, MsgBuffer,
    NetlinkRoute, Result as WgResult, SubHeader,
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
    wgname_filter: Option<String>,
    ip_filter: Option<IpAddr>,
    listen_port: u16,
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

    fn peer_from_attr<F: AsRawFd>(
        &self,
        wgindex: i32,
        attributes: AttributeIterator<'_, F>,
    ) -> Option<Peer> {
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
        let wgdata = self
            .wgdata
            .as_mut()
            .expect("Error, received tcp event, but no wireguard listener is configured.");
        let (mut stream, addr) = wgdata.listeners[token - 1].accept()?;
        println!("New client with address {}", addr);
        let peers = wgdata.wg.get_peers()?;
        let peer = match Self::find_peer(&peers, &addr) {
            Some(peer) => peer,
            None => {
                println!(
                    "No client found with allowed-ip matching address {}",
                    addr.ip()
                );
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

        self.clients.insert(self.count, c);
        self.count += 1; // count will overflow when we reach usize::MAX clients, we must build
                         // with panic-on-overflow to prevent any polling confusion in that case.
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
            match mb_msg {
                // EAGAIN indicates that there is noting more to read from netlink
                Err(WgError::OsError(no)) if no == errno::from_i32(EAGAIN) => break,
                Ok((16, ifinfo)) => {
                    if self.wgdata.is_some() {
                        println!("RTM_NEWLINK event ignored because we already have a device");
                    } else {
                        // self.newlink_event(ifinfo)
                        println!("RTM_NEWLINK event {:?}", ifinfo);
                        // TODO: optionally use ifinfo to help wireguard setup
                        self.try_setup_wireguard()?;
                    }
                }
                Ok((17, ifinfo)) => {
                    if let Some(ref wgdata) = self.wgdata {
                        println!("RTM_DELLINK event, {:?}", ifinfo);
                        if wgdata.wg.index == ifinfo.index {
                            self.remove_wireguard()?;
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

    fn recv_notifications(&mut self) -> WgResult<()> {
        let wgdata = self
            .wgdata
            .as_ref()
            .expect("Error, received wg netlink event, but no wireguard interface is configured.");
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

    fn remove_wireguard(&mut self) -> WgResult<()> {
        let wgdata = self
            .wgdata
            .as_mut()
            .expect("Error, tried to remove inexistant wireguard device");
        // Remove nl event stream
        self.poll.registry().deregister(&mut wgdata.nlstream)?;
        // Remove all clients
        for c in self.clients.values_mut() {
            c.stream.shutdown(Shutdown::Both)?;
            self.poll.registry().deregister(&mut c.stream)?;
        }

        self.clients.clear();
        // Remove all listeners
        for l in wgdata.listeners.iter_mut() {
            self.poll.registry().deregister(l)?;
        }

        self.nltok = 1;
        self.count = 0;
        // Delete wireguard interface
        self.wgdata = None;
        Ok(())
    }

    fn try_setup_wireguard(&mut self) -> WgResult<()> {
        if self.wgdata.is_some() {
            panic!("Error, tried to setup a wireguard device, but one exists already");
        }

        match WireguardDev::new(self.wgname_filter.as_deref()) {
            Err(WgError::NoInterfaceFound) => (),
            Err(e) => return Err(e),
            Ok(mut wg) => {
                // Sleep a few seconds to let time to the network management service
                // to assign the ip addresses.
                // This hack should ideally be replaced by listening for
                // netlink NEWADDR events, but I really can't be bothered to implement that.
                std::thread::sleep(Duration::new(2, 0));
                // Register tcp listeners for each interface address
                let listeners = self.setup_listeners(&wg.name)?;
                if listeners.is_empty() {
                    println!(
                        "Warning, no address found matching {:?} on interface {}",
                        self.ip_filter, wg.name
                    );
                    return Ok(());
                }

                // Register netlink wireguard events socket :
                let mut nlstream = wg.subscribe(SockFlag::SOCK_NONBLOCK)?;
                self.nltok = listeners.len() + 1;
                self.poll.registry().register(
                    &mut nlstream,
                    Token(self.nltok),
                    Interest::READABLE,
                )?;
                self.count = self.nltok + 1;
                if self.wgname_filter.is_none() {
                    // We didn't have an interface name specified, but in the event the interface
                    // is removed we only want to use a new interface with the same name.
                    self.wgname_filter.replace(wg.name.clone());
                }

                self.wgdata.replace(WireguardData {
                    wg,
                    nlstream,
                    listeners,
                });
            }
        }

        Ok(())
    }

    fn setup_listeners(&mut self, ifname: &str) -> WgResult<Vec<TcpListener>> {
        let mut listeners = Vec::<TcpListener>::new();
        for (index, mut addr) in getsockaddrs(ifname).enumerate() {
            // if self.ip_filter.is_some() && Some(&addr.ip()) != filter {
            if self.ip_filter.map(|ip| ip != addr.ip()).unwrap_or(false) {
                continue;
            }

            addr.set_port(self.listen_port);
            listeners.push(TcpListener::bind(addr)?);
            self.poll.registry().register(
                &mut listeners[index],
                Token(index + 1),
                Interest::READABLE,
            )?;
            println!(
                "Using wireguard interface {} and address {:?}",
                ifname, addr
            );
        }

        Ok(listeners)
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

pub fn server_main(filter: Option<&String>, args: &ArgMatches) -> WgResult<()> {
    let mut server = Server {
        clients: HashMap::new(),
        poll: Poll::new()?,
        count: 0,
        nltok: 0,
        wgdata: None,
        wgname_filter: filter.cloned(),
        ip_filter: args.get_one::<IpAddr>("address").copied(),
        listen_port: *args.get_one::<u16>("port").expect("default"),
    };

    // Register netlink route link events socket :
    let linktok = 0;
    let nlroute = NetlinkRoute::new(SockFlag::empty());
    let mut linkevts = nlroute.subscribe_link(SockFlag::SOCK_NONBLOCK)?;
    server
        .poll
        .registry()
        .register(&mut linkevts, Token(linktok), Interest::READABLE)?;
    server.try_setup_wireguard()?;

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
