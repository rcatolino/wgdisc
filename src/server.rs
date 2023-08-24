use crate::cidr;
use crate::rpc::{MsgBuf, PeerDef, RecvMessage, SendMessage};
use crate::wireguard;
use clap::ArgMatches;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use nix::ifaddrs::getifaddrs;
use serde_json::Deserializer;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::net::{IpAddr, SocketAddr};

struct Client {
    stream: TcpStream,
    buffer: MsgBuf,
    pubkey: String,
    addr: SocketAddr,
}

impl Client {
    fn new_data_event(&mut self, peers: &[PeerDef]) -> IoResult<bool> {
        let drained = self.buffer.drain(&mut self.stream)?;
        if drained == 0 {
            // Empty read, the socket must be closed
            return Ok(true);
        } else {
            // println!("Read {} bytes from client {}.", drained, self.addr);
            match self.handle_messages(peers) {
                Ok(consumed) => self.buffer.consume(consumed),
                Err(e) => {
                    println!(
                        "Error deserializing from client {} : {}. Terminating client.",
                        self.addr, e
                    );
                    return Ok(true); // Invalid/Corrupted message => bad client
                }
            }
        }

        Ok(false)
    }

    fn handle_messages(&mut self, peers: &[PeerDef]) -> std::io::Result<usize> {
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
    peers: Vec<PeerDef>,
    clients: HashMap<usize, Client>,
    poll: Poll,
    count: usize,
    wgifname: String,
}

impl Server {
    fn find_peer(&'_ self, addr: &SocketAddr) -> Option<&'_ PeerDef> {
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
        for c in self.clients.values() {
            serde_json::to_writer(&c.stream, &SendMessage::AddPeer(peer))?
        }

        self.clients.insert(self.count, c);
        self.count += 1;
        Ok(Some(()))
    }

    fn update_peers(&mut self) {
        self.peers = wireguard::get_peers(&self.wgifname)
            .unwrap_or_else(|_| panic!("Unable to get wireguard peers for {}", &self.wgifname));
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

pub fn server_main(wgifname: &str, args: &ArgMatches) -> std::io::Result<()> {
    let mut listeners = Vec::<TcpListener>::new();
    let mut server = Server {
        clients: HashMap::new(),
        peers: Vec::new(),
        poll: Poll::new()?,
        count: 0,
        wgifname: wgifname.to_string(),
    };

    for (index, mut addr) in getsockaddrs(wgifname).enumerate() {
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
            wgifname, addr
        );
    }

    if listeners.is_empty() {
        let msg = format!("No address found for interface {}", wgifname);
        return Err(IoError::new(ErrorKind::Other, msg));
    }

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
                // We start numbering clients from listeners.len() + 1
                Ordering::Equal => unreachable!(),
                Ordering::Greater => {
                    // Client event
                    let client = server
                        .clients
                        .get_mut(&token)
                        .expect("Polled event from non existing client !");

                    let should_close = client.new_data_event(&server.peers)?;
                    if event.is_read_closed() || should_close {
                        let key = client.pubkey.clone();
                        println!("Closing client {}", client.pubkey);
                        server.poll.registry().deregister(&mut client.stream)?;
                        server.clients.remove(&token);
                        for c in server.clients.values() {
                            serde_json::to_writer(
                                &c.stream,
                                &SendMessage::DeletePeer(key.as_str()),
                            )?
                        }
                    }
                }
            }
        }
    }
}
