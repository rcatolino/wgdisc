use crate::rpc::{Message, MsgBuf, PeerDef};
use crate::wireguard::list;
use clap::ArgMatches;
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};
use nix::ifaddrs::getifaddrs;
use serde_json::Deserializer;
use std::collections::HashMap;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};

struct Server;
impl Server {
    fn get_peer_list() -> Message {
        Message::AddPeers(Vec::new())
    }
}

pub fn getsockaddrs<'a>(ifname: &'a str) -> impl Iterator<Item = SocketAddr> + 'a {
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

pub fn server_main(args: &ArgMatches) -> std::io::Result<()> {
    let wgifname = list()?;
    let mut listeners = Vec::<TcpListener>::new();
    let mut poll = Poll::new()?;

    for (index, mut addr) in getsockaddrs(&wgifname).enumerate() {
        let filter = args.get_one::<IpAddr>("address");
        if filter.is_some() && Some(&addr.ip()) != filter {
            continue;
        }

        addr.set_port(*args.get_one::<u16>("port").expect("default"));
        listeners.push(TcpListener::bind(addr)?);
        poll.registry()
            .register(&mut listeners[index], Token(index), Interest::READABLE)?;
        println!(
            "Using wireguard interface {} and address {:?}",
            wgifname, addr
        );
    }

    if listeners.len() == 0 {
        let msg = format!("No address found for interface {}", wgifname);
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    let msg = Message::AddPeer(PeerDef {
        peer_key: vec![0; 16],
        endpoint: "127.0.0.1".parse().unwrap(),
        allowed_ips: vec![("0.0.0.1".parse().unwrap(), 0)],
    });

    let mut events = Events::with_capacity(128);
    let mut clients = HashMap::new();
    let mut count = listeners.len() + 1;
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            // println!("New event : {:?}", event);
            let token = event.token().0;
            if token < listeners.len() {
                // Listener event
                let (mut s, _) = listeners[token].accept()?;
                poll.registry()
                    .register(&mut s, Token(count), Interest::READABLE)?;
                clients.insert(count, (s, MsgBuf::new()));
                count += 1;
            } else if token > listeners.len() {
                // Client event
                // serde_json::to_writer(&s, &msg)?;
                let (stream, buffer) = clients
                    .get_mut(&token)
                    .expect("Polled event from non existing client !");

                let drained = buffer.drain(stream)?;
                let mut should_close = false;
                if drained == 0 {
                    should_close = true;
                } else {
                    println!("Read {} bytes from client {}.", drained, token);
                    let consumed = {
                        let mut msgstream =
                            Deserializer::from_reader(&mut *buffer).into_iter::<Message>();
                        for msg in msgstream.by_ref() {
                            match msg {
                                Ok(Message::GetPeerList) => {
                                    println!("Received message GetPeerList");
                                    serde_json::to_writer(&mut *stream, &Server::get_peer_list())?
                                }
                                Err(e) => println!("Error deserializing msg : {:?}", e),
                                Ok(m) => println!("Unsupported message {:?}", m),
                            }
                        }

                        msgstream.byte_offset()
                    };

                    buffer.consume(consumed);
                }

                if event.is_read_closed() || should_close {
                    poll.registry().deregister(stream)?;
                    clients.remove(&token);
                }
            }
        }
    }
}
