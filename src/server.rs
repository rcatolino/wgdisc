use crate::rpc::{Message, MsgBuf};
use crate::wireguard;
use clap::ArgMatches;
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};
use nix::ifaddrs::getifaddrs;
use serde_json::Deserializer;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Error as IoError;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};

struct Server;
impl Server {
    fn get_peer_list(ifname: &str) -> Message {
        let peers = wireguard::get_peers(ifname)
            .unwrap_or_else(|_| panic!("Unable to get wireguard peers for {}", ifname));
        Message::AddPeers(peers)
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

fn handle_messages<W: Write>(
    wgifname: &str,
    stream: &mut W,
    buffer: &mut MsgBuf,
) -> std::io::Result<usize> {
    let mut msgstream = Deserializer::from_reader(&mut *buffer).into_iter::<Message>();
    for msg in msgstream.by_ref() {
        match msg {
            Ok(Message::GetPeerList) => {
                println!("Received message GetPeerList");
                serde_json::to_writer(&mut *stream, &Server::get_peer_list(wgifname))?
            }
            Err(e) if e.is_eof() => (), // This just means we need to wait
            // for more data to deserialize
            Err(e) => return Err(IoError::new(ErrorKind::Other, e.to_string())),
            Ok(m) => println!("Unsupported message {:?}", m),
        }
    }

    Ok(msgstream.byte_offset())
}

pub fn server_main(wgifname: &str, args: &ArgMatches) -> std::io::Result<()> {
    let mut listeners = Vec::<TcpListener>::new();
    let mut poll = Poll::new()?;

    for (index, mut addr) in getsockaddrs(wgifname).enumerate() {
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

    if listeners.is_empty() {
        let msg = format!("No address found for interface {}", wgifname);
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    let mut events = Events::with_capacity(128);
    let mut clients = HashMap::new();
    let mut count = listeners.len() + 1;
    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            // println!("New event : {:?}", event);
            let token = event.token().0;
            match token.cmp(&listeners.len()) {
                Ordering::Less => {
                    // Listener event
                    let (mut s, _) = listeners[token].accept()?;
                    poll.registry()
                        .register(&mut s, Token(count), Interest::READABLE)?;
                    clients.insert(count, (s, MsgBuf::new()));
                    count += 1;
                }
                Ordering::Equal => unreachable!(), // We start numbering clients from
                // listeners.len() + 1
                Ordering::Greater => {
                    // Client event
                    let (stream, buffer) = clients
                        .get_mut(&token)
                        .expect("Polled event from non existing client !");

                    let drained = buffer.drain(stream)?;
                    let mut should_close = false;
                    if drained == 0 {
                        should_close = true;
                    } else {
                        println!("Read {} bytes from client {}.", drained, token);
                        match handle_messages(wgifname, stream, buffer) {
                            Ok(consumed) => buffer.consume(consumed),
                            Err(e) => {
                                println!("Error deserializing from client {} : {}. Terminating client.", token, e);
                                should_close = true;
                            }
                        }
                    }

                    if event.is_read_closed() || should_close {
                        poll.registry().deregister(stream)?;
                        clients.remove(&token);
                    }
                }
            }
        }
    }
}
