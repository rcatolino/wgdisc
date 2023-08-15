use crate::rpc::{Message, PeerDef};
use crate::wireguard::list;
use clap::ArgMatches;
use mio::{Events, Poll};
use nix::ifaddrs::getifaddrs;
use serde_json::Deserializer;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener};

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
    let addrs: Vec<SocketAddr> = getsockaddrs(&wgifname)
        .filter_map(|mut sockaddr| {
            if let Some(filter) = args.get_one::<IpAddr>("address") {
                if sockaddr.ip() != *filter {
                    return None;
                }
            }

            sockaddr.set_port(*args.get_one::<u16>("port").expect("default"));
            Some(sockaddr)
        })
        .collect();

    println!(
        "Using wireguard interface {} and address {:?}",
        wgifname, addrs
    );

    if addrs.len() == 0 {
        let msg = format!("No address found for interface {}", wgifname);
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    let poll = Poll::new()?;
    let events = Events::with_capacity(128);

    let listener = TcpListener::bind(addrs[0])?;

    /*
    let listener = TcpListener::bind((
        args.get_one::<String>("host").expect("required").as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;
    */

    let msg = Message::AddPeer(PeerDef {
        peer_key: vec![0; 16],
        endpoint: "127.0.0.1".parse().unwrap(),
        allowed_ips: vec![("0.0.0.1".parse().unwrap(), 0)],
    });

    for stream in listener.incoming() {
        let s = stream?;
        serde_json::to_writer(&s, &msg)?;
        let msg_stream = Deserializer::from_reader(&s).into_iter::<Message>();
        for msg in msg_stream {
            println!("New message : {:?}", msg);
            match msg? {
                Message::GetPeerList => serde_json::to_writer(&s, &Server::get_peer_list())?,
                _ => println!("Unsupported message"),
            }
        }
    }

    Ok(())
}
