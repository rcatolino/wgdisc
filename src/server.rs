use crate::rpc::{Query, Response, PeerDef};
use clap::{ArgMatches};
use std::net::{TcpListener, TcpStream};

struct Server;
impl Server {
    fn get_peer_list(&self) -> Response {
        Response::PeerList { peers: Vec::new() }
    }
}

pub fn server_main(args: &ArgMatches) -> std::io::Result<()> {
    let listener = TcpListener::bind((
        args.get_one::<String>("host").expect("required").as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;
    let msg = Query::AddPeer {
        peer: PeerDef {
            peer_key: vec![0; 16],
            endpoint: "127.0.0.1".parse().unwrap(),
            allowed_ips: vec![("0.0.0.1".parse().unwrap(), 0)],
        },
    };

    for stream in listener.incoming() {
        serde_json::to_writer(stream?, &msg)?;
    }

    Ok(())
}
