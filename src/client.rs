use clap::{ArgMatches};
use std::net::{TcpStream};
use serde_json::Deserializer;
use crate::rpc::{Query, PeerDef};

struct Client;
impl Client {
    fn add_peer(peer: PeerDef) {
        println!("New peer : {:?}", peer);
    }

    fn delete_peer(peer_key: &[u8]) {
        println!("Delete peer with key {:?}", peer_key);
    }
}

pub fn client_main(args: &ArgMatches) -> std::io::Result<()> {
    let stream = TcpStream::connect((
        args.get_one::<String>("host").expect("required").as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;
    let msg_stream = Deserializer::from_reader(stream).into_iter::<Query>();
    for msg in msg_stream {
        println!("New message : {:?}", msg);
    }

    Ok(())
}
