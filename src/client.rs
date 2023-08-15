use crate::rpc::{Message, PeerDef};
use clap::ArgMatches;
use serde_json::Deserializer;
use std::net::TcpStream;

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
    /*
    for msg in msg_stream {
        println!("New message : {:?}", msg);
    }
    */
    serde_json::to_writer(&stream, &Message::GetPeerList)?;
    let msg_stream = Deserializer::from_reader(&stream).into_iter::<Message>();
    for msg in msg_stream {
        println!("New message : {:?}", msg);
        match msg? {
            Message::AddPeer(peer) => Client::add_peer(peer),
            Message::DeletePeer(peer_key) => Client::delete_peer(&peer_key),
            Message::AddPeers(peer_list) => {
                for p in peer_list {
                    Client::add_peer(p);
                }
            }
            _ => println!("Unsupported message"),
        };
    }

    Ok(())
}
