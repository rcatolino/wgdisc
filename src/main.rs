use std::net::{IpAddr,TcpStream, TcpListener};
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use clap::{Arg, Command, ArgAction, ArgMatches};

#[derive(Serialize, Deserialize, Debug)]
enum Message {
    AddPeer { peer: PeerDef },
    DeletePeer { pubkey: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug)]
struct PeerDef {
    peer_key : Vec<u8>,
    endpoint: IpAddr,
    allowed_ips : Vec<(IpAddr, u8)>,
}

trait Peer {
    fn add_peer(peer: PeerDef);
    fn delete_peer(peer: &[u8]);
}

struct Client;

impl Peer for Client {
    fn add_peer(peer: PeerDef) {
        println!("New peer : {:?}", peer);
    }

    fn delete_peer(peer_key: &[u8]) {
        println!("Delete peer with key {:?}", peer_key);
    }
}

fn server_main(args: &ArgMatches) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:34254")?;
    let msg = Message::AddPeer {
        peer : PeerDef {
            peer_key: vec![0; 16],
            endpoint: "127.0.0.1".parse().unwrap(),
            allowed_ips: vec![("0.0.0.1".parse().unwrap(), 0)],
        }
    };

    for stream in listener.incoming() {
        serde_json::to_writer(stream?, &msg)?;
    }

    Ok(())
}

fn client_main(args: &ArgMatches) -> std::io::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:34254")?;
    let msg_stream = Deserializer::from_reader(stream).into_iter::<Message>();
    for msg in msg_stream {
        println!("New message : {:?}", msg);
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    let matches = Command::new("wgdisc")
        .arg(Arg::new("verbose").short('v').long("verbose").action(ArgAction::SetTrue))
        .subcommand_required(true)
        .subcommand(
            Command::new("client")
                .arg(Arg::new("host").required(true))
                .arg(Arg::new("port").default_value("31250"))
        )
        .subcommand(
            Command::new("server")
                .arg(Arg::new("host").required(true))
                .arg(Arg::new("port").default_value("31250"))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("client", submatches)) => client_main(submatches)?,
        Some(("server", submatches)) => server_main(submatches)?,
        _ => unreachable!("Unknown or missing subcommand"),
    };

    Ok(())
}


