use crate::rpc::Message;
use crate::wireguard;
use clap::ArgMatches;
use serde_json::Deserializer;
use std::net::TcpStream;

pub fn client_main(wgifname: &str, args: &ArgMatches) -> std::io::Result<()> {
    let stream = TcpStream::connect((
        args.get_one::<String>("address")
            .expect("required")
            .as_str(),
        *args.get_one::<u16>("port").expect("default"),
    ))?;

    // We've just started, ask for all existing peers :
    serde_json::to_writer(&stream, &Message::GetPeerList)?;
    let msg_stream = Deserializer::from_reader(&stream).into_iter::<Message>();

    // Listen for incoming messages
    for msg in msg_stream {
        println!("New message : {:?}", msg);
        match msg? {
            Message::AddPeer(peer) => {
                wireguard::add_peers(wgifname, [&peer])?;
            }
            Message::DeletePeer(_) => (),
            Message::AddPeers(peer_list) => {
                wireguard::add_peers(wgifname, peer_list.iter())?;
            }
            _ => println!("Unsupported message"),
        };
    }

    Ok(())
}
