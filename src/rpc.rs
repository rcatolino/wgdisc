use serde::{Deserialize, Serialize};
use std::net::{IpAddr};

#[derive(Serialize, Deserialize, Debug)]
pub enum Query {
    AddPeer { peer: PeerDef },
    DeletePeer { pubkey: Vec<u8> },
    GetPeerList,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    PeerList { peers: Vec<PeerDef> }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerDef {
    pub peer_key: Vec<u8>,
    pub endpoint: IpAddr,
    pub allowed_ips: Vec<(IpAddr, u8)>,
}


