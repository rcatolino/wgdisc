use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    AddPeer(PeerDef),
    DeletePeer(Vec<u8>),
    AddPeers(Vec<PeerDef>),
    GetPeerList,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerDef {
    pub peer_key: Vec<u8>,
    pub endpoint: IpAddr,
    pub allowed_ips: Vec<(IpAddr, u8)>,
}
