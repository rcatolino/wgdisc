use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{copy, ErrorKind, Read, Result};
use std::net::IpAddr;

// We separate the receive/send message because this allows us to remove a vec allocation
// in the serializing case
#[derive(Serialize, Debug)]
pub enum SendMessage<'a> {
    AddPeer(&'a PeerDef),
    DeletePeer(&'a str),
    AddPeers(&'a [PeerDef]),
    GetPeerList,
}

#[derive(Deserialize, Debug)]
pub enum RecvMessage {
    AddPeer(PeerDef),
    DeletePeer(String),
    AddPeers(Vec<PeerDef>),
    GetPeerList,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerDef {
    pub peer_key: String,
    pub endpoint: (IpAddr, u16),
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u32>,
}

impl PeerDef {
    pub fn to_wg_set<'a>(&self) -> impl Iterator<Item = String> + 'a {
        [
            String::from("peer"),
            self.peer_key.clone(),
            String::from("endpoint"),
            format!("{}:{}", self.endpoint.0, self.endpoint.1),
            String::from("allowed-ips"),
            self.allowed_ips
                .iter()
                .map(|(ip, mask)| format!("{}/{}", ip, mask))
                .collect::<Vec<String>>()
                .join(","),
            String::from("persistent-keepalive"),
            self.keepalive
                .map(|u| u.to_string())
                .unwrap_or("off".to_string()),
        ]
        .into_iter()
    }

    pub fn from_wg_dump(line: &str) -> Option<PeerDef> {
        let mut conf = line.split_terminator('\t');
        let brackets: &[_] = &['[', ']'];
        let peer = PeerDef {
            peer_key: conf.next()?.to_string(),
            endpoint: conf.nth(1)?.rsplit_once(':').and_then(|(ip, port)| {
                Some((ip.trim_matches(brackets).parse().ok()?, port.parse().ok()?))
            })?,
            allowed_ips: conf
                .next()?
                .split_terminator(',')
                .filter_map(|ipmask| {
                    let (ip, mask) = ipmask.rsplit_once('/')?;
                    Some((ip.parse().ok()?, mask.parse().ok()?))
                })
                .collect(),
            keepalive: conf.nth(3)?.parse::<u32>().ok(),
        };

        Some(peer)
    }
}

pub struct MsgBuf {
    inner: VecDeque<u8>,
    position: usize,
}

impl Read for MsgBuf {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let (first_slice, second_slice) = self.inner.as_slices();
        let src = if self.position < first_slice.len() {
            &first_slice[self.position..]
        } else if self.position - first_slice.len() < second_slice.len() {
            &second_slice[self.position - first_slice.len()..]
        } else {
            return Ok(0);
        };

        let copy_size = std::cmp::min(buf.len(), src.len());
        buf[0..copy_size].copy_from_slice(&src[0..copy_size]);
        self.position += copy_size;
        Ok(copy_size)
    }
}

impl MsgBuf {
    pub fn new() -> Self {
        MsgBuf {
            inner: VecDeque::with_capacity(1024),
            position: 0,
        }
    }

    pub fn drain<T: Read>(&mut self, source: &mut T) -> Result<usize> {
        let previous_size = self.inner.len();
        match copy(source, &mut self.inner) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(self.inner.len() - previous_size),
            Ok(_) => Ok(self.inner.len() - previous_size),
            Err(e) => Err(e),
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn consume(&mut self, amt: usize) {
        self.position = 0;
        self.inner.drain(..amt);
    }
}
