use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{copy, ErrorKind, Read, Result};
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
    pub peer_key: String,
    pub endpoint: (IpAddr, u16),
    pub allowed_ips: Vec<(IpAddr, u8)>,
}

impl PeerDef {
    pub fn to_wg_set<'a>(&self) -> impl Iterator<Item = String> + 'a {
        [
            String::from("peer"),
            self.peer_key.clone(),
            String::from("endpoint"),
            format!("{}:{}", self.endpoint.0, self.endpoint.1),
            String::from("allwed-ips"),
            self.allowed_ips
                .iter()
                .map(|(ip, mask)| format!("{}/{}", ip, mask))
                .collect::<Vec<String>>()
                .join(","),
        ]
        .into_iter()
    }

    pub fn from_wg_dump(line: &str) -> Option<PeerDef> {
        let conf: Vec<&str> = line.split_terminator('\t').collect();
        let peer = PeerDef {
            peer_key: conf[0].to_string(),
            endpoint: conf[2]
                .rsplit_once(':')
                .and_then(|(ip, port)| Some((ip.parse().ok()?, port.parse().ok()?)))?,
            allowed_ips: conf[3]
                .split_terminator(',')
                .filter_map(|ipmask| {
                    let (ip, mask) = ipmask.rsplit_once('/')?;
                    Some((ip.parse().ok()?, mask.parse().ok()?))
                })
                .collect(),
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
        Ok(copy_size.try_into().unwrap())
    }
}

impl MsgBuf {
    pub fn new() -> Self {
        MsgBuf {
            inner: VecDeque::with_capacity(16),
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
