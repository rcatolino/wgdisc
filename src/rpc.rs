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
