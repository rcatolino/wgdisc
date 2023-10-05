use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{copy, ErrorKind, Read, Result};
use wireguard_uapi::wireguard::Peer;

// We separate the receive/send message because this allows us to remove a vec allocation
// in the serializing case
#[derive(Serialize, Debug)]
pub enum SendMessage<'a> {
    AddPeer(&'a Peer),
    DeletePeer(&'a [u8]),
    AddPeers(&'a [Peer]),
    GetPeerList,
}

#[derive(Deserialize, Debug)]
pub enum RecvMessage {
    AddPeer(Peer),
    DeletePeer(Vec<u8>),
    AddPeers(Vec<Peer>),
    GetPeerList,
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
