use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{copy, ErrorKind, Read, Result};
use wireguard_uapi::wireguard::Peer;

// We separate the receive/send message because this allows us to remove a vec allocation
// in the serializing case
#[derive(Serialize, Debug)]
pub enum SendMessage<'a> {
    Ping,
    AddPeer(&'a Peer),
    DeletePeer(&'a [u8]),
    AddPeers(&'a [Peer]),
    GetPeerList,
}

#[derive(Deserialize, Debug)]
pub enum RecvMessage {
    Ping,
    AddPeer(Peer),
    DeletePeer(Vec<u8>),
    AddPeers(Vec<Peer>),
    GetPeerList,
}

/// Buffer used for non-blocking deserialization
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

    /// Copy as much data as possible from the source into the inner buffer.
    /// Does not return an error if the underlying source returns EAGAIN/EWOULDBLOCK.
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

    /// Indicates that `amt` bytes of data have been used and can be discarded from the buffer.
    /// The read head is reset to the start of the buffer, so any data that was prevously read
    /// beyond `amt` (incomplete messages) will be read again.
    pub fn consume(&mut self, amt: usize) {
        self.position = 0;
        self.inner.drain(..amt);
    }
}
