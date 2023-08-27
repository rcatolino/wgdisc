# Wireguard Peer Discovery

This tool allows peer to peer connections between `n` hosts in a wireguard vpn without having to configure `n-1` peer for each hosts.
Instead each of the hosts has only one peer configured (the "server" host). The "server" then sends each all of the peer details to each client.

## On the server machine

`wgdisc server`

## On the clients

`wgdisc client -a <server ip in the vpn network>`

