module github.com/pilot-protocol/handshake

go 1.25.12

require (
	github.com/pilot-protocol/common v0.5.7
	github.com/pilot-protocol/pilotprotocol v1.12.5
)

require (
	github.com/coder/websocket v1.8.15 // indirect
	github.com/pilot-protocol/rendezvous v0.2.5 // indirect
	github.com/pilot-protocol/trustedagents v0.2.4 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/pilot-protocol/pilotprotocol => ../web4

replace github.com/pilot-protocol/common => ../common
