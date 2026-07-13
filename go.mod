module github.com/pilot-protocol/handshake

go 1.25.12

require (
	github.com/pilot-protocol/pilotprotocol v0.0.0
	github.com/pilot-protocol/common v0.4.0
)

require (
	github.com/coder/websocket v1.8.14 // indirect
	github.com/pilot-protocol/rendezvous v0.1.0 // indirect
	github.com/pilot-protocol/trustedagents v0.1.0 // indirect
)

replace github.com/pilot-protocol/pilotprotocol => ../web4

replace github.com/pilot-protocol/common => ../common
