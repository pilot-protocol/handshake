module github.com/pilot-protocol/handshake

go 1.25.10

require (
	github.com/TeoSlayer/pilotprotocol v0.0.0
	github.com/pilot-protocol/common v0.2.0
)

require (
	github.com/coder/websocket v1.8.14 // indirect
	github.com/pilot-protocol/rendezvous v0.1.0 // indirect
	github.com/pilot-protocol/trustedagents v0.1.0 // indirect
)

replace github.com/TeoSlayer/pilotprotocol => ../web4

replace github.com/pilot-protocol/common => ../common
