module github.com/pilot-protocol/handshake

go 1.25.3

require (
	github.com/TeoSlayer/pilotprotocol v0.0.0
	github.com/pilot-protocol/common v0.0.0
)

require (
	github.com/coder/websocket v1.8.14 // indirect
	github.com/pilot-protocol/trustedagents v0.0.0 // indirect
)

replace github.com/TeoSlayer/pilotprotocol => ../web4

replace github.com/pilot-protocol/common => ../common

// Mirror web4's replace directives so transitive deps resolve against
// local sibling checkouts during co-development. Drop these once each
// repo is tagged and v0.0.0 placeholders are replaced with real
// semvers (then web4 also drops its replaces).
replace github.com/pilot-protocol/app-store => ../app-store

replace github.com/pilot-protocol/trustedagents => ../trustedagents

replace github.com/pilot-protocol/skillinject => ../skillinject

replace github.com/pilot-protocol/webhook => ../webhook

replace github.com/pilot-protocol/eventstream => ../eventstream

replace github.com/pilot-protocol/dataexchange => ../dataexchange

replace github.com/pilot-protocol/updater => ../updater

replace github.com/pilot-protocol/gateway => ../gateway

replace github.com/pilot-protocol/nameserver => ../nameserver

replace github.com/pilot-protocol/policy => ../policy
