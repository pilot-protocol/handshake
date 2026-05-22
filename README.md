# handshake

Handshake plugin for the Pilot Protocol daemon. Manages node-to-node
trust:

- listens on port 444 for incoming handshake offers
- emits `handshake.requested` events to the daemon
- persists accepted trust records to `trust.json`
- consults the trustedagents allowlist for auto-accept of public peers
- handles both direct and relayed handshakes (NAT-traversal cases)

## Install

```go
import "github.com/pilot-protocol/handshake"
```

## Usage

```go
s := handshake.NewService(handshake.Config{
    TrustPath:         "~/.pilot/trust.json",
    AutoApprovePublic: true,
})
rt.Register(s)
```

## Layout

| File | What it does |
|---|---|
| `handshake.go` | Wire format and `Manager` (in-memory trust + pending state). |
| `runtime.go` | Daemon-facing interface for trust lookup and auto-approve flag. |
| `service.go` | `*Service` — `coreapi.Service` adapter. |
