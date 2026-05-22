# handshake

Pilot Protocol handshake plugin. Manages node-to-node trust:
- listens on port 444 for incoming handshake offers
- emits `handshake.requested` events to the daemon
- persists accepted trust records (`trust.json`)
- consults the trustedagents allowlist for auto-accept of public peers
- handles both direct and relayed handshakes (NAT-traversal cases)

## Layout

| File | What it does |
|---|---|
| `handshake.go` | Wire format + `Manager` (in-memory trust + pending state). |
| `runtime.go` | Daemon-facing interface for trust lookup + auto-approve flag. |
| `service.go` | `*Service` — `coreapi.Service` adapter. |

## Import paths

```go
import "github.com/pilot-protocol/handshake"

s := handshake.NewService(handshake.Config{
    TrustPath:        "~/.pilot/trust.json",
    AutoApprovePublic: true,
})
rt.Register(s)
```

## Test deps

The tests reach into `pkg/daemon` and `pkg/registry/{client,server}`
from the protocol repo (via `tests/regtestutil`). Production builds
linking against this module **do not** pull those in.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4 pulls it in via
`require github.com/pilot-protocol/handshake v0.1.0`. During
co-development the protocol repo uses `replace ../handshake`.
