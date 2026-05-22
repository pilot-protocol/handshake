# handshake

[![ci](https://github.com/pilot-protocol/handshake/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/handshake/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/handshake/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/handshake)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

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

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
