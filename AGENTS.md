# AGENTS.md

Guidance for AI agents working on this repository.

## Build & test

```bash
go build ./...          # must pass before any PR
go vet ./...            # must pass before any PR
go test ./...           # must pass before any PR
go generate ./...       # regenerate mocks when the Service interface in handler.go changes
```

Tests output OTel span/metric JSON to stdout — this is normal, look for `ok`/`FAIL` lines to assess pass/fail.

## Architecture

```
cmd/main.go
  └── wires OTel provider, service, handler → lambda.Start (blocks)

internal/handler/handler.go   RouteEvent  — sniffs version field, routes to typed handler
internal/handler/v1.go        HandleV1Event     (API Gateway v1.0)
internal/handler/v2.go        HandleV2Event     (API Gateway v2.0)
internal/handler/websocket.go HandleWebsocketEvent
internal/service/service.go   ValidateToken — fetches JWKS, parses + validates JWT, extracts principal
```

OTel provider, logger helpers, and error attribute key come from `github.com/matt-gp/core` — not from local packages.

## OTel conventions

**Metrics** — two instruments only, both on the handler:
- `oidc_authorizer.invocations` — `metric.Int64Counter`
- `oidc_authorizer.request.duration` — `metric.Float64Histogram`, unit `s`

Both carry `status` (`success`|`error`) and `event.type` (`v1`|`v2`|`websocket`). Don't add more metrics without a clear reason; the service intentionally has none.

**Spans** — only on meaningful operations:
- `validate-token` in service
- `v1-event`, `v2-event`, `websocket-event` in the individual handlers

Don't add spans to every function. Routing and unmarshalling are not worth their own spans.

**Attributes** — `event.type` carries the API Gateway version (`v1`, `v2`, `websocket`), not internal operation steps. Use dot-notation keys (`event.type`, `status`) following OTel semantic conventions.

## Security constraints

This is a security-critical project — it is the authentication gate for API Gateway.

- **Never log raw JWT token values**, even at debug level. Tokens are replayable credentials.
- Token validation failures are normal outcomes (Deny), not errors — don't treat them as exceptional.
- Error messages must not leak internal state to the caller.

## Key behaviours to preserve

- `RouteEvent` records metrics **after** the full handler returns, so latency and status reflect the complete invocation including token validation.
- `getTokenFromWebsocketEvent` guards against a missing space in the `Authorization` header before splitting — keep this guard consistent with the v1/v2 pattern.
- `service.New` returns `*Service` directly (no error) — keep it that way unless the constructor gains fallible operations.
- The `main` span was intentionally removed: `lambda.Start` blocks and `os.Exit` skips deferred functions, so spans in `main` are never exported.
