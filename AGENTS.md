# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`extauthz` is the OpenKCM External Authorization service. It implements the Envoy `ext_authz` gRPC API (`envoy.service.auth.v3.AuthorizationServer`) — Envoy calls `Check()` for each incoming HTTP request and this service decides whether to allow, deny, or treat the request as unauthenticated, based on three orthogonal credentials and a Cedar policy decision on top.

## Build, lint, test

```bash
make build          # binary at ./extauthz
make lint           # golangci-lint run -v --fix ./...
make test           # unit + integration with coverage; produces cover.out and junit-*.xml
go test -run TestX ./internal/extauthz   # single test in a package
go test --tags=integration -run TestX ./integration   # single integration test
make helm-test      # helm unit tests + helm integration tests via k3d (needs docker + k3d)
```

Integration tests live under `./integration` and require the `integration` build tag — `make test` runs them in a second `gotestsum` invocation. They `go build` the binary themselves and start a Valkey testcontainer; Docker must be available.

There is also a Taskfile (`Taskfile.yaml`) that pulls in shared tasks from `hack/common/Taskfile_service.yaml` (CI / image / release helpers — not required for normal dev).

## Running locally

The binary loads its config via `commoncfg.LoadConfig` from `/etc/extauthz`, `$HOME/.extauthz`, and `.` (in that order). A working sample is in `examples/` — `examples/config.yaml`, `examples/policies.cedar`, `examples/trustedSubjects.yaml`, `examples/keyId` + matching PEM. To run from a checkout, copy/symlink those into the working directory (or a config dir) and `./extauthz`. `--version` prints build info.

## Architecture

Entry point: `cmd/extauthz/main.go` is intentionally tiny — it only loads config, initializes logger + OTLP, and calls `business.Main`. Real wiring is in `internal/business/`:

- `business.go` → `extauthz.go` builds the `*extauthz.Server` by composing `ServerOption`s (functional options pattern used throughout the codebase).
- `grpc.go` registers the server on a `commongrpc.NewServer` and serves `cfg.GRPCServer.Address`. Shutdown is driven by context cancellation from `runFuncWithSignalHandling` in `main.go`.

`internal/extauthz/` is the heart. `Check()` in `check.go` runs three independent credential checks and merges their `checkResult`s — **the most restrictive result wins** (`check_result.go`):

1. **mTLS / XFCC** (`check_client_cert.go`) — parses the Envoy `x-forwarded-client-cert` header (multiple certs allowed, custom comma-splitting in `splitCertHeader` to respect quoted values). Subject must be in the trusted-subjects YAML map (`trusted_certificates.go`); the mapped value becomes the region.
2. **JWT bearer** (`check_jwt_token.go`) — delegates to `internal/handler/OIDC`, which supports static providers from config plus on-demand discovery, caches signing keys and introspection results (`ttlcache`), and validates against configured audiences. Issuer claim keys are configurable (default `iss`).
3. **Session cookie** (`check_session.go`) — only active when a session manager is configured *and* the path matches one of `sessionPathPrefixes`. The tenant ID is the path segment immediately after the prefix; the cookie is `__Host-Http-SESSION-<tenantID>`. CSRF token (`x-csrf-token`) is verified against an HMAC of the session derived from `csrfSecret`. Sessions are fetched from a remote session-manager gRPC service (`internal/session/`).

After the merged result, `Check()` calls into the **policy engine** (`internal/policies/`) for an additional Cedar-based decision (host/path/auth-type/issuer go in as context). The engine is an interface; the only implementation is `internal/policies/cedarpolicy/`, which loads `*.cedar` files from `cfg.Cedar.PolicyPath` (or explicit bytes/file). Policies, trusted subjects, and the signing key are all hot-loadable from disk and typically delivered as Kubernetes ConfigMaps (see `examples/*Configmap*.yaml`).

On `ALLOWED`, the response strips the inbound `x-forwarded-client-cert` and (if a `clientDataSigner` is configured) adds `auth.HeaderClientData` + `auth.HeaderClientDataSignature`: a signed JSON blob of the resolved subject/region/type/issuer that downstream services consume as a trustworthy identity envelope. The signing key is loaded from `cfg.ClientData.SigningKeyIDFilePath` — the file holds a key ID and `<keyID>.pem` is read from the same directory (`internal/clientdata/`).

`respond.go` has the small set of canned `CheckResponse` builders (`respondAllowed`, `respondUnauthenticated`, `respondPermissionDenied`, `respondTenantBlocked`, `respondInternalServerError`).

## Conventions worth knowing

- Errors are wrapped with `github.com/samber/oops` (`oops.In(...).Wrapf(...)`, `oops.Hint(...).Wrap(...)`). Match this when adding error paths in `business`/`extauthz`.
- Logging uses `slogctx` (`github.com/veqryn/slog-context`) — propagate context with `slogctx.With(ctx, ...)` rather than passing loggers around. The `Check()` flow uses prefix constants (`LogPrefixCheck`, `LogPrefixClientCert`, …) for greppability.
- New server dependencies go in via a `ServerOption` (`WithFoo(...)`) returning an error if the value is invalid — see `internal/extauthz/extauthz.go`.
- Test interfaces are defined locally next to consumers (e.g. `sessionManagerInterface`, `oidcHandlerInterface`) so that mocks don't require touching the producing package.
- `golangci-lint` config (`.golangci.yaml`) enables `default: all` with a long disable list — when adding code, expect strict linting (paralleltest, testifylint, etc.). Test files relax `dupl`/`funlen`/`gocognit`/`goconst`/`maintidx`.
- The gRPC server created in `internal/business/grpc.go` does not enforce TLS/mTLS and may run on plain TCP. In this case the deployment must involve a service mesh like `linkerd` to ensure the communication is secure.
