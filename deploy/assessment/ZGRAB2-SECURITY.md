# ZGrab2 container dependency security overlay

The image retains ZGrab2 `1.0.0` scanner source at upstream commit
`ea734bcf60ef2921684cb522dfb87a07a322afa6`. Deckard replaces only its Go module
manifest and checksums with the reviewed `zgrab2.go.mod` and `zgrab2.go.sum`.
This is a downstream dependency overlay, not an unchanged upstream build.

| Module | Upstream | Downstream |
| --- | --- | --- |
| `github.com/rabbitmq/amqp091-go` | `v1.10.0` | `v1.13.0` |
| `golang.org/x/crypto` | `v0.45.0` | `v0.57.0` |
| `golang.org/x/net` | `v0.47.0` | `v0.60.0` |
| `golang.org/x/text` | `v0.31.0` | `v0.42.0` |

These exact versions address fixable HIGH findings in the original scanner binary.
The Go dependencies require `go 1.26.0` and lift `x/sys` to `v0.48.0` and
`x/term` to `v0.46.0`. No other dependency versions change. The downstream lock
was produced with `go get` for the four explicit versions and `go mod tidy`.
The build verifies module checksums and uses `-mod=readonly`.

The image retains upstream, embedded SMB, Go and compiled dependency notices.
Native HTTP/TLS scanner fixtures and binary build-metadata tests must pass.
A fresh HIGH/CRITICAL vulnerability scan must pass before publication.
The local fixtures do not prove Kubernetes network containment.
