# go-commons

Go packages three estate services share: grimoire, tribelt and the estate dashboard. A package
lands here only when a consumer migrates to it, in a pull request of the consumer's that names
this one (JorisJonkers-dev/go-commons#1). Nothing here is speculative.

| Package | What | Consumers |
|---------|------|-----------|
| [`secure`](secure) | the browser hardening headers: the three every service sends the same, and the content security policy, permissions policy and HSTS each service sets | estate-dashboard |
| [`testlint`](testlint) | lints for the estate testing standards: a test named as a sentence, and a table of functions that runs each case as a named `t.Run`; run as `go tool testlint ./...` | identity |

## Use

```bash
go get github.com/JorisJonkers-dev/go-commons@vX.Y.Z
```

Pin an exact tag; see [VERSIONING.md](VERSIONING.md). Pre-1.0, a minor release may break an API.

The test lints are a tool, not a library:

```bash
go get -tool github.com/JorisJonkers-dev/go-commons/cmd/testlint@vX.Y.Z
go tool testlint ./...                    # and -tags integration ./... for integration tests
```

## Work on it

`mise install`, then `task check`, which is everything CI runs: lint, the tests with the race
detector and a 95% coverage gate, and a secret scan.
