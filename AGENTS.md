# Agents

Guidance for any coding agent working in this repository.

The estate-wide conventions (labels, traps) are in the [estate contract](https://github.com/JorisJonkers-dev/workspace/blob/main/CLAUDE.md); read it before non-trivial changes. There is no CLAUDE.md here.

This repository holds Go packages shared by several estate services (`identity`, `secure`, `testlint`). A package lands here only when a consumer migrates to it. See `README.md` and `VERSIONING.md`.

## Build and test

- `task` lists the targets, defined in `Taskfile.yml`.
- `task check` runs lint, test and the secrets scan, as CI does.
- `task test` runs `go test -race` over all packages.
- `task lint` runs `go mod verify`, golangci-lint and actionlint.
- `task fix` applies golangci-lint fixes.
