# Contributing to Citadel

Thanks for helping out. Please read this before opening a pull request.

## Licence and CLA

Citadel is licensed under the [Functional Source License 1.1, Apache 2.0 Future
License](LICENSE) (FSL-1.1-ALv2). To keep the licence ours to manage, every
contributor must sign the [Contributor License Agreement](CLA.md) before a pull
request can be merged.

You only sign once. When you open your first pull request, the CLA bot posts a
comment. Reply with:

> I have read the CLA Document and I hereby sign the CLA

The signature is recorded against your GitHub account, and the check turns
green. If you contribute on behalf of an employer, make sure you are allowed to
before signing.

## Before you open a pull request

- Read [docs/design.md](docs/design.md) §1 (invariants) and §9 (network model)
  if your change crosses the sandbox boundary, and §14 if it touches ownership,
  grants or the audit record.
- Run the fast checks locally:

  ```sh
  make vet lint licenses test
  ```

  `make check` runs the full suite, which needs the development VM
  ([hack/vm/README.md](hack/vm/README.md)).
- Adding a Go dependency? It must use a permissive licence (Apache-2.0, MIT,
  BSD or ISC), which `make licenses` enforces. List it in [NOTICE](NOTICE).
