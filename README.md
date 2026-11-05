<p align="center"><img src="assets/banner.svg" alt="Rudy LogProof · authenticated Merkle log evidence" width="100%"></p>

<p align="center">
<a href="https://github.com/r4venrudy/rudy-logproof/actions/workflows/ci.yml"><img src="https://github.com/r4venrudy/rudy-logproof/actions/workflows/ci.yml/badge.svg" alt="Build and verify"></a>
<img src="https://img.shields.io/badge/Go-1.27-55e0b6?style=flat-square&amp;labelColor=101e2a" alt="Go">
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-55e0b6?style=flat-square&amp;labelColor=101e2a" alt="MIT"></a>
<a href="https://rudy.systems"><img src="https://img.shields.io/badge/RUDY-SYSTEMS-55e0b6?style=flat-square&amp;labelColor=101e2a" alt="Rudy Systems"></a>
</p>

**A signature authenticates a checkpoint. An inclusion proof binds an entry to it. A consistency proof connects that checkpoint to the history you saved earlier.**

Rudy LogProof verifies those three claims together for release evidence and other ordered records. Its Go core implements SHA-256 Merkle tree construction, inclusion and consistency proofs, Ed25519 checkpoint authentication, exact saved-anchor matching, and explicit freshness checks. It uses the Go standard library and runs offline.

## Verify the invented log

Download the [native preview](https://github.com/r4venrudy/rudy-logproof/releases), compare the archive's SHA-256 with its exact entry in `SHA256SUMS.txt`, then extract it.

```sh
bin/logproof verify --key examples/fixtures/trust.json --anchor examples/fixtures/anchor.json --at 1020 --max-age 10 examples/fixtures/bundle.json
```

On Windows use `bin\logproof.exe`. The included bundle has 14 signed checkpoints, 13 transitions, and 178 inclusion proofs. The final checkpoint commits to 33 invented leaves.

```json
{"schema":1,"verified":true,"code":"VERIFIED","checkpoints":14,"inclusions":178,"finalSize":"33","finalRoot":"107c695415e56af3aced500a9ab8cc92f05fd3c7b84ecd88d720605538a5ef97"}
```

The fixtures use a public deterministic test seed, an `example.invalid` origin, and invented data. Their key and timestamps are for this walkthrough. For a real audit, obtain the trusted public key and saved checkpoint through your trusted workflow. Set `--at` from a trusted clock and choose `--max-age` in seconds. Only the final checkpoint must satisfy the age limit. Every checkpoint must be no later than `--at`, and issue times cannot decrease.

## Construct proofs for your records

The input contains a schema version and an ordered array of canonical padded base64 strings. An empty string encodes an empty record. Bytes are hashed exactly as decoded.

```json
{"schema":1,"leaves":["cmVsZWFzZS1h","cmVsZWFzZS1i",""]}
```

```sh
bin/logproof root examples/fixtures/leaves.json
bin/logproof prove --index 17 examples/fixtures/leaves.json
bin/logproof consistency --old-size 16 examples/fixtures/leaves.json
```

All commands write JSON to standard output. Use shell redirection to save it. Proof generation produces unsigned data for a log producer. Checkpoint signatures must be created by the producer according to the documented envelope.

## What verification establishes

| Check | Evidence |
| --- | --- |
| Pinned origin and Ed25519 public key | Anchor and checkpoint signatures authenticate under the supplied key |
| Exact saved anchor | The bundle begins with every field of the caller's saved checkpoint |
| Consistency at each transition | The earlier tree remains the prefix of the later tree |
| Inclusion at a selected checkpoint | The submitted leaf hashes to the signed root at its claimed index |
| Explicit time policy | Issue times are ordered, none is from the future, and the final checkpoint is fresh enough |

Exit 0 means the requested operation succeeded. Verification returns 1 with a JSON diagnostic when authentication, anchoring, proof, or freshness fails. Exit 2 indicates malformed input, unsupported schema, limits, usage, or I/O failure. Reports include hashes and counts while omitting leaf payloads, public keys, signatures, and origin names.

A verified bundle with zero inclusions establishes the checkpoint transitions only. Each inclusion binds the supplied bytes to one checkpoint. The caller decides which records must be present.

## Build and validate

Use Go 1.27 or newer. Python 3.10 or newer runs the independent oracle and packaging scripts.

```sh
go test ./...
go vet ./...
go build -trimpath -o bin/logproof ./cmd/logproof
python3 tests/integration.py bin/logproof .
```

The native test matrix checks every leaf and every earlier size for trees of 0–80 entries, mutated proofs, full-width uint64 sizes including a 65-node consistency proof, signed checkpoint failures, and strict JSON behavior. The independent Python oracle constructs trees by pairing levels and verifies consistency iteratively. CI also runs Go's race detector and bounded parser/proof fuzzing on Linux.

The source example generator can regenerate the committed synthetic fixture set.

```sh
go run ./examples/demo examples/fixtures
```

## Format and analysis boundaries

The Merkle hashing and proof ordering follow the tree algorithms in RFC 6962 and RFC 9162. The supported checkpoint signature envelope is LogProof schema 1, as documented below. The Merkle primitives are reusable through the Go package.

The input budget is 32 MiB with at most 256 checkpoints, 10,000 inclusion statements, 1 MiB per decoded record, and 16 MiB total decoded leaf data. Inclusion paths have at most 64 nodes. Consistency paths may require 65 nodes across the full uint64 range. Local proof construction accepts up to 100,000 records within the same byte budget. JSON fields are exact, required, and unique. Unknown fields, null values, noncanonical encodings, and excess proof nodes are rejected.

A valid path authenticates the supplied view. Detecting a log that presents different signed views requires comparing or exchanging independently retained checkpoints. Remote-view collection, private-key custody, trust-key rotation, and anchor persistence belong to the caller.

[Schema and signing envelope](docs/FORMAT.md) · [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) · [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)
