# LogProof JSON schema 1

All fields below are required with their exact spelling. A JSON null is invalid. Arrays may be empty unless a count constraint says otherwise. Integers stored in strings are canonical unsigned decimal values from 0 through 18446744073709551615. Hex strings are lowercase. Base64 uses the canonical padded standard alphabet.

## Trust input

```json
{"schema":1,"origin":"example.invalid/release-log","publicKey":"<32-byte Ed25519 key as 64 hex digits>"}
```

The origin is a byte string of 1–128 printable ASCII characters from ! through ~. It is compared exactly. Trust comes from the caller-provided key and saved checkpoint.

## Checkpoint and signed bytes

```json
{"origin":"example.invalid/release-log","size":"33","root":"<32-byte SHA-256 root as 64 hex digits>","issued":"1020","signature":"<64-byte Ed25519 signature as padded base64>"}
```

The signed message is the following UTF-8 byte sequence, with LF line endings and a final LF. Each placeholder is replaced with the exact canonical field value.

```text
RUDY LOGPROOF CHECKPOINT 1
<origin>
<size>
<root>
<issued>
```

The signature field is excluded from the message. Issued time is whole Unix seconds. An empty tree must use SHA-256 of the empty byte string. The envelope uses standard Ed25519 with the LogProof domain and field layout.

## Bundle

```json
{
  "schema":1,
  "checkpoints":["<checkpoint objects in order>"],
  "consistency":["<arrays of lowercase hex nodes, one per adjacent checkpoint pair>"],
  "inclusions":[
    {"checkpoint":0,"index":"0","leaf":"<base64 bytes>","proof":["<lowercase hex nodes>"]}
  ]
}
```

The strings shown inside checkpoints and consistency above are explanatory placeholders. Actual entries are objects and arrays respectively. See the committed fixtures for complete valid documents.

Checkpoint and inclusion counts are JSON integer tokens. The inclusion checkpoint is a zero-based index into the checkpoints array. Proof nodes run from the leaf/subtree toward the root.

A transition from size zero requires an empty proof and the canonical empty old root. Equal tree sizes require an empty proof and equal roots. Shrinking sizes fail verification. For growing sizes, the unique minimal consistency path must reconstruct both roots.

The first checkpoint must match the caller's anchor object in all fields. The tool authenticates the anchor as well as every bundle checkpoint. A correctly signed checkpoint from a different origin fails under the pinned origin.

## Merkle API

The Go package `merkle` exposes `Leaf`, `Node`, `Empty`, `Root`, `Inclusion`, `Consistency`, `VerifyInclusion`, and `VerifyConsistency`. Verifiers consume the entire proof. Generator functions operate on already-hashed leaves. Callers of the public package must authenticate roots through their own trust mechanism.

The `audit` package adds the bounded JSON schema and authenticated checkpoint policy. The command uses both packages. Its input schema contains public verification material only.
