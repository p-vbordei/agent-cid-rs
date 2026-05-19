# agent-cid — v1.0 specification

**Status:** 1.0 — 2026-04-24. Reference implementation: this repo (`src/`). Conformance vectors: [`conformance/`](./conformance/).

## Abstract

`agent-cid` defines a minimal content-addressed manifest format for artifacts exchanged between AI agents. It binds a CID to an agent-specific metadata envelope — producer DID, schema URI, timestamps, signing chain, optional versioning and retention hints.

## 1. Terminology

- **CID** — Content Identifier (CIDv1, multihash sha-256). See [multiformats](https://github.com/multiformats/cid).
- **Manifest** — the small JSON/CBOR envelope that wraps a CID with agent-specific metadata.
- **Artifact** — the byte-blob whose CID is in the manifest.
- **Producer** — the agent that created the artifact, identified by DID.

## 2. Manifest schema

```
{
  "v": "agent-cid/1",
  "cid": "bafybeig...",                  // CIDv1, multihash sha-256
  "size": <uint>,                        // bytes
  "media_type": "application/...",
  "schema_uri": "https://...",           // URI describing the body schema
  "producer": "did:key:..." | "did:web:...",
  "created_at": "<RFC 3339>",
  "parent_cid?": "bafy...",              // previous version of this artifact
  "retention?": {
    "stale_after?": "<RFC 3339>",
    "expires_at?": "<RFC 3339>"
  },
  "sigs": [
    {
      "signer_did": "did:...",
      "alg": "ed25519",
      "sig": "<base64>"
    }
  ]
}
```

Signatures cover the canonical encoding of the manifest **with `sigs` removed**.

Canonical encoding: JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)). Deterministic CBOR representation is normatively equivalent and MAY be used for size-sensitive transports.

## 3. Operations

### 3.1 Build

```
build(bytes: Bytes, opts: {
  producer_did,
  schema_uri,
  media_type,
  parent_cid?,
  retention?,
  signers: [{ did, sign_fn }]
}) -> Manifest
```

Computes the CID over `bytes`, fills in the manifest, and collects signatures from each signer in order.

### 3.2 Verify

```
verify(manifest: Manifest, bytes: Bytes, did_resolver) -> { ok, errors[] }
```

Verification MUST check:

1. `cid` matches `multihash(sha256, bytes)`.
2. `size == len(bytes)`.
3. Every signature in `sigs` verifies under its `signer_did`'s current (or historical, at `created_at`) verification method.
4. Retention hints are not hard-expired (`expires_at > now`) unless verifier opts to ignore.

### 3.3 Resolve

```
resolve(manifest) -> { cid, producer, parent? }
```

Pure accessor; returns structured pointers. Does not fetch bytes.

## 4. Versioning

A new artifact version points at its predecessor via `parent_cid`. Verifiers MAY traverse the chain to reconstruct history. Revoked or superseded versions remain cryptographically valid — revocation is out-of-band.

## 5. Retention

`retention.stale_after` is advisory ("prefer fresher"). `retention.expires_at` is normative ("reject after this"). Consumers SHOULD honor both. Absence of retention = no advisory staleness.

## 6. Security considerations

- **CID is the anchor.** Mutating bytes breaks the CID; mutating the manifest breaks the signatures.
- **Signer key rotation** follows `agent-id` rules; verifiers MUST resolve signer keys at `created_at`, not "now".
- **Parent-chain trust** is transitive only if every manifest in the chain verifies. A revoked middle signer breaks the chain; policy on how to handle revocation is left to the application.
- **Size limits** are not normative; transports MAY enforce their own.

For `did:web` (added in v0.2):

- **HTTPS-only.** Verifiers MUST reject `http://` URLs derived from `did:web:`.
- **Response size cap.** Verifiers SHOULD enforce a maximum DID document size (default 64 KiB) to prevent resource exhaustion.
- **Fetch timeout.** Verifiers SHOULD enforce a fetch timeout (default 5 s).
- **Cache freshness.** A pubkey cache MAY be used; default TTL is 5 minutes. Verifiers MUST NOT cache the verification result, only the pubkey. Cache scope SHOULD be per-resolver instance, so swapping resolvers (e.g., a test stub vs. the production fetcher) does not return stale entries. Callers needing strict freshness or single-shot resolution pass `resolverCache: false`.
- **Historical key resolution at `created_at`** is NOT YET supported in v0.2 (current key only). This will land in v0.3 alongside `agent-id`'s rotation history protocol.

## 7. Conformance

A conforming implementation MUST:

- (C1) Build → verify roundtrip succeeds on a 1 KiB body.
- (C2) Mutating a single byte of the body causes `verify` to fail (CID mismatch).
- (C3) Parent-chain traversal over 3 versions succeeds; a revoked middle signer causes traversal to flag the broken link.
- (C4) Canonical encoding across implementations is byte-identical.

Test vectors live in `conformance/`.

## 8. References

- [CIDv1 / multiformats](https://github.com/multiformats/cid)
- [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [`agent-id` spec](../agent-id/SPEC.md)
