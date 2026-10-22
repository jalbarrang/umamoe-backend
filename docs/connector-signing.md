# Connector signing: design proposal

Branch: `feature/connector-pairing`. Nothing implemented yet — this is the design, the schema decision, and the
verification order, so the work can be argued about before it is written.

## What the connector sends

The ApiTap mod can HMAC-sign every record. The contract is fixed already and has a cross-checked test vector
(`mods/src/ApiTap/README.md` in honse-mods):

```
v1|viewerId|kind|class|hash|seq|atUnix|nonce
hmac = HMAC-SHA256(key, canonical)   # lowercase hex
```

`hash` is 16 bytes of SHA-256 over the payload, so the stamp is bound to the data. `seq`/`atUnix` stop reordering
and re-dating. `nonce` stops a whole valid batch being replayed. `v1` lets the layout change later.

Known-good fixture (key `00112233…eeff`, nonce `nonce-42`):

```
v1|280420104509|response|Gallop.TrophyData|9f2c1ab73de0a41c5e8b7d6f2a90c314|128|1792625680|nonce-42
8cad2ca0d2241283c6bc8ad68ae7cc3f3c3cb6f685ba094fafb1584096dd790c
```

Write the verifier against that before wiring anything to a real client — "the signature never verifies" is nearly
always two sides signing slightly different bytes.

## Key question: which secret signs?

### Option A — derive it from the existing API key (recommended, no migration)

`api_keys` already stores `key_hash = sha256(raw_key)`, and the raw key exists only on the user's machine. So the
hash **is** a shared secret both sides can compute:

```
client: signing_key = sha256(raw_api_key)
server: signing_key = api_keys.key_hash          (already stored)
```

Consequences:

- **No schema change, no new credential.** Pairing is not strictly needed: an API key already means "this user, this
  machine, revocable".
- Revocation, attribution and rate-limiting are the ones the API key already has.
- A database leak yields forgery ability (an attacker can compute valid HMACs) but **not** account takeover, because
  `X-API-Key` auth hashes what is presented and compares — presenting `key_hash` hashes to something else.
- Rotation is per API key, which is the granularity users already understand.

If that leak model is unacceptable, wrap it: store `HMAC(jwt_secret, key_hash)` and derive with the same wrap on both
sides. Cheap, and it keeps signing keys out of a plain dump.

### Option B — a dedicated `connector_keys` table

Worth it only if signing must be revocable **separately** from API access, or if per-device labels and last-used
timestamps are wanted for a support workflow.

```sql
CREATE TABLE connector_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash     VARCHAR(64) NOT NULL UNIQUE,   -- sha256(raw) as with api_keys
    label        VARCHAR(255),
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);
```

`POST /api/connector/pair` then returns the raw key exactly once, and the client stores it with DPAPI.

## Endpoints, either way

| route | auth | purpose |
|---|---|---|
| `POST /api/connector/nonce` | API key / JWT | one-time nonce, TTL-bounded |
| `POST /api/connector/upload` | API key / JWT | records + hmac + nonce |
| `DELETE /api/connector/keys/:id` | JWT | revoke (Option B only) |

Nonces fit the existing Redis store (`redis_store.rs`, `set_string_ex`, `increment_with_expiry`): key
`connector:nonce:<user_id>:<nonce>` with a short TTL, deleted on first use. Without a store for single use, a signed
batch can be replayed verbatim and the HMAC still verifies.

## Verification order (cheapest rejection first)

1. **Auth** — resolve user from API key or JWT (`middleware/auth.rs` already does both).
2. **Timestamp window** — `|now - atUnix| <= 300s`. Kills stale and future-dated batches.
3. **Nonce unused** — Redis claim, delete-on-use. Kills replay.
4. **HMAC** — recompute over the canonical string, constant-time compare.
5. **Seq monotonic per user** — Redis high-water mark. Kills truncation and reordering within a batch stream.
6. **Plausibility** — master-data ids exist, counters only move forward, totals reconcile.

Steps 1–5 prove *the key holder sent this*. Step 6 is the only one that says anything about whether the *game* did.
A patched client signs its own fabrications with its own valid key; `cheat_analysis.rs` shows the project already
treats plausibility as its own problem, so this is a natural extension of it rather than a new idea.

## Dependencies

Already in `Cargo.toml`: `hmac 0.12`, `sha2 0.10`, `hex 0.4`, `rand 0.8`, `uuid 1`, `jsonwebtoken 9`. Nothing new is
needed for any of this.

## Open questions

1. **Option A or B?** A is a day less work and no migration; B buys independent revocation.
2. **Batch or per-record HMAC?** One HMAC per batch over a digest of the record hashes is the same guarantee for a
   fraction of the cost. Per-record is simpler to reason about.
3. **What is the upload unit?** A session's worth of records, or continuous streaming? That decides whether `seq` is
   per record or per batch.
4. **Retention.** These payloads contain other players' ids and names (Team Stadium opponent lists). What gets stored,
   and for how long, needs deciding before the first upload lands — and `sid` is already redacted at the source.
