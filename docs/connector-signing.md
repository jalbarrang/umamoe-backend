# Connector auth and signing: design proposal

Branch: `feature/connector-pairing`. Nothing implemented yet — this is the design, the decision, and the
verification order, so the work can be argued about before it is written.

## Decision up front: the JWT is the default, pairing is opt-in

Almost nobody will create an API key, and they should not have to. The connector authenticates with the uma.moe JWT
the user already has, exactly like the web app.

That changes what signing is for. **A JWT over TLS already proves who sent a batch and that it arrived unaltered.**
So the ranking of the fields is:

| field | still needed? | why |
|---|---|---|
| JWT (`Authorization: Bearer`) | yes | identity, and the only thing that authorises an upload |
| `hash` per record | yes | dedupe, change detection, upload idempotency |
| `hmac` per record | **only if** records are verified later by someone who was not on the connection, or pass through an intermediary that is not trusted |

If the answer to "who verifies these records, and where" is "our backend, at ingest, over TLS", then HMAC adds
ceremony and no guarantee. Path 1 below is therefore the default.

## The JWT cannot be the signing key

Three reasons, all disqualifying:

1. It is signed with a **global** secret — every user's token verifies under the same key, so it is not per-user
   material.
2. It **expires in 7 days** (`auth.rs: create_token`), so signatures would stop verifying mid-week.
3. It is a **bearer credential**. Putting it in a config file hands out full account access — strictly worse than the
   tampering it was meant to prevent. (`sid` was redacted in the connector for the same reason.)

A signing key has to be issued by the server, be per-user, and outlive the token. That is what pairing is for — and
it is optional.

## Path 1 (default): JWT auth, no HMAC

```
POST /api/connector/upload      Authorization: Bearer <jwt>
{ "records": [ { "class": "...", "hash": "...", "at": ..., "data": {...} } ] }
```

- No schema change, no new credential, no pairing UX.
- Server: resolve user from the JWT (`middleware/auth.rs` already does this for both JWT and `X-API-Key`), store the
  records against that user, dedupe on `hash`.
- Replay is not a concern in the same way: a duplicate `hash` is simply a duplicate row.

What this gives up: records cannot be verified by a third party later, and anything that touches them outside the TLS
connection (a queue, an export, a partner integration) is unverified data.

## Path 2 (opt-in): pair once, sign batches

Only for users or deployments that need records verifiable at rest, or that relay them through something untrusted.

`POST /api/connector/pair` — **authorised by the JWT**, and the JWT is not the key it returns:

```
POST /api/connector/pair        Authorization: Bearer <jwt>
{ "label": "desktop" }
→ { "key": "<base64, shown once>", "key_prefix": "umac_ab..." }
```

Server generates 32 random bytes (`rand`), stores `sha256(raw)` — the same hashing `api_keys` already uses — and
returns the raw value once. The connector stores it with Windows DPAPI, not in a config file.

```sql
CREATE TABLE connector_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash     VARCHAR(64) NOT NULL UNIQUE,   -- sha256(raw)
    key_prefix   VARCHAR(8) NOT NULL,           -- for display
    label        VARCHAR(255),
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);
```

Signing key = `sha256(raw)` on the client, `key_hash` on the server. As with API keys, a database dump yields
forgery ability but not account takeover, because bearer auth hashes what is presented and compares. If that is not
acceptable, store `HMAC(jwt_secret, sha256(raw))` and apply the same wrap on both sides.

**Pairing UX: loopback redirect (RFC 8252), not copy-paste.** The connector opens the uma.moe login in the browser,
the backend redirects to `http://127.0.0.1:<port>/connector/callback?code=...`, and the connector exchanges the code
for a key. The mod already hosts an `HttpListener` for ApiTap, so this needs no new machinery, and the token never
passes through the desktop app at all. Device-code is the fallback if a local listener is blocked.

**The signing contract** is already fixed and cross-checked against an independent implementation
(`mods/src/ApiTap/README.md`):

```
v1|viewerId|kind|class|hash|seq|atUnix|nonce
hmac = HMAC-SHA256(key, canonical)          # lowercase hex
```

Known-good fixture (key `00112233…eeff`, nonce `nonce-42`) — write the verifier against this first:

```
v1|280420104509|response|Gallop.TrophyData|9f2c1ab73de0a41c5e8b7d6f2a90c314|128|1792625680|nonce-42
8cad2ca0d2241283c6bc8ad68ae7cc3f3c3cb6f685ba094fafb1584096dd790c
```

Sign **a batch**, not every record: one HMAC over one canonical string carrying the batch digest is the same
guarantee for a fraction of the cost.

## Verification order (Path 2), cheapest rejection first

1. **Auth** — JWT, or `X-API-Key`, or the connector key itself.
2. **Timestamp window** — `|now - atUnix| <= 300s`.
3. **Nonce unused** — Redis claim, delete on use (`redis_store.rs` has `set_string_ex`). Without this, a valid batch
   can be replayed verbatim and the HMAC still verifies.
4. **HMAC** — recompute, constant-time compare.
5. **Seq monotonic per user** — Redis high-water mark. Catches truncation and reordering.
6. **Plausibility** — master-data ids exist, counters only move forward, totals reconcile.

Steps 1–5 prove *the key holder sent this*. Step 6 is the only one that says anything about whether the *game* did. A
patched client signs its own fabrications with its own valid key, so step 6 is not optional in either path — and
`cheat_analysis.rs` shows the project already treats plausibility as its own problem, so this extends existing work
rather than starting a new one.

## The API-key path (exception, not default)

For users who *do* create an API key, no pairing is needed: `api_keys.key_hash = sha256(raw)` is already a shared
secret both sides can compute, so the key doubles as the signing key. Worth supporting because it costs nothing, but
it must not be the only way in — that would put a setup step in front of every user.

## Dependencies

Already in `Cargo.toml`: `hmac 0.12`, `sha2 0.10`, `hex 0.4`, `rand 0.8`, `uuid 1`, `jsonwebtoken 9`. Nothing new is
needed for either path.

## Open questions

1. **Path 1 only, or Path 1 + Path 2?** Path 1 is a day's work and no migration. Path 2 adds the table, pairing, and
   nonce handling.
2. **What is the upload unit?** A session's records, or continuous streaming? Decides whether `seq` is per record or
   per batch.
3. **Retention.** These payloads contain other players' ids and names (Team Stadium opponent lists). What is stored,
   and for how long, wants deciding before the first upload lands — `sid` is already redacted at the source.
