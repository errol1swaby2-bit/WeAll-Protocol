# PR #93 A01 — Public-lobby route identity: provisional registry repair

**Source head before change:** `a301bd453342ceff857f508af171438bba0e1dd7`
**Status:** Stable-ID registration only; V2 semantic review **NOT approved**, Genesis/public beta **NO-GO**.

The production route in `src/weall/api/routes_public_parts/content.py::public_lobby_comments` is `GET /v1/public-lobby/comments`. It reads a synthetic `public-lobby:` thread from public content state, checks visible comments, bounds page size to 50 and uses a deterministic cursor. The browser is not the source of content authority.

The V2 route scanner constructs the canonical identity `GET /v1/public-lobby/comments|src/weall/api/routes_public_parts/content.py|public_lobby_comments` and previously found no matching active registry row. The additive registry entry is `ROUTE-63E26182B51EAFCB` (SHA-256 prefix over the canonical identity). No historical row or tombstone is intentionally changed.

The new structural regression checks the exact identity, uniqueness, handler-to-route mapping and the presence of visible-comment/cursor logic. These tests do **not** establish end-to-end privacy, abuse resistance, or independent constitutional authority.

## Explicit unfinished gates

- V2 route semantic-review inventory and digest remain subject to named reviewer adjudication; **do not invent or auto-accept a review record** for this addition.
- Regenerate derived V2 route artifacts **only after** the route's source-bound behavior has received proper review alongside the existing outstanding transaction semantic contracts.
- Execute the strict compiler, complete backend/regression and reviewer gates on the exact resulting head. Expected failures must be retained as blockers, not patched around.
- No activation, seed-registry change, validator grant, PoH advancement, economics or public-testnet authorization is part of this change.
