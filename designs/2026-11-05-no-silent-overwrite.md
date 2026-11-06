# No silent overwrite, and many keys per vendor (WA-1124)

## Goal

No stored value is replaced without a warning and a second, explicit step. Each key of a vendor has its own place, so a new key never needs the old one's name. A person and an agent find the right key by vendor and purpose.

## What happened (2026-11-05)

An agent's explore `keep` wrote `CLOUDFLARE_API_TOKEN` twice: first the account id, then another project's token. The env file and the shared store took both. SSM kept the versions; `autobrowse env history` and `env restore` put the token back (v3 → v6).

## What is there

- `EnvStore.put(name, value)` replaces. SSM sends `Overwrite: true`. About 60 call sites in autobrowse write through it or a store built on it.
- The key vault (`keys.ts`) is already vendor → many keys: `site@account`, owner, purposes, status, history. `X_API_KEY` names are a projection of it; `env set X_API_KEY` is refused and points at the vault.
- A token with another name (`CLOUDFLARE_API_TOKEN`, `*_TOKEN`, `*_SECRET`) is outside the vault: one flat name, one value.
- Credentials keep each old state before a push (`history.ts`).

## Options

| Option | For | Against |
|---|---|---|
| A. The store refuses. `put` on a name that holds another value throws unless the caller says `replace` | One rule in one place: a new caller cannot forget it | Each caller that replaces on purpose (a re-mint, a projection) says so in code: about 15 sites |
| B. Guards at the surfaces (`env set`, explore `keep`) | Small. No publish | The next surface forgets. The store still replaces for anyone |
| C. Append only: no name is ever replaced; each value is a new label and a pointer names the current one | Nothing is lost, by construction | Every reader learns the pointer. A refreshed OAuth token makes a new label each hour |
| D. An owner per name: only the flow that minted a value may replace it | Re-mints need no change | A registry to keep. An agent's `keep` is a flow too, so the 11-05 write passes |

Priorities, in order:

1. No working key is lost or shadowed without a person's yes.
2. A machine re-mint (a token refresh) runs with no person.
3. One rule in one place.
4. Few changes for callers.

**Chosen: A, with the vault for every vendor key.** A meets 1 and 3. Re-mints own their name, so they say `replace`: 2 holds. C's gain (nothing replaced) comes from the vault where it matters: a second key of a vendor is a new address, never a put on the old one. B is how A looks at the surfaces, so the surfaces ship first on 0.13.0 and the store rule follows with the publish.

## Shape

### The store rule

- `put(name, value, { replace })`:
  - no value there: writes.
  - the same value there: writes (a new expiry).
  - another value there, `replace: true`: writes.
  - another value there, no `replace`: throws `WouldReplace { key, heldLength, where }`. No value in the error.
- The confirmation is a plain yes (William, 2026-11-05: "a double check confirm… confirm or deny"). The first plan made the caller quote a hash of the held value; he found that unclear.
- The cost of a plain yes: a caller can send it on the first try. So the surface asks the question, and the explore server takes a yes only for a question it asked in this session.
- The synced store asks both sides before it writes either. A shared store that does not answer is not asked; `share()` asks it later and leaves a refused name unshared until `share({ replace: true })`.
- SSM has no conditional put: two writers inside the same second can both pass. One operator; the 100 versions are the way back.
- Code that owns a name says `replace: true`: a token refresh, the projection's ring names, a credential push (it keeps history first), the vault's own rows. A grep for `replace: true` lists every place that replaces.
- `remove`: SSM's delete takes every version with it. The SSM store copies the last value to `removed/<name>` first; a copy that fails stops the remove.

### Two phases at the surfaces

Phase one writes nothing and asks: "this would replace NAME (held since …, n chars). Every reader of NAME gets the new value. Is that intended?" Phase two is the same command with the yes.

| Surface | Phase one | Phase two |
|---|---|---|
| `autobrowse env set NAME`, `env push` | exit 1, nothing written: each name, where it is held, since when, its length | the same command with `--confirm` |
| `env pull` | a file value the store held before is a rotation: it goes. One the store never held exists only in the file: exit 1, nothing written | `env pull … --confirm` |
| `env rm NAME` | exit 1: what would go | `env rm NAME --confirm` |
| explore `keep` | `{ok:false, kept:false, question, held:{env, length}}`; nothing written, nothing journaled | `{"cmd":"keep", …, "confirm":true}`, taken only after the question was asked in this session |
| `autobrowse agent` (headless) `keep` | "NOT KEPT": another name, or stop for a person | none: its `keep` has no `confirm` |
| compiled walk `keep` | stops for a person (`NeedsHuman`), nothing written | none in the walk: a person renames the step's env name or moves the held value |
| a new secret at a held vault address | the vault's `put` throws: the address, the held key's id | `creds key rotate` (keeps the old id in `previous`) |
| `creds key add` on a held label, or with `--env` on a held name | exit 1, nothing written: the label's id and length, each env name | the same command with `--confirm` |
| a flow or workflow that mints (`keeps`), `site setup` | stops before the first act with the question (`NeedsHuman`) | input or plan `replace: true`; `site setup … --confirm` |
| explore `keep` with `key` on a held label | refused: points to `creds key rotate` | none from explore |
| the projection on a key's `env` name | a value the key never had: `WouldReplace`, nothing written | `applyProjection(…, { replace: true })` |

### Many keys per vendor

- A key in the vault may name the env names it stands for: `env: ["CLOUDFLARE_API_TOKEN"]`. The projection writes them. Two keys of one owner that can be used never share an env name: `put` refuses, as it does for a purpose.
- A rotated key's old value under its env name is replaced with no question: the key's `previous` names it. An env name no key fills any more is left as it is.
- `env set` and `keep` refuse an env name a vault key fills, and print the vault command.
- explore `keep` takes `key: "cloudflare@pages-deploy"` with `env`: the value goes to the vault at a new address and fills that env name. `creds key add <vendor>@<label> --env <NAME>` does the same by hand.
- Reading: `creds key ls [vendor]` (address, purposes, env names, id, age; no secret). Code asks `keysFor(vendor, purpose)`. A shell asks for the env name.
- The Cloudflare tokens (six; the seventh name is the account id) move in as `cloudflare@<label>`, each with its env name. A copy, not a move: nothing is removed. **Done 2026-11-05 (WA-1129, credvault 0.14.1):** `cloudflare@api`, `@access`, `@tunnel`, `@tunnel-admin`, `@wren-saas`, `@wren-workers`. No purposes, so each fills its own name only: no `CLOUDFLARE_API_KEY*`, no `NUM_CLOUDFLARE`. No env name or date changed. A process on credvault before 0.14.1 that projects `cloudflare` would add those pool names: deploy it before it changes a Cloudflare key.

## Order

1. autobrowse, on credvault 0.13.0: the two phases at each surface in the table above but `creds key add` (a check before the put). **Built 2026-11-05.** Still open until step 2: code that calls a store's `put` itself (the generated workflows `google-cloud-oauth-client`, `google-cloud-project`, `langfuse-project-keys`, `bootstrap`). A token refresh replaces on purpose.
2. credvault 0.14.0: `replace` and `WouldReplace` in the store, `env` on a key. **Built 2026-11-05.**
3. autobrowse on 0.14.0: the surfaces catch `WouldReplace` and ask; the callers that replace on purpose say `replace: true`; `keep` with `key`; the Cloudflare tokens into the vault (a credential change: William's yes).

## Decision log

- 2026-11-05: Any overwrite gets a warning and a confirmation, two phases, across credvault (William).
- 2026-11-05: A replaced value must stay stored and usable; many keys per type (William: "a dictionary points to a list").
- 2026-11-05: The rule lives in the store, not at each caller (option A; William: "I guess A makes sense").
- 2026-11-05: The confirmation is a plain yes, not a quoted hash (William: "just like a double check confirm… Is this an intended consequence? And then it's like, confirm or deny").
- 2026-11-05: Explore takes a yes only for a question it asked in this session (my call): a yes sent on the first try is no second phase.
- 2026-11-05: A vault secret change must name the old id in `previous` (my call): the rule needs no flag, and a rotation already records it.
- 2026-11-05: Many keys per vendor through the vault (William: "the key vault is already like dictionary to list. Yeah, that's fine").
- 2026-11-05: `env rm` gets two phases too (my call): SSM's delete removes every version, so a remove loses more than a replace.
- 2026-11-05: `env pull` lets a rotation through and stops only for a file value the store never held (my call): a second machine must get a new key with no person, and a value only in a file has no history.
- 2026-11-05: A walk has no replace of its own (my call): a walk runs unattended, and a replace needs a person.
- 2026-11-05: The vault is the list. No second structure: a token with another name joins it through `env` on the key.
- 2026-11-05: A flow that mints a value names it in `keeps`, and the runner asks before the first act (my call): a refusal after the mint loses a value the site shows once. The yes is `replace: true` in the input or the plan.
- 2026-11-05: A flow that reads a value the site already has names none (my call): the store refuses late, the runner turns `WouldReplace` into a question for a person, and nothing is lost.
- 2026-11-05: Code that owns a name replaces with no question (my call): a rolled refresh token, an account's own consent names, bootstrap after a failed API check, values derived from a key pair, `AUTOBROWSE_ACCOUNTS`, `env restore` (the command names the version), a renewal (the lapse is the reason).
- 2026-11-05: From explore, a label that holds another key has no yes path (my call): a new value at an address is a rotation, and `creds key rotate` is a person's command. `creds key add` on a held label asks first and takes `--confirm`.
- 2026-11-05: An env name a vault key fills is not set, removed or kept by hand (my call): a hand-set value would split env from vault.
- 2026-11-05: The Cloudflare copy waits (my call, WA-1129): a vault key with its own env name still joins the vendor ring, and scoped tokens are not one pool. Options there; nothing was copied.
- 2026-11-05: A key with its own env name and no purpose is in no ring (William: "I agree with A", WA-1129). `inRing` decides for `keysFor` and the projection; a purpose puts the key back. Rejected: a `ring: false` field per key (one more field to set right), tokens left flat (no labels, ids or audit), copy as is (pool names for scoped tokens). credvault 0.14.1.
