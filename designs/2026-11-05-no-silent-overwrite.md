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
| A. The store refuses. `put` on a name that holds another value throws unless the caller cites the mark of the value it replaces | One rule in one place: a new caller cannot forget it. Phase two must quote what phase one showed | Each caller that replaces on purpose (a re-mint, a projection) says so in code: about 15 sites |
| B. Guards at the surfaces (`env set`, explore `keep`) | Small. No publish | The next surface forgets. The store still replaces for anyone |
| C. Append only: no name is ever replaced; each value is a new label and a pointer names the current one | Nothing is lost, by construction | Every reader learns the pointer. A refreshed OAuth token makes a new label each hour |
| D. An owner per name: only the flow that minted a value may replace it | Re-mints need no change | A registry to keep. An agent's `keep` is a flow too, so the 11-05 write passes |

Priorities, in order:

1. No working key is lost or shadowed without a person's yes.
2. A machine re-mint (a token refresh) runs with no person.
3. One rule in one place.
4. Few changes for callers.

**Chosen: A, with the vault for every vendor key.** A meets 1 and 3. Re-mints hold the old value, so they cite its mark: 2 holds. C's gain (nothing replaced) comes from the vault where it matters: a second key of a vendor is a new address, never a put on the old one. B is how A looks at the surfaces, so the surfaces ship first on 0.13.0 and the store rule follows with the publish.

## Shape

### The store rule

- `markOf(value)`: sha256, 8 hex. Safe to print. The same mark `env history` shows.
- `put(name, value, { over })`:
  - no value there: writes.
  - the same value there: writes nothing but a changed expiry.
  - another value there, `over` equals its mark: writes.
  - another value there, no `over` or a wrong one: throws `WouldReplace { name, mark, version, updatedAt }`. No value in the error.
- The synced store compares against what `get` answers (this machine, else the shared store) before either write.
- SSM has no conditional put: two writers inside the same second can both pass. One operator; the 100 versions are the way back.
- Code that owns a name cites the mark of the value it read: a token refresh, `applyProjection`, a credential push, a key's status change. A grep for `over:` lists every place that replaces.
- `remove(name, { over })` follows the same rule. SSM's delete takes every version with it: there is no way back. So the SSM store first copies the value to `removed/<name>`, then deletes.

### Two phases at the surfaces

| Surface | Phase one | Phase two |
|---|---|---|
| `autobrowse env set NAME` | exit 1, nothing written: the name, where it is held (the store, the env file), its mark and length; the rule; the line to replace | `env set NAME --replace <marks>` |
| `env push` | exit 1, none of its names written: each name that holds another value in the store | `env push … --replace <marks>` |
| `env pull` | a file value the store held before is a rotation: it goes. One the store never held exists only in the file: exit 1, nothing written | `env pull … --replace <marks>` |
| `env rm NAME` | exit 1: the remove deletes every version | `env rm NAME --confirm <mark>` |
| explore `keep` | `{ok:false, kept:false, held:{env, mark, length}, warning}`; nothing written, nothing journaled. The warning: keep both under another name; replace only when the person said so in this conversation, or this session minted the held value | `{"cmd":"keep", …, "replace":"<mark>"}` |
| `autobrowse agent` (headless) `keep` | "NOT KEPT": another name, or stop for a person | none: its `keep` has no `replace` |
| compiled walk `keep` | stops for a person (`NeedsHuman`), nothing written | none in the walk: a person renames the step's env name or moves the held value |
| `creds key add vendor@label` on a live address | exit 1: the address, the key's id and age | `creds key rotate` (keeps the old id in `previous`) |

### Many keys per vendor

- A key in the vault may name the env names it stands for: `env: ["CLOUDFLARE_API_TOKEN"]`. The projection writes them. Two keys of one owner that can be used never share an env name: `put` refuses, as it does for a purpose.
- `env set` and `keep` refuse a token-shaped name (`*_TOKEN`, `*_SECRET`, `*_KEY`) of a vendor that has keys in the vault, and print the vault command.
- explore `keep` takes `key: "cloudflare@pages-deploy"` with `purposes` and `env`: the value goes to the vault at a new address.
- Reading: `creds key ls [vendor]` (address, purposes, env names, id, age; no secret). Code asks `keysFor(vendor, purpose)`. A shell asks for the env name.
- The seven Cloudflare tokens move in as `cloudflare@<label>`, each with its purpose and its env name. The flat names stay as the projection, so no reader changes. A copy, not a move: nothing is removed.

## Order

1. autobrowse, on credvault 0.13.0: the two phases at each surface in the table above but `creds key add` (a check before the put). **Built 2026-11-05.** Still open until step 2: code that calls a store's `put` itself (the generated workflows `google-cloud-oauth-client`, `google-cloud-project`, `langfuse-project-keys`, `bootstrap`). A token refresh replaces on purpose.
2. credvault 0.14.0: `over` and `WouldReplace` in the store, `env` on a key. Publish waits for William's yes.
3. autobrowse on 0.14.0: the callers that replace on purpose cite `over`; `keep` with `key`; the Cloudflare tokens into the vault (a credential change: William's yes).

## Decision log

- 2026-11-05: Any overwrite gets a warning and a confirmation, two phases, across credvault (William).
- 2026-11-05: A replaced value must stay stored and usable; many keys per type (William: "a dictionary points to a list").
- 2026-11-05: The rule lives in the store, not at each caller (my recommendation; William to confirm before the publish).
- 2026-11-05: `env rm` gets two phases too (my call): SSM's delete removes every version, so a remove loses more than a replace.
- 2026-11-05: `env pull` lets a rotation through and stops only for a file value the store never held (my call): a second machine must get a new key with no person, and a value only in a file has no history.
- 2026-11-05: A walk has no replace of its own (my call): a walk runs unattended, and a replace needs a person.
- 2026-11-05: The vault is the list. No second structure: a token with another name joins it through `env` on the key.
