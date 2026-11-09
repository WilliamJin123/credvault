# credvault

Keep the credentials an automation signs in with. Sealed at rest, shared through AWS SSM, every use audited, expiries watched.

No browser, no UI. The tool that signs in (a browser agent, a worker) reads from it. The tool that mints tokens writes to it.

```sh
npm install credvault
```

## What is in it

| Piece | What it does |
| --- | --- |
| `fileCredentials(path, cipher)` | Logins by site name (`github`, `google@ops`). A 0600 JSON file, sealed with AES-256-GCM. |
| `roles` on a credential | What the account is for on its site (`main`, `alt`), `ROLE_NAME` words. Travels with the login like any field; which role names which account is the app's rule. |
| `details` on a credential | Fixed facts a site asks for besides the login (`memberNumber`, `deliveryPostal`, `warehouse`), by camelCase name (`DETAIL_NAME`). Sealed, pushed, kept in history and pulled like any field. A login field's name (`RESERVED_DETAILS`) is refused. |
| `keychainKey({ service })` | The seal key, kept in the macOS Keychain. Made on first use. |
| `envCredentials(env, { prefix })` | The same logins read from env, for containers. Read-only. |
| `pushCredentials` / `pullCredentials` | Move logins between a laptop and the shared store: every field, passkeys and recovery codes as JSON. Canaries stay put. |
| `syncedCredentials` | The shared store is the truth, the local file the offline copy: a read checks the listing (no value read) and reads the values only when the site changed; pass `versions: versionsFile(path)` so other processes on the machine trust the copy too. A store with no change times is re-read every 60s. 3s timeout; writes land in both. No pull chore. |
| `ssmCredentialHistory(ssm, "/app/config/history")` | Every state a credential has had, one SSM parameter per site, a version per change (SSM keeps 100). Pass it as `history` to a push or `syncedCredentials`: a push keeps what the store held, then what it writes. It never deletes. `versions` names the fields that changed, never values. |
| `ssmEnvStore(ssm, "/app/config")` | Named values (API keys, tokens), one SSM SecureString each. Each value is decrypted once per version per process (every read is a KMS request, billed past 20k a month). |
| `envFileStore("~/.myapp/.env")` | The same, in a local 0600 `.env`. Expiry is a comment above the line. |
| `syncedEnvStore(local, shared)` | A machine's `.env` in front of the shared store: every put lands in both (local first, so a mint is never lost; a refused shared write still throws), reads prefer the local copy. A token minted on a laptop is on every machine. A refused shared write is remembered (`unshared`, `unsharedFile(path)`: names only), and the next put or `share()` sends it. |
| `put(name, value, { expiresAt })` + `expiring(list, ms)` | Record when a token stops working. List what lapses soon, without decrypting anything. |
| `put(name, value, { replace })`, `WouldReplace` | A put on a name that holds another value writes nothing and throws `WouldReplace` (the name, the held value's length, where; never a value). `replace: true` is the confirmation: code that owns the name sets it, a surface sets it after a person said yes. The same value again is no replace. `remove` on SSM copies the last value to `removed/NAME` first: SSM's delete takes every version. |
| `fileAudit(path)` | Where each secret went, one hash-chained line per use. `verifyChain` finds any edit. |
| `canaryStore(store)` | Reading a tripwire credential records it, tells a person, and throws. |
| `totp(seed)` | The current code from a TOTP seed. `findTotpSecret(pageText)` finds the seed on an enrollment page. |
| `newPassword()` | 24 characters, every class, no look-alikes. |
| `ownerCredentials({ roleArn, owner, region })` | One app, many owners: an AWS session tagged `owner=<owner>` from one shared role, renewed before it ends. `ownerSsmClient` wraps it; `ownerPath("/myapp", "acme")` = `/myapp/owners/acme`. |
| `apiKeySchema`, `ApiKey` | An API key as a credential: vendor (`site`), label (`account`), `owner`, `secret`, `purposes`, `status` (`live`, `spent` until a date, `revoked`), `via`, `vendorId`, `cap`, `previous`. The address is `site@account` (`keyAddress`, `parseKeyAddress`). No use count is stored: the audit has it. |
| `env` on a key | Env names a key fills besides its vendor's ring names (`env: ["CLOUDFLARE_API_TOKEN"]`). The projection writes them. One env name, one key per owner. A key with env names and no purpose is in no ring (`inRing`): it fills its own names only, so scoped tokens of one vendor are not a pool. A purpose puts it back. A new secret at a held address is refused unless `previous` names the old id: a second key takes its own label. |
| `keyId(secret)`, `keyInfo(key)`, `liveAt(key, now)` | `keyId` is 12 hex characters of the secret's sha256: it names a key in a log. `keyInfo` is a key without its secret, with `address` and `id`; every listing returns that. `liveAt` is true for `live`, and for `spent` once `spentUntil` has passed. |
| `envKeys(store)`, `memoryKeys(init?)` | Keys in an `EnvStore`, one row per key (the key as JSON, named `keyRowName(address)`: `exa@env-1` is `EXA__ENV_1`). Point the store at its own SSM path: SSM keeps 100 versions of each row, which is the key's history. `put` refuses a purpose another unrevoked key of the same vendor and owner holds. `list` has no secrets. |
| `movePurposes(store, address, purposes)` | Gives a key purposes and takes them off the other keys of the same vendor and owner, in one call. The explicit move that `put` asks for. |
| `keysFor(store, { owner, vendor, purpose?, now? })` | The ring: the live keys of a vendor for an owner (`inRing`). The key with the purpose first, then the `default` key, then the rest by `madeAt` (ties by account, `env-2` before `env-10`). Each key once. |
| `projectKeys(keys)`, `applyProjection(store, keys)`, `projectionDiff(store, keys)` | The env view of the keys, one way. Per vendor: `<BASE>_API_KEY` from the `default` key, `<BASE>_API_KEY_1..n` from the rest in ring order, `NUM_<BASE>` = n. `applyProjection` writes only names that differ and removes stale ones. `projectionDiff` lists what would change as ids, never values: empty means env equals the vault. `parseVendorKeyName` and `isProjectedName` tell a projected name from any other. |
| `keyUses(uses)` | From the audit: per key id, the count of allowed uses and the time of the last. A key use is a `SecretUse` with `keyId`, `owner` and `reason` set. |
| `keysFromEnv(entries, { owner, madeAt })` | The migration piece. Each `<BASE>_API_KEY` is account `env-0` with purpose `default`, each `<BASE>_API_KEY_<n>` is `env-<n>`. A name above `NUM_<BASE>`, or a second name with the same value, is skipped and listed with its reason. Pure. |
| `credvault gate --config <file>`, `gate(config)` | The key gate. Each role's processes hold sentinels (`wsk_…`, `sentinel(gateKey, role, name)`, stable) in `<dir>/<role>.env`, never keys. mitmproxy (pinned, upstream mode to the role's egress proxy) ends TLS only on keyed vendor hosts (`VENDOR_HOSTS`, or `hosts` in the config) and swaps a sentinel in a header, the query or the body for the real key. A sentinel on another role or host: 403 and an alert. Every swap and refusal is a `fileAudit` line with the `keyId`. Clients trust `<dir>/ca.pem` (`NODE_EXTRA_CA_CERTS`) or `<dir>/ca-bundle.pem` (`SSL_CERT_FILE`). Design: `designs/2026-11-08-gate.md`. |

## Example

```ts
import { SSMClient } from "@aws-sdk/client-ssm";
import { aesGcmCipher, expiring, fileCredentials, keychainKey, ssmEnvStore, totp } from "credvault";

const logins = fileCredentials("~/.myapp/credentials.json", aesGcmCipher(keychainKey({ service: "myapp" })));
const github = await logins.get("github");
const code = github?.totpSecret ? totp(github.totpSecret) : null;

const keys = ssmEnvStore(new SSMClient({}), "/myapp/config");
await keys.put("NPM_TOKEN", token, { expiresAt: "2026-12-21T00:00:00Z" });
const soon = expiring(await keys.list(), 14 * 86_400_000);
```

## Owners

One role serves every owner. Its policy names the session tag, so a session
reaches only its owner's path, and a session without the tag reaches nothing:

```json
{
  "Effect": "Allow",
  "Action": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:PutParameter", "ssm:DeleteParameter"],
  "Resource": [
    "arn:aws:ssm:*:*:parameter/myapp/owners/${aws:PrincipalTag/owner}",
    "arn:aws:ssm:*:*:parameter/myapp/owners/${aws:PrincipalTag/owner}/*"
  ]
}
```

Its trust policy allows `sts:AssumeRole` and `sts:TagSession`, with the
`owner` tag required. Add `kms:Decrypt`/`Encrypt` on the SSM key, and
`ssm:DescribeParameters` on `*` (it cannot be scoped: names show, values
never). `ownerSsmClient({ roleArn, owner: "acme", region })` then hands
`ssmEnvStore(ssm, ownerPath("/myapp", "acme") + "/config")` a client that
cannot read another owner.

## Rules it keeps

- Values never go into argv, logs or error messages. `list` returns names only.
- A sealed file opened without its key fails loudly. It never fails as a parse error.
- A wrong write is undone from history. A push that cannot keep the old state writes nothing.
- Each app has its own Keychain item, SSM path and env prefix, so two apps never share a secret by accident. Each owner of an app has its own path and an AWS session that reaches only it.

PolyForm Strict 1.0.0: noncommercial use only; no changes, no redistribution. A commercial license: wrenautomation.com. See LICENSE.md and CONTRIBUTING.md.
