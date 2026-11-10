/**
 * TOTP (RFC 6238) with node:crypto, no dependency: the codes an
 * authenticator app would show, so a login's second factor is ours to
 * type. `findTotpSecret` pulls the seed out of an enrollment page (the
 * otpauth:// link behind the QR, or the "enter this key manually" text).
 */
import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`base32: bad character ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export type TotpAlgorithm = "sha1" | "sha256" | "sha512";

export interface TotpOptions {
  /** Unix ms; defaults to now. */
  at?: number;
  period?: number;
  digits?: number;
  algorithm?: TotpAlgorithm;
}

/** The code for `secret` (base32) at `at`. */
export function totp(secret: string, opts: TotpOptions = {}): string {
  const period = opts.period ?? 30;
  const digits = opts.digits ?? 6;
  const counter = Math.floor((opts.at ?? Date.now()) / 1000 / period);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(opts.algorithm ?? "sha1", base32Decode(secret))
    .update(msg)
    .digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

/** Milliseconds until the current code rolls over; wait it out when a site rejects a code that is about to expire. */
export function totpRemainingMs(at = Date.now(), period = 30): number {
  const step = period * 1000;
  return step - (at % step);
}

export interface TotpParams {
  secret: string;
  issuer: string | null;
  account: string | null;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
}

export function parseOtpauth(uri: string): TotpParams {
  const u = new URL(uri);
  if (u.protocol !== "otpauth:" || u.host !== "totp") throw new Error("not an otpauth://totp URI");
  const secret = u.searchParams.get("secret");
  if (!secret) throw new Error("otpauth URI has no secret");
  const label = decodeURIComponent(u.pathname.replace(/^\/+/, ""));
  const [labelIssuer, account] = label.includes(":") ? label.split(":", 2) : [null, label];
  const algo = (u.searchParams.get("algorithm") ?? "SHA1").toLowerCase();
  return {
    secret: secret.replace(/[\s=-]/g, "").toUpperCase(),
    issuer: u.searchParams.get("issuer") ?? labelIssuer,
    account: account || null,
    digits: Number(u.searchParams.get("digits") ?? 6),
    period: Number(u.searchParams.get("period") ?? 30),
    algorithm: algo === "sha256" || algo === "sha512" ? algo : "sha1",
  };
}

const OTPAUTH = /otpauth:\/\/totp\/[^\s"'<>]+/i;
/**
 * 16+ base32 characters in one case, optionally in spaced or dashed groups
 * of 4. One case because a page prints its key in one case, and the words
 * around it ("Make sure Time based") are mixed: they must not join the run.
 */
const MANUAL_KEYS = [
  /\b(?:[a-z2-7]{4}[\s-]?){4,}[a-z2-7]*\b/g,
  /\b(?:[A-Z2-7]{4}[\s-]?){4,}[A-Z2-7]*\b/g,
];
/**
 * Seed lengths sites hand out, most common first (Google/Cloudflare 32,
 * GitHub/Microsoft 16, AWS 64). A run is cut to the first of these some
 * prefix of its groups adds up to, so a 4-letter word after the key
 * ("then") does not join it. A wrong cut fails the confirm step, nothing worse.
 */
const SEED_LENGTHS = [32, 16, 64, 26, 52, 20, 24, 40];

/** One run cut to a seed length, else whole when it can be one; null when it cannot. */
function cutRun(run: string): string | null {
  const tokens = run.trim().split(/[\s-]+/);
  const prefixes = tokens.map((_, i) => tokens.slice(0, i + 1).join(""));
  // no digit and uneven groups ("passcode from your"): words, not a key
  const key = (n: number) => {
    const used = tokens.slice(0, n);
    const words = n > 1 && !/[2-7]/.test(prefixes[n - 1] ?? "") && used.some((t) => t.length !== 4);
    return words ? null : (prefixes[n - 1] ?? null);
  };
  for (const len of SEED_LENGTHS) {
    const i = prefixes.findIndex((p) => p.length === len);
    if (i >= 0) return key(i + 1);
  }
  const whole = tokens.join("");
  return whole.length >= 16 && whole.length % 2 === 0 ? key(tokens.length) : null;
}

/**
 * Every run on the page, best first: a digit (prose has none; a 32-letter seed lacks
 * one ~0.1% of the time), then upper case. Plaid's "passcode from your app" cut to 16
 * and won over the real key (11-10).
 */
function manualKey(text: string): string | null {
  const keys = MANUAL_KEYS.flatMap((re) =>
    [...text.matchAll(re)].map((m) => cutRun(m[0])).filter((k): k is string => k !== null),
  );
  const rank = (k: string) => (/[2-7]/.test(k) ? 0 : 2) + (k === k.toUpperCase() ? 0 : 1);
  const best = keys.map((k, i) => ({ k, i })).sort((a, b) => rank(a.k) - rank(b.k) || a.i - b.i)[0];
  return best ? best.k.toUpperCase() : null;
}

/** The seed in page text or HTML: a URI wins, then a manual-entry key. Null when neither is there. */
export function findTotpSecret(text: string): string | null {
  const uri = text.match(OTPAUTH);
  if (uri) {
    try {
      return parseOtpauth(uri[0].replace(/&amp;/g, "&")).secret;
    } catch {
      // fall through to a manual key
    }
  }
  return manualKey(text);
}
