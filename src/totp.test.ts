import { describe, expect, it } from "vitest";
import { base32Decode, findTotpSecret, parseOtpauth, totp, totpRemainingMs } from "./totp.js";

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp", () => {
  it("decodes base32", () => {
    expect(base32Decode("GEZDGNBVGY3TQOJQ").toString()).toBe("1234567890");
    expect(base32Decode("gezd gnbv-gy3t qojq").toString()).toBe("1234567890");
  });
  it("matches the RFC 6238 vectors", () => {
    expect(totp(RFC_SECRET, { at: 59_000, digits: 8 })).toBe("94287082");
    expect(totp(RFC_SECRET, { at: 1_111_111_109_000, digits: 8 })).toBe("07081804");
    expect(totp(RFC_SECRET, { at: 59_000 })).toBe("287082");
  });
  it("knows when the code rolls over", () => {
    expect(totpRemainingMs(59_000)).toBe(1_000);
    expect(totpRemainingMs(60_000)).toBe(30_000);
  });
  it("parses otpauth URIs", () => {
    const p = parseOtpauth(
      "otpauth://totp/Cloudflare:will%40example.com?secret=jbsw%20y3dp-ehpk3pxp&issuer=Cloudflare&digits=6",
    );
    expect(p).toEqual({
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Cloudflare",
      account: "will@example.com",
      digits: 6,
      period: 30,
      algorithm: "sha1",
    });
  });
  it("finds the seed on a page: URI first, then a manual key, else nothing", () => {
    expect(
      findTotpSecret(
        '<img src="data:..."><a href="otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP&amp;issuer=X">',
      ),
    ).toBe("JBSWY3DPEHPK3PXP");
    expect(findTotpSecret("Can't scan? Enter this key: jbsw y3dp ehpk 3pxp")).toBe(
      "JBSWY3DPEHPK3PXP",
    );
    expect(findTotpSecret("Welcome back, nothing to see")).toBeNull();
  });
  it("keeps the key apart from the 4-letter words after it", () => {
    const google =
      "Enter your email address and this key (spaces don’t matter): jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp Make sure Time based is selected Tap Add to finish";
    expect(findTotpSecret(google)).toBe("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    expect(findTotpSecret("key: jbsw y3dp ehpk 3pxp then tap add")).toBe("JBSWY3DPEHPK3PXP");
    expect(findTotpSecret("MAKE SURE TIME BASED IS SELECTED")).toBeNull();
  });
  it("takes the key over a run of prose words before it", () => {
    const plaid =
      "Alternatively, enter the following secret:\nJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\nEnter the passcode from your app";
    expect(findTotpSecret(plaid)).toBe("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    expect(findTotpSecret(`Enter the passcode from your app\n${plaid}`)).toBe(
      "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    );
  });
});
