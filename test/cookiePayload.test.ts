import { URLSearchParams } from "url";
import { CookiePayload } from "../src/cookiePayload";
import { generatePublicKey, publicKey, sampleCookie } from "./fixtures";

describe("CookiePayload.fromCookieText", () => {
  test("decodes a cookie", () => {
    const payload = CookiePayload.fromCookieText(sampleCookie);
    expect(payload).toBeDefined();
    expect(payload?.signature.length).toBe(684);

    const params = new URLSearchParams(payload?.data);
    expect(params.get("firstName")).toBe("Test");
    expect(params.get("lastName")).toBe("User");
  });

  test.each([
    ["no dot separator", sampleCookie.replace(".", "")],
    ["multiple dot separators", sampleCookie.replace(".", "..")],
    ["non-base64 data", `not-base64-data.${sampleCookie.split(".")[1]}`],
    ["non-base64 signature", `${sampleCookie.split(".")[0]}.not-base64-sig`],
  ])("returns undefined for %s", (_name, cookie) => {
    expect(CookiePayload.fromCookieText(cookie)).toBeUndefined();
  });
});

describe("CookiePayload.payloadTextVerifiedSignedWith", () => {
  const payload = CookiePayload.fromCookieText(sampleCookie)!;

  test("returns the data when signed by the given key", () => {
    expect(payload.payloadTextVerifiedSignedWith(publicKey[0])).toBe(
      payload.data,
    );
  });

  test("returns undefined when signed by a different key", () => {
    expect(
      payload.payloadTextVerifiedSignedWith(generatePublicKey()),
    ).toBeUndefined();
  });

  test("returns undefined when the signature is malformed", () => {
    const bad = new CookiePayload(payload.data, "1234");
    expect(bad.payloadTextVerifiedSignedWith(publicKey[0])).toBeUndefined();
  });

  test("returns undefined when the data has been tampered with", () => {
    const bad = new CookiePayload(payload.data + "x", payload.signature);
    expect(bad.payloadTextVerifiedSignedWith(publicKey[0])).toBeUndefined();
  });
});
