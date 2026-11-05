import {
  CookieFailure,
  FreshSuccess,
  gracePeriodInMillis,
  guardianValidation,
  StaleSuccess,
  User,
  UserValidationFailure,
} from "../src/api";
import { fetchPublicKey } from "../src/fetch-public-key";
import {
  BuilderParams,
  createCookie,
  PanDomainAuthentication,
  validateVerifiedPayload,
} from "../src/panda";

import { CookiePayload, decodeBase64 } from "../src/cookiePayload";
import { parseUser } from "../src/utils";
import {
  generatePublicKey,
  privateKey,
  publicKey,
  sampleCookie,
  sampleCookieWithoutMultifactor,
  sampleNonGuardianCookie,
} from "./fixtures";

jest.mock("../src/fetch-public-key");

function cookieData(cookie: string): string {
  return (CookiePayload.fromCookieText(cookie) as CookiePayload).data;
}

function userFromCookie(cookie: string): User {
  // This function is only used to generate a `User` object from
  // a well-formed text fixture cookie, in order to check that successful
  // `AuthenticationResult`s have the right shape. As such we don't want
  // to have to deal with the case of a bad cookie so we just assert it parses.
  return parseUser(cookieData(cookie));
}

async function createDefaultPandaWith(
  overrides: Partial<BuilderParams> = {},
): Promise<PanDomainAuthentication> {
  const defaultParams: BuilderParams = {
    cookieName: "cookiename",
    region: "region",
    bucket: "bucket",
    keyFile: "keyfile",
    validateUser: () => true,
  };
  return await PanDomainAuthentication.builder({
    ...defaultParams,
    ...overrides,
  });
}

describe("validateVerifiedPayload", function () {
  // validateVerifiedPayload receives cookie data whose signature has already been verified
  test("fail to authenticate if cookie expired and we're outside the grace period", () => {
    // Cookie expires at epoch time 1234
    const afterEndOfGracePeriod = new Date(1234 + gracePeriodInMillis + 1);
    const expected: CookieFailure = {
      success: false,
      reason: "expired-cookie",
    };
    expect(
      validateVerifiedPayload(
        cookieData(sampleCookie),
        afterEndOfGracePeriod,
        guardianValidation,
      ),
    ).toStrictEqual(expected);
  });

  test("fail to authenticate if user fails validation function", () => {
    expect(
      validateVerifiedPayload(
        cookieData(sampleCookieWithoutMultifactor),
        new Date(0),
        guardianValidation,
      ),
    ).toStrictEqual({
      success: false,
      reason: "invalid-user",
      user: userFromCookie(sampleCookieWithoutMultifactor),
    });
    expect(
      validateVerifiedPayload(
        cookieData(sampleNonGuardianCookie),
        new Date(0),
        guardianValidation,
      ),
    ).toStrictEqual({
      success: false,
      reason: "invalid-user",
      user: userFromCookie(sampleNonGuardianCookie),
    });
  });

  test("authenticate if the cookie and user are valid", () => {
    const expected: FreshSuccess = {
      success: true,
      // Cookie is not expired so no need to refresh credentials
      shouldRefreshCredentials: false,
      user: userFromCookie(sampleCookie),
    };
    expect(
      validateVerifiedPayload(cookieData(sampleCookie), new Date(0), guardianValidation),
    ).toStrictEqual(expected);
  });

  test("authenticate with shouldRefreshCredentials if cookie expired but we're within the grace period", () => {
    const beforeEndOfGracePeriod = new Date(1234 + gracePeriodInMillis - 1);
    const expected: StaleSuccess = {
      success: true,
      user: userFromCookie(sampleCookie),
      shouldRefreshCredentials: true,
      mustRefreshByEpochTimeMillis: 1234 + gracePeriodInMillis,
    };
    expect(
      validateVerifiedPayload(
        cookieData(sampleCookie),
        beforeEndOfGracePeriod,
        guardianValidation,
      ),
    ).toStrictEqual(expected);
  });

  test("fail to authenticate if user fails validation function, even within the grace period", () => {
    const user = userFromCookie(sampleCookieWithoutMultifactor);
    const withinGracePeriod = new Date(user.expires + 1);
    expect(
      validateVerifiedPayload(
        cookieData(sampleCookieWithoutMultifactor),
        withinGracePeriod,
        guardianValidation,
      ),
    ).toStrictEqual({
      success: false,
      reason: "invalid-user",
      user,
    });
  });
});

describe("createCookie", function () {
  it("should return the same cookie based on the user details being provided", function () {
    const user: User = {
      firstName: "Test",
      lastName: "User",
      email: "test.user@guardian.co.uk",
      authenticatingSystem: "test",
      authenticatedIn: ["test"],
      expires: 1234,
      multifactor: true,
    };

    const cookie = createCookie(user, privateKey);

    expect(decodeBase64(cookie)).toEqual(decodeBase64(sampleCookie));
    expect(cookie).toEqual(sampleCookie);
  });
});

describe("panda class", function () {
  const keyOne = generatePublicKey();
  const keyTwo = generatePublicKey();

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    (
      fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
    ).mockResolvedValue({ keys: [keyOne], lastUpdated: new Date() });
  });
  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe("stop", () => {
    it("stops auto refresh", async () => {
      const panda = await createDefaultPandaWith();
      expect(panda.keyUpdateTimer).not.toBeUndefined();
      panda.stop();
      expect(panda.keyUpdateTimer).toBeUndefined();
    });
  });

  describe("getPublicKey", () => {
    it("getsPublicKey immediately when last fetch is within the cache time", async () => {
      const panda = await createDefaultPandaWith();
      const fetchesBeforeGet = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      await expect(panda.getPublicKeys()).resolves.toStrictEqual([keyOne]);
      const fetchesAfterGet = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfterGet).toEqual(fetchesBeforeGet);
    });

    it("getsPublicKey after refetching when last fetch is outside the cache time", async () => {
      // cache time is 1 min
      const fiveMinsAgo = new Date();
      fiveMinsAgo.setMinutes(fiveMinsAgo.getMinutes() - 5);

      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: [keyOne], lastUpdated: fiveMinsAgo });

      const panda = await createDefaultPandaWith();

      const fetchesBefore = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      await expect(panda.getPublicKeys()).resolves.toStrictEqual([keyOne]);

      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: [keyTwo], lastUpdated: fiveMinsAgo });

      const fetchesAfter = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      await expect(panda.getPublicKeys()).resolves.toStrictEqual([keyTwo]);

      expect(fetchesAfter).toEqual(fetchesBefore + 1);
    });

    it("throws if fetchPublicKey fails as part of initialisation via builder method", async () => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockRejectedValue(new Error("Failed to fetch public key"));

      await expect(createDefaultPandaWith()).rejects.toThrow(
        "Failed to fetch public key",
      );
    });

    it("recovers and retains the cached key if fetchPublicKey fails after initialisation", async () => {
      // cache time is 1 min
      const fiveMinsAgo = new Date();
      fiveMinsAgo.setMinutes(fiveMinsAgo.getMinutes() - 5);

      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: [keyOne], lastUpdated: fiveMinsAgo });

      const panda = await createDefaultPandaWith();

      const fetchesBefore = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockRejectedValue(new Error("Failed to fetch public key"));

      await expect(panda.getPublicKeys()).resolves.toStrictEqual([keyOne]);

      const fetchesAfter = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfter).toEqual(fetchesBefore + 1);
    });
  });

  describe("decode", () => {
    it("returns the first defined result and stops trying further keys", async () => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({
        keys: [keyOne, keyTwo, generatePublicKey()],
        lastUpdated: new Date(),
      });
      const panda = await createDefaultPandaWith();
      const f = jest.fn((key) => (key === keyTwo ? "found" : undefined));

      await expect(panda.decode(f)).resolves.toBe("found");
      expect(f).toHaveBeenCalledTimes(2);
    });

    it("treats a throwing callback as a failure for that key and carries on", async () => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: [keyOne, keyTwo], lastUpdated: new Date() });
      const panda = await createDefaultPandaWith();
      const errorSpy = jest.spyOn(console, "error").mockImplementation();

      const result = await panda.decode((key) => {
        if (key === keyOne) throw new Error("boom");
        return "ok";
      });

      expect(result).toBe("ok");
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("boom"));
      errorSpy.mockRestore();
    });

    it("awaits async callbacks rather than accepting the first promise", async () => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: [keyOne, keyTwo], lastUpdated: new Date() });
      const panda = await createDefaultPandaWith();

      const result = await panda.decode(async (key) =>
        key === keyTwo ? "second" : undefined,
      );
      expect(result).toBe("second");
    });

    it("returns undefined if no key yields a result", async () => {
      const panda = await createDefaultPandaWith();
      await expect(panda.decode(() => undefined)).resolves.toBeUndefined();
    });

    it("returns falsy-but-defined results", async () => {
      const panda = await createDefaultPandaWith();
      await expect(panda.decode(() => "")).resolves.toBe("");
    });
  });

  describe("verify", () => {
    beforeEach(() => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: publicKey, lastUpdated: new Date() });
    });

    it("should authenticate if cookie and user are valid", async () => {
      jest.setSystemTime(100);
      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `cookiename=${sampleCookie}`,
      );

      const expected: FreshSuccess = {
        success: true,
        // Cookie is not expired
        shouldRefreshCredentials: false,
        user: userFromCookie(sampleCookie),
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should authenticate if cookie and user are valid when multiple cookies are passed", async () => {
      jest.setSystemTime(100);
      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `a=blah; b=stuff; cookiename=${sampleCookie}; c=4958345`,
      );

      const expected: FreshSuccess = {
        success: true,
        // Cookie is not expired
        shouldRefreshCredentials: false,
        user: userFromCookie(sampleCookie),
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should authenticate if one of the available public keys is valid", async () => {
      jest.setSystemTime(100);
      jest.clearAllMocks();
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({
        keys: [generatePublicKey(), publicKey[0]],
        lastUpdated: new Date(),
      });
      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `cookiename=${sampleCookie}`,
      );

      const expected: FreshSuccess = {
        success: true,
        // Cookie is not expired
        shouldRefreshCredentials: false,
        user: userFromCookie(sampleCookie),
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail with invalid-cookie if the signature was made with none of the available keys", async () => {
      jest.setSystemTime(100);
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({
        keys: [generatePublicKey(), generatePublicKey()],
        lastUpdated: new Date(),
      });
      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `cookiename=${sampleCookie}`,
      );

      const expected: CookieFailure = {
        success: false,
        reason: "invalid-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail with invalid-cookie if the signature is malformed", async () => {
      jest.setSystemTime(100);
      const panda = await createDefaultPandaWith();
      const [data] = sampleCookie.split(".");

      for (const signature of ["1234", sampleCookie.split(".")[1].slice(0, -2)]) {
        const result = await panda.verify(`cookiename=${data}.${signature}`);
        expect(result).toStrictEqual({
          success: false,
          reason: "invalid-cookie",
        });
      }
    });

    it("should fail with invalid-cookie if the data has been tampered with", async () => {
      jest.setSystemTime(100);
      const panda = await createDefaultPandaWith();
      // Valid signature for the multifactor cookie, but data from the non-multifactor one
      const [, signature] = sampleCookie.split(".");
      const [otherData] = sampleCookieWithoutMultifactor.split(".");

      const result = await panda.verify(`cookiename=${otherData}.${signature}`);
      expect(result).toStrictEqual({
        success: false,
        reason: "invalid-cookie",
      });
    });

    it.each([
      ["data is not base64", `not-base64-data.${sampleCookie.split(".")[1]}`],
      ["signature is not base64", `${sampleCookie.split(".")[0]}.not-base64-sig`],
      ["there is no dot separator", sampleCookie.replace(".", "")],
      ["there are multiple dot separators", sampleCookie.replace(".", "..")],
    ])("should fail with invalid-cookie if %s", async (_name, badCookie) => {
      jest.setSystemTime(100);
      const panda = await createDefaultPandaWith();
      const result = await panda.verify(`cookiename=${badCookie}`);
      expect(result).toStrictEqual({
        success: false,
        reason: "invalid-cookie",
      });
    });

    it("should fail to authenticate if cookie expired and we're outside the grace period", async () => {
      // Cookie expiry is 1234
      const afterEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis + 1;
      jest.setSystemTime(afterEndOfGracePeriodEpochMillis);

      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `cookiename=${sampleCookie}`,
      );

      const expected: CookieFailure = {
        success: false,
        reason: "expired-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("authenticate with shouldRefreshCredentials if cookie expired but we're within the grace period", async () => {
      // Cookie expiry is 1234
      const beforeEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis - 1;
      jest.setSystemTime(beforeEndOfGracePeriodEpochMillis);

      const panda = await createDefaultPandaWith();
      const authenticationResult = await panda.verify(
        `cookiename=${sampleCookie}`,
      );

      const expected: StaleSuccess = {
        success: true,
        shouldRefreshCredentials: true,
        mustRefreshByEpochTimeMillis: 1234 + gracePeriodInMillis,
        user: userFromCookie(sampleCookie),
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate if user is not valid", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });
      const authenticationResult = await panda.verify(
        `cookiename=${sampleNonGuardianCookie}`,
      );

      const expected: UserValidationFailure = {
        success: false,
        reason: "invalid-user",
        user: userFromCookie(sampleNonGuardianCookie),
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate if there is no cookie with the correct name", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });
      const authenticationResult = await panda.verify(
        `wrongcookiename=${sampleNonGuardianCookie}`,
      );

      const expected: CookieFailure = {
        success: false,
        reason: "no-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate if the cookie request header is malformed", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });
      // The cookie headers should be semicolon-separated name=value
      const authenticationResult = await panda.verify(sampleNonGuardianCookie);

      const expected: CookieFailure = {
        success: false,
        reason: "no-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate if there is no cookie with the correct name out of multiple cookies", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });
      const authenticationResult = await panda.verify(
        `wrongcookiename=${sampleNonGuardianCookie}; anotherwrongcookiename=${sampleNonGuardianCookie}`,
      );

      const expected: CookieFailure = {
        success: false,
        reason: "no-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate with invalid-cookie reason if cookie is malformed", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        cookieName: "rightcookiename",
        validateUser: guardianValidation,
      });
      // There is a valid Panda cookie in here, but it's under the wrong name
      const authenticationResult = await panda.verify(
        `wrongcookiename=${sampleNonGuardianCookie}; rightcookiename=not-valid-panda-cookie`,
      );

      const expected: CookieFailure = {
        success: false,
        reason: "invalid-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it("should fail to authenticate with no-cookie reason if no cookie is present at all", async () => {
      jest.setSystemTime(100);

      const panda = await createDefaultPandaWith({
        cookieName: "rightcookiename",
        validateUser: guardianValidation,
      });
      const noCookie = undefined;
      const authenticationResult = await panda.verify(noCookie);

      const expected: CookieFailure = {
        success: false,
        reason: "no-cookie",
      };
      expect(authenticationResult).toStrictEqual(expected);
    });
  });

  describe("refresh behaviour", () => {
    beforeEach(() => {
      (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mockResolvedValue({ keys: publicKey, lastUpdated: new Date() });
    });

    it("should refresh the public key on a schedule", async () => {
      const _panda = await createDefaultPandaWith();

      const fetchesBefore = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      /**
       * Advance time by 2 minutes, which is longer than the cache time of 1 minute.
       * advanceTimersByTimeAsync also flushes async timer callbacks (e.g. the async setInterval).
       */
      await jest.advanceTimersByTimeAsync(2 * 60 * 1000);

      const fetchesAfter = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfter).toBeGreaterThan(fetchesBefore);
    });

    it("should refresh the public key when 'verify' is called after the cache time has elapsed", async () => {
      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });

      panda.stop(); // Stop the auto-refresh so we can control when the refresh happens

      const fetchesBefore = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      /**
       * Advance time by 2 minutes, which is longer than the cache time of 1 minute.
       * advanceTimersByTimeAsync also flushes async timer callbacks (e.g. the async setInterval).
       */
      await jest.advanceTimersByTimeAsync(2 * 60 * 1000);

      const fetchesAfterWait = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfterWait).toEqual(fetchesBefore);

      await panda.verify(`cookiename=${sampleCookie}`);

      const fetchesAfter = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfter).toBeGreaterThan(fetchesBefore);
    });

    it("should use the cached key when 'verify' is called if the cache time has not elapsed", async () => {
      const panda = await createDefaultPandaWith({
        validateUser: guardianValidation,
      });

      panda.stop(); // Stop the auto-refresh so we can control when the refresh happens

      const fetchesBefore = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      await panda.verify(`cookiename=${sampleCookie}`);

      const fetchesAfter = (
        fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>
      ).mock.calls.length;

      expect(fetchesAfter).toEqual(fetchesBefore);
    });
  });
});
