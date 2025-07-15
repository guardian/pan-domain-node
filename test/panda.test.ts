import {
    CookieFailure, FreshSuccess,
    gracePeriodInMillis,
    guardianValidation, StaleSuccess,
    User, UserValidationFailure
} from '../src/api';
import { verifyUser, createCookie, PanDomainAuthentication } from '../src/panda';
import { fetchPublicKey } from '../src/fetch-public-key';

import {
    sampleCookie,
    sampleCookieWithoutMultifactor,
    sampleNonGuardianCookie,
    publicKey,
    privateKey
} from './fixtures';
import {decodeBase64, parseCookie, ParsedCookie, parseUser} from "../src/utils";

jest.mock('../src/fetch-public-key');
jest.useFakeTimers();

function userFromCookie(cookie: string): User {
    // This function is only used to generate a `User` object from
    // a well-formed text fixture cookie, in order to check that successful
    // `AuthenticationResult`s have the right shape. As such we don't want
    // to have to deal with the case of a bad cookie so we just cast to `ParsedCookie`.
    const parsedCookie = parseCookie(cookie) as ParsedCookie;
    return parseUser(parsedCookie.data);
}

describe('verifyUser', function () {

    test("fail to authenticate if cookie is missing", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'no-cookie'
        };
        expect(verifyUser(undefined, "", new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate if signature is malformed", () => {
        const [data, signature] = sampleCookie.split(".");
        const testCookie = data + ".1234";

        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        expect(verifyUser(testCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate if cookie expired and we're outside the grace period", () => {
        // Cookie expires at epoch time 1234
        const afterEndOfGracePeriod = new Date(1234 + gracePeriodInMillis + 1)
        const expected: CookieFailure = {
            success: false,
            reason: 'expired-cookie'
        };
        expect(verifyUser(sampleCookie, publicKey, afterEndOfGracePeriod, guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate if user fails validation function", () => {
        expect(verifyUser(sampleCookieWithoutMultifactor, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'invalid-user',
            user: userFromCookie(sampleCookieWithoutMultifactor)
        });
        expect(verifyUser(sampleNonGuardianCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'invalid-user',
            user: userFromCookie(sampleNonGuardianCookie)
        });
    });

    test("fail to authenticate with invalid-cookie reason if signature is not valid", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        const slightlyBadCookie = sampleCookie.slice(0, -2);
        expect(verifyUser(slightlyBadCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate with invalid-cookie reason if data part is not base64", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        const [_, signature] = sampleCookie.split(".");
        const nonBase64Data = "not-base64-data";
        const testCookie = `${nonBase64Data}.${signature}`;
        expect(verifyUser(testCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate with invalid-cookie reason if signature part is not base64", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        const [data, _] = sampleCookie.split(".");
        const nonBase64Signature = "not-base64-signature";
        const testCookie = `${data}.${nonBase64Signature}`;
        expect(verifyUser(testCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate with invalid-cookie reason if cookie has no dot separator", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        const noDotCookie = sampleCookie.replace(".", "");
        expect(verifyUser(noDotCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("fail to authenticate with invalid-cookie reason if cookie has multiple dot separators", () => {
        const expected: CookieFailure = {
            success: false,
            reason: 'invalid-cookie'
        };
        const multipleDotsCookie = sampleCookie.replace(".", "..");
        expect(verifyUser(multipleDotsCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("authenticate if the cookie and user are valid", () => {
        const expected: FreshSuccess = {
            success: true,
            // Cookie is not expired so no need to refresh credentials
            shouldRefreshCredentials: false,
            user: userFromCookie(sampleCookie)
        };
        expect(verifyUser(sampleCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    test("authenticate with shouldRefreshCredentials if cookie expired but we're within the grace period", () => {
        const beforeEndOfGracePeriod = new Date(1234 + gracePeriodInMillis - 1);
        const expected: StaleSuccess = {
            success: true,
            user: userFromCookie(sampleCookie),
            shouldRefreshCredentials: true,
            mustRefreshByEpochTimeMillis: 1234 + gracePeriodInMillis
        };
        expect(verifyUser(sampleCookie, publicKey, beforeEndOfGracePeriod, guardianValidation)).toStrictEqual(expected);
    });
});

describe('createCookie', function () {
    it('should return the same cookie based on the user details being provided', function () {
        const user: User = {
            firstName: "Test",
            lastName: "User",
            email: "test.user@guardian.co.uk",
            authenticatingSystem: "test",
            authenticatedIn: ["test"],
            expires: 1234,
            multifactor: true
        };

        const cookie = createCookie(user, privateKey);

        expect(decodeBase64(cookie)).toEqual(decodeBase64(sampleCookie));
        expect(cookie).toEqual(sampleCookie)
    });
});

describe('panda class', function () {
  beforeEach(() => {
    (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mockResolvedValue({ key: 'PUBLIC KEY', lastUpdated: new Date() });
  });

  describe('stop', () => {

    it('stops auto refresh', () => {
      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      expect(panda.keyUpdateTimer).not.toBeUndefined();
      panda.stop();
      expect(panda.keyUpdateTimer).toBeUndefined();
    });

  });

  describe('getPublicKey', () => {

    it('getsPublicKey immediately when last fetch is within the cache time', async () => {

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const fetchesBeforeGet = (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mock.calls.length;

      await expect(panda.getPublicKey()).resolves.toEqual('PUBLIC KEY');
      const fetchesAfterGet = (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mock.calls.length;

      expect(fetchesAfterGet).toEqual(fetchesBeforeGet);

    });

    it('getsPublicKey after refetching when last fetch is outside the cache time', async () => {
      // cache time is 1 min
      const fiveMinsAgo = new Date();
      fiveMinsAgo.setMinutes(fiveMinsAgo.getMinutes() - 5);

      (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mockResolvedValue({ key: 'PUBLIC KEY', lastUpdated: fiveMinsAgo });

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);

      const fetchesBefore = (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mock.calls.length;

      await expect(panda.getPublicKey()).resolves.toEqual('PUBLIC KEY');

      (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mockResolvedValue({ key: 'PUBLIC KEY 2', lastUpdated: fiveMinsAgo });

      const fetchesAfter = (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mock.calls.length;

      await expect(panda.getPublicKey()).resolves.toEqual('PUBLIC KEY 2');

      expect(fetchesAfter).toEqual(fetchesBefore + 1);
    });

  });

  describe('verify', () => {

    beforeEach(() => {
      (fetchPublicKey as jest.MockedFunction<typeof fetchPublicKey>).mockResolvedValue({ key: publicKey, lastUpdated: new Date() });
    });

    it('should authenticate if cookie and user are valid', async () => {
      jest.setSystemTime(100);
      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`cookiename=${sampleCookie}`);

      const expected: FreshSuccess = {
          success: true,
          // Cookie is not expired
          shouldRefreshCredentials: false,
          user: userFromCookie(sampleCookie)
      }
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should authenticate if cookie and user are valid when multiple cookies are passed', async () => {
      jest.setSystemTime(100);
      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`a=blah; b=stuff; cookiename=${sampleCookie}; c=4958345`);

      const expected: FreshSuccess = {
          success: true,
          // Cookie is not expired
          shouldRefreshCredentials: false,
          user: userFromCookie(sampleCookie)
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate if cookie expired and we\'re outside the grace period', async () => {
      // Cookie expiry is 1234
      const afterEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis + 1
      jest.setSystemTime(afterEndOfGracePeriodEpochMillis);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`cookiename=${sampleCookie}`);

      const expected: CookieFailure = {
          success: false,
          reason: 'expired-cookie'
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('authenticate with shouldRefreshCredentials if cookie expired but we\'re within the grace period', async () => {
      // Cookie expiry is 1234
      const beforeEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis - 1;
      jest.setSystemTime(beforeEndOfGracePeriodEpochMillis);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`cookiename=${sampleCookie}`);

      const expected: StaleSuccess = {
          success: true,
          shouldRefreshCredentials: true,
          mustRefreshByEpochTimeMillis: 1234 + gracePeriodInMillis,
          user: userFromCookie(sampleCookie)
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate if user is not valid', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      const authenticationResult = await panda.verify(`cookiename=${sampleNonGuardianCookie}`);

      const expected: UserValidationFailure = {
          success: false,
          reason: 'invalid-user',
          user: userFromCookie(sampleNonGuardianCookie)
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate if there is no cookie with the correct name', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      const authenticationResult = await panda.verify(`wrongcookiename=${sampleNonGuardianCookie}`);

      const expected: CookieFailure = {
          success: false,
          reason: "no-cookie"
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate if the cookie request header is malformed', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      // The cookie headers should be semicolon-separated name=valueg
      const authenticationResult = await panda.verify(sampleNonGuardianCookie);

      const expected: CookieFailure = {
          success: false,
          reason: "no-cookie"
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate if there is no cookie with the correct name out of multiple cookies', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      const authenticationResult = await panda.verify(`wrongcookiename=${sampleNonGuardianCookie}; anotherwrongcookiename=${sampleNonGuardianCookie}`);

      const expected: CookieFailure = {
          success: false,
          reason: "no-cookie"
      };
      expect(authenticationResult).toStrictEqual(expected);
    });

    it('should fail to authenticate with invalid-cookie reason if cookie is malformed', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('rightcookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      // There is a valid Panda cookie in here, but it's under the wrong name
      const authenticationResult = await panda.verify(`wrongcookiename=${sampleNonGuardianCookie}; rightcookiename=not-valid-panda-cookie`);

      const expected: CookieFailure = {
        success: false,
        reason: "invalid-cookie"
      };
      expect(authenticationResult).toStrictEqual(expected);
    });
  });

});
