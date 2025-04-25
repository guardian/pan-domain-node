import {
    Authenticated,
    gracePeriodInMillis,
    guardianValidation,
    Unauthenticated,
    Unauthorised,
    User
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
jest.useFakeTimers('modern');

function userFromCookie(cookie: string): User {
    const parsedCookie = parseCookie(cookie) as ParsedCookie;
    return parseUser(parsedCookie.data);
}

describe('verifyUser', function () {

    test("fail to authenticate if cookie is missing", () => {
        expect(verifyUser(undefined, "", new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'no-cookie'
        });
    });

    test("fail to authenticate if signature is malformed", () => {
        const [data, signature] = sampleCookie.split(".");
        const testCookie = data + ".1234";

        expect(verifyUser(testCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'bad-cookie'
        });
    });

    test("fail to authenticate if cookie expired and we're outside the grace period", () => {
        // Cookie expires at epoch time 1234
        const afterEndOfGracePeriod = new Date(1234 + gracePeriodInMillis + 1)
        expect(verifyUser(sampleCookie, publicKey, afterEndOfGracePeriod, guardianValidation)).toStrictEqual({
            success: false,
            reason: 'expired-cookie'
        });
    });

    test("fail to authenticate if user fails validation function", () => {
        expect(verifyUser(sampleCookieWithoutMultifactor, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'bad-user',
            user: userFromCookie(sampleCookieWithoutMultifactor)
        });
        expect(verifyUser(sampleNonGuardianCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: false,
            reason: 'bad-user',
            user: userFromCookie(sampleNonGuardianCookie)
        });
    });

    // Malformed cookie text (no dot)
    test("fail to authenticate with bad-cookie reason if cookie is malformed", () => {
        const expected: Unauthenticated = {
            success: false,
            reason: 'bad-cookie'
        };
        expect(verifyUser("complete garbage", publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });

    // Signature not valid
    test("fail to authenticate with bad-cookie reason if signature is not valid", () => {
        const expected: Unauthenticated = {
            success: false,
            reason: 'bad-cookie'
        };
        const slightlyBadCookie = sampleCookie.slice(0, -2);
        expect(verifyUser(slightlyBadCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual(expected);
    });
    
    test("authenticate if the cookie and user are valid", () => {
        expect(verifyUser(sampleCookie, publicKey, new Date(0), guardianValidation)).toStrictEqual({
            success: true,
            // Cookie is not expired so no need to refresh credentials
            shouldRefreshCredentials: false,
            user: userFromCookie(sampleCookie)
        });
    });

    test("authenticate with shouldRefreshCredentials if cookie expired but we're within the grace period", () => {
        const beforeEndOfGracePeriod = new Date(1234 + gracePeriodInMillis - 1);
        const expected: Authenticated = {
            success: true,
            user: userFromCookie(sampleCookie),
            shouldRefreshCredentials: true
        }
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

      expect(authenticationResult).toStrictEqual({
          success: true,
          // Cookie is not expired
          shouldRefreshCredentials: false,
          user: userFromCookie(sampleCookie)
      });
    });

    it('should fail to authenticate if cookie expired and we\'re outside the grace period', async () => {
      // Cookie expiry is 1234
      const afterEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis + 1
      jest.setSystemTime(afterEndOfGracePeriodEpochMillis);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`cookiename=${sampleCookie}`);

      expect(authenticationResult).toStrictEqual({
          success: false,
          reason: 'expired-cookie'
      });
    });

    it('authenticate with shouldRefreshCredentials if we\'re within the grace period', async () => {
      // Cookie expiry is 1234
      const beforeEndOfGracePeriodEpochMillis = 1234 + gracePeriodInMillis - 1;
      jest.setSystemTime(beforeEndOfGracePeriodEpochMillis);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', (u)=> true);
      const authenticationResult = await panda.verify(`cookiename=${sampleCookie}`);

      expect(authenticationResult).toStrictEqual({
          success: true,
          shouldRefreshCredentials: true,
          user: userFromCookie(sampleCookie)
      });
    });

    it('should fail to authenticate if user is not valid', async () => {
      jest.setSystemTime(100);

      const panda = new PanDomainAuthentication('cookiename', 'region', 'bucket', 'keyfile', guardianValidation);
      const authenticationResult = await panda.verify(`cookiename=${sampleNonGuardianCookie}`);

      expect(authenticationResult).toStrictEqual({
          success: false,
          reason: 'bad-user',
          user: userFromCookie(sampleNonGuardianCookie)
      });
    });

  });

});
