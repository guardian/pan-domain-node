import { parseKeysFromIni } from "../src/fetch-public-key";

describe("parseKeysFromIni", () => {
  it("should parse a valid ini string and return the public key", () => {
    const iniString = [
      "aValue=someValue",
      "publicKey=abcd123==",
      "someOtherKey=someValue",
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys).toEqual([
      "-----BEGIN PUBLIC KEY-----\nabcd123==\n-----END PUBLIC KEY-----",
    ]);
    expect(result).toHaveProperty("lastUpdated");
    expect(result.lastUpdated).toBeInstanceOf(Date);
  });

  it("should parse also accepted keys from the ini string", () => {
    const iniString = [
      "publicKey=abcd123==",
      "alsoAccept.0.publicKey=efgh456==",
      "alsoAccept.1.publicKey=ijkl789==",
      "alsoAccept.10.publicKey=mnopqrs==",
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys).toEqual([
      "-----BEGIN PUBLIC KEY-----\nabcd123==\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----\nefgh456==\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----\nijkl789==\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----\nmnopqrs==\n-----END PUBLIC KEY-----",
    ]);
  });

  it("should only parse also accepted keys that match the expected format", () => {
    const iniString = [
      "publicKey=abcd123==",
      "alsoAccept.0.publicKey=efgh456==",
      "alsoAccept.invalidKey=shouldNotBeParsed",
      "alsoAccept.1.publicKey=ijkl789==",
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys).toEqual([
      "-----BEGIN PUBLIC KEY-----\nabcd123==\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----\nefgh456==\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----\nijkl789==\n-----END PUBLIC KEY-----",
    ]);
  });

  it("should throw an error if the publicKey is missing", () => {
    const iniString = "someOtherKey=someValue";

    expect(() => parseKeysFromIni(iniString)).toThrow(
      "Missing publicKey setting from config",
    );
  });

  it("should throw an error if the ini string is empty", () => {
    const iniString = "";

    expect(() => parseKeysFromIni(iniString)).toThrow(
      "Missing publicKey setting from config",
    );
  });
});
