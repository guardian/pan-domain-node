import { parseKeysFromIni } from "../src/fetch-public-key";

describe("parseKeysFromIni", () => {
  it("should parse a valid ini string and return the public key", () => {
    const iniString = [
      "aValue=someValue",
      "publicKey=abcd123==",
      "someOtherKey=someValue",
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("key");
    expect(result.key).toBe(
      "-----BEGIN PUBLIC KEY-----\nabcd123==\n-----END PUBLIC KEY-----",
    );
    expect(result).toHaveProperty("lastUpdated");
    expect(result.lastUpdated).toBeInstanceOf(Date);
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
