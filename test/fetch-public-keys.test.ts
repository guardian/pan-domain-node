import { parseKeysFromIni } from "../src/fetch-public-key";
import { generatePublicKey, toBase64Der } from "./fixtures";

const keyA = generatePublicKey();
const keyB = generatePublicKey();
const keyC = generatePublicKey();
const keyD = generatePublicKey();
const [a, b, c, d] = [keyA, keyB, keyC, keyD].map(toBase64Der);

describe("parseKeysFromIni", () => {
  it("should parse a valid ini string and return the public key", () => {
    const iniString = [
      "aValue=someValue",
      `publicKey=${a}`,
      "someOtherKey=someValue",
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys.map(toBase64Der)).toEqual([a]);
    expect(result).toHaveProperty("lastUpdated");
    expect(result.lastUpdated).toBeInstanceOf(Date);
  });

  it("should parse also accepted keys from the ini string", () => {
    const iniString = [
      `publicKey=${a}`,
      `alsoAccept.0.publicKey=${b}`,
      `alsoAccept.1.publicKey=${c}`,
      `alsoAccept.10.publicKey=${d}`,
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys.map(toBase64Der)).toEqual([a, b, c, d]);
  });

  it("should only parse also accepted keys that match the expected format", () => {
    const iniString = [
      `publicKey=${a}`,
      `alsoAccept.0.publicKey=${b}`,
      "alsoAccept.invalidKey=shouldNotBeParsed",
      `alsoAccept.1.publicKey=${c}`,
    ].join("\n");

    const result = parseKeysFromIni(iniString);
    expect(result).toHaveProperty("keys");
    expect(result.keys.map(toBase64Der)).toEqual([a, b, c]);
  });

  it("should throw if a configured key is not a valid public key", () => {
    expect(() => parseKeysFromIni("publicKey=notAKey")).toThrow();
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
