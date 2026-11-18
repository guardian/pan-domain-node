import {
  calculateKeyObjectHashId,
  logKeyDiffs,
  toKeyObject,
} from "../src/utils";
import { generatePublicKey } from "./fixtures";

test("calculateKeyObjectHashId", () => {
  const encodedPublicKey =
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtlvGdaBPy+eRfntUlaJO1tS4beLJ+OIj+xE0awKpnTPdt8fbLbR+PYwYLlB2sWl4tkF0V0GIZJgb3Y2ruqICNN7HLcJTlR+G9TDmF+Hu+GlCYlnHeivlQidTtC1WLXuDO2EBzQDkXzfeeP0QdtyoYqlPe1Vpt9ksTzTspBTM7VJ/10ot8OAuHThn611P6lT8QBG0MzHb/XXjGr3JqZdl4xer78lQrqnmjy3UlusgDIiyRo3/HcMyxPmWpgszLvcOHG2qQ8JVpvMEfkukB2ROSamGNy9zKAW9rqnzMyHTcrhPDlapeMUIdCSsyOT3Hh8yQT/aIR+7e48PUYrC3e2nrn8QrsebE6YC0s3wPnyH5V9u0X7UY/34B1C7nb22boOfGrMexJ3Pvy9bvdL1w80Ob/IPm7OBH8PgcJ1UzlrYnIIt6ddr5nvLvkBPgkQsiYuwEwFUQJu89NhVH/JsV35B2TycJFGdd7fMyjLGC2apMFgVvN+kautcB5+I+bcWq0/3+O7FK50IeIRzWx44xU5tyGGAhwTRMqrPlW8kg8au2Mm2MitrlkRQ3MYH8ajmUyhZKAmOMH3S6/y/fn4g4ABx7sv7vKTSwLvjCpiLNx5FxF4i0I9ZLRCr8WW3D2EqpQwJhMPL6BdhPeJ0bx2UdY2+y8L7QgerrkUKMCIej9KdqhkCAwEAAQ==";
  const hashId = calculateKeyObjectHashId(toKeyObject(encodedPublicKey));
  expect(hashId).toBe("tudwv");
});

describe("logKeyDiffs", () => {
  const keyA = generatePublicKey();
  const keyB = generatePublicKey();
  const keyC = generatePublicKey();
  let logSpy: jest.SpyInstance;

  beforeEach(() => {
    logSpy = jest.spyOn(console, "log").mockImplementation();
  });
  afterEach(() => {
    logSpy.mockRestore();
  });

  test("logs nothing when the keys are unchanged, comparing by key value", () => {
    const copyOfA = toKeyObject(
      keyA.export({ type: "spki", format: "der" }).toString("base64"),
    );
    logKeyDiffs([keyA, keyB], [copyOfA, keyB]);
    expect(logSpy).not.toHaveBeenCalled();
  });

  test("logs added and removed keys by hash", () => {
    logKeyDiffs([keyA, keyB], [keyB, keyC]);

    expect(logSpy).toHaveBeenCalledTimes(2);
    expect(logSpy).toHaveBeenCalledWith(
      `New public keys added. Key hashes: ${calculateKeyObjectHashId(keyC)}`,
    );
    expect(logSpy).toHaveBeenCalledWith(
      `Public keys removed. Key hashes: ${calculateKeyObjectHashId(keyA)}`,
    );
  });
});
