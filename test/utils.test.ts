import { URLSearchParams } from "url";
import { calculateKeyHashId, parseCookie } from "../src/utils";
import { sampleCookie } from "./fixtures";

test("decode a cookie", () => {
  const parsedCookie = parseCookie(sampleCookie);
  expect(parsedCookie).toBeDefined();

  // Unfortunately the above expect() doesn't narrow the type
  if (parsedCookie) {
    const { data, signature } = parsedCookie;
    expect(signature.length).toBe(684);

    const params = new URLSearchParams(data);

    expect(params.get("firstName")).toBe("Test");
    expect(params.get("lastName")).toBe("User");
  }
});

test("calculateKeyHashId", () => {
  const encodedPublicKey =
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtlvGdaBPy+eRfntUlaJO1tS4beLJ+OIj+xE0awKpnTPdt8fbLbR+PYwYLlB2sWl4tkF0V0GIZJgb3Y2ruqICNN7HLcJTlR+G9TDmF+Hu+GlCYlnHeivlQidTtC1WLXuDO2EBzQDkXzfeeP0QdtyoYqlPe1Vpt9ksTzTspBTM7VJ/10ot8OAuHThn611P6lT8QBG0MzHb/XXjGr3JqZdl4xer78lQrqnmjy3UlusgDIiyRo3/HcMyxPmWpgszLvcOHG2qQ8JVpvMEfkukB2ROSamGNy9zKAW9rqnzMyHTcrhPDlapeMUIdCSsyOT3Hh8yQT/aIR+7e48PUYrC3e2nrn8QrsebE6YC0s3wPnyH5V9u0X7UY/34B1C7nb22boOfGrMexJ3Pvy9bvdL1w80Ob/IPm7OBH8PgcJ1UzlrYnIIt6ddr5nvLvkBPgkQsiYuwEwFUQJu89NhVH/JsV35B2TycJFGdd7fMyjLGC2apMFgVvN+kautcB5+I+bcWq0/3+O7FK50IeIRzWx44xU5tyGGAhwTRMqrPlW8kg8au2Mm2MitrlkRQ3MYH8ajmUyhZKAmOMH3S6/y/fn4g4ABx7sv7vKTSwLvjCpiLNx5FxF4i0I9ZLRCr8WW3D2EqpQwJhMPL6BdhPeJ0bx2UdY2+y8L7QgerrkUKMCIej9KdqhkCAwEAAQ==";
  const hashId = calculateKeyHashId(encodedPublicKey);
  expect(hashId).toBe("tudwv");
});
