import * as qs from 'qs';
import { parseCookie, decodeBase64 } from './utils';
import { cookie } from '../fixtures/sampleCookie';

test("parse a cookie", () => {
    const { data, signature } = parseCookie(cookie);
    
    expect(data.length).toBe(320);
    expect(signature.length).toBe(684);
});

test("base64 decode a cookie", () => {
    const params = qs.parse(decodeBase64(parseCookie(cookie).data));
    
    expect(params["firstName"]).toBe("Chris");
    expect(params["lastName"]).toBe("Finch");
});