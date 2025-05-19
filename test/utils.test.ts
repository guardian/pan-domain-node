import { parseCookie, decodeBase64 } from '../src/utils';
import { sampleCookie } from './fixtures';
import { URLSearchParams } from 'url';

test("decode a cookie", () => {
    const parsedCookie = parseCookie(sampleCookie);
    expect(parsedCookie).toBeDefined()

    // Unfortunately the above expect() doesn't narrow the type
    if (parsedCookie) {
        const { data, signature } = parsedCookie;
        expect(signature.length).toBe(684);

        const params = new URLSearchParams(data);

        expect(params.get("firstName")).toBe("Test");
        expect(params.get("lastName")).toBe("User");
    }
});