var Qs = require('qs');

var PandaUtils = require('./../lib/pandaUtils');

var cookieFixture = require('./fixtures/sampleCookie').cookie;

describe('jasmine-node', function(){

    var parsedCookie;
    beforeEach(function () {
        parsedCookie = PandaUtils.parseCookie(cookieFixture);
    });

    it('should parse a cookie', function () {
        expect(parsedCookie.hasOwnProperty('data')).toBe(true);
        expect(parsedCookie.data.length).toEqual(320);
        expect(parsedCookie.hasOwnProperty('signature')).toBe(true);
        expect(parsedCookie.signature.length).toEqual(684);
    });

    it('should base64 decode a cookie data', function () {
        var decodedData = PandaUtils.decodeBase64(parsedCookie.data);

        expect(decodedData.length).toEqual(239);

        var parsedDecodedData = Qs.parse(decodedData);

        expect(parsedDecodedData.firstName).toBe('Chris');
        expect(parsedDecodedData.lastName).toBe('Finch');
    });

});
