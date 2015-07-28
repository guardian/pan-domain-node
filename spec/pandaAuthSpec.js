var Qs = require('qs');

var PandaUtils = require('./../lib/pandaUtils');

var cookieFixture = require('./fixtures/sampleCookie').cookie;
var samplePublicKey = require('./fixtures/samplePublicKey').samplePublicKey;

describe('jasmine-node', function(){

    var parsedCookie;

    it('should parse a cookie', function () {
        parsedCookie = PandaUtils.parseCookie(cookieFixture);

        expect(parsedCookie.hasOwnProperty('data')).toBe(true);
        expect(parsedCookie.data.length).toEqual(320);
        expect(parsedCookie.hasOwnProperty('signature')).toBe(true);
        expect(parsedCookie.signature.length).toEqual(684);
    });

    it('should base64 decode a cookie data', function () {
        var decodedData = PandaUtils.decodeBase64(parsedCookie.data);

        expect(decodedData.length).toEqual(239);

        var parsedDecodedData = Qs.parse(decodedData);
console.log(parsedDecodedData)
        expect(parsedDecodedData.firstName).toBe('Chris');
        expect(parsedDecodedData.lastName).toBe('Finch');
    });

    it('should correctly format a PEM key', function () {
        var formattedKey = PandaUtils.stringToRSAPublicFormat(samplePublicKey);
        var splitKey = formattedKey.split('\n');

        expect(splitKey.length).toEqual(20);
        expect(splitKey[0]).toBe('-----BEGIN PUBLIC KEY-----');
        expect(splitKey[splitKey.length - 1]).toBe('-----END PUBLIC KEY-----');
        expect(splitKey[9].length).toEqual(64);
    });

});
