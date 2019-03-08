"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var PanDomainAuthentication_1 = require("./PanDomainAuthentication");
exports.PanDomainAuthentication = PanDomainAuthentication_1.PanDomainAuthentication;
var AuthenticationStatus;
(function (AuthenticationStatus) {
    AuthenticationStatus["INVALID_COOKIE"] = "Invalid Cookie";
    AuthenticationStatus["EXPIRED"] = "Expired";
    AuthenticationStatus["NOT_AUTHORISED"] = "Not Authorised";
    AuthenticationStatus["AUTHORISED"] = "Authorised";
})(AuthenticationStatus = exports.AuthenticationStatus || (exports.AuthenticationStatus = {}));
function guardianValidation(user) {
    return (user.user.email.indexOf('guardian.co.uk') !== -1) && user.multiFactor;
}
exports.guardianValidation = guardianValidation;
