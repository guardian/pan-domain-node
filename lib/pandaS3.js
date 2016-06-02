var PandaUtils = require('./pandaUtils');
var fetchPEM = require('pan-domain-public-keys').fetchPEM;

exports.getKey = function () {
    return fetchPEM(PandaUtils.settings.domain);
}
