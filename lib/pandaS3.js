var AWS = require('aws-sdk');
var s3 = new AWS.S3();
var Q = require('q');
var PandaUtils = require('./pandaUtils');

function GetPublicKeyFromAws () {

    var params = {
      Bucket: 'pan-domain-auth-settings', /* required */
      Key: 'local.dev-gutools.co.uk.settings.public' /* required */
    };

    return Q.Promise(function (resolve, reject) {

        s3.getObject(params, function(err, data) {
          if (err) {
              console.error('Panda Auth could not contact AWS S3', err, err.stack); // an error occurred
              reject(err);
          } else {
              var keyData = data.Body.toString(PandaUtils.TEXT_ENCODING).replace('publicKey=', '');

              if (keyData) {
                  resolve(PandaUtils.stringToRSAPublicFormat(keyData));
              } else {
                  console.error('Panda Auth could not read the public key from AWS S3');
                  reject(false); // TODO: More meaningful error
              }
          }
        });
    });
};

module.exports = {
    getKey: GetPublicKeyFromAws
};
