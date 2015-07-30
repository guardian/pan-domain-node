var AWS = require('aws-sdk');
var s3 = new AWS.S3();
var Q = require('q');
var PandaUtils = require('./pandaUtils');

function GetPublicKeyFromAws () {

    var params = {
      Bucket: PandaUtils.settings.pandaBucket, /* required */
      Key: PandaUtils.settings.pandaPublicKey /* required */
    };

    return Q.Promise(function (resolve, reject) {
        PandaUtils.log('info', 'About to call s3 with params ' + JSON.stringify(params));
        s3.getObject(params, function(err, data) {
          if (err) {
              PandaUtils.log('error', ['Panda Auth could not contact AWS S3', err, err.stack]);
              reject(err);
          } else {
              var keyData = data.Body.toString(PandaUtils.TEXT_ENCODING).replace('publicKey=', '');

              if (keyData) {
                  resolve(PandaUtils.stringToRSAPublicFormat(keyData));
              } else {
                  PandaUtils.log('error', 'Panda Auth could not read the public key from AWS S3');
                  reject(false); // TODO: More meaningful error
              }
          }
        });
    });
};

module.exports = {
    getKey: GetPublicKeyFromAws
};
