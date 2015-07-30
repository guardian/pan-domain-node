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
        s3.getObject(params, function(err, data) {
          PandaUtils.log('info', "S3 params " + params);
          if (err) {
              PandaUtils.log('error', ['Panda Auth could not contact AWS S3', err, err.stack]);
              reject(err);
          } else {
              var fileContents = data.Body.toString(PandaUtils.TEXT_ENCODING);
              PandaUtils.log('info', 'FILE ' + fileContents);
              var keyData = data.Body.toString(PandaUtils.TEXT_ENCODING).replace('publicKey=', '').trim();
              PandaUtils.log('info', 'keyData ' + keyData);

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
