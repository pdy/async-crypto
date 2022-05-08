'use strict'

const Crypto = require('crypto');

/**
 * @param{Buffer} priv
 * @param{Buffer} pub
 * @param{Function} cb
 */
function rsaTestSignVerifyDER(priv, pub, cb){

  const privKey = Crypto.createPrivateKey({
    key: priv,
    format: 'der',
    type: 'pkcs1'
  });

  if(!privKey)
    return cb("Can't create privKey");

  const pubKey = Crypto.createPublicKey({
    key: pub,
    format: 'der',
    type: 'spki'
  });

  if(!pubKey)
    return cb("Can't create pubKey");

  var sign = Crypto.createSign('RSA-SHA1');
  if(!sign.write('some data to sign'))
    return cb("Can't write data to sign object");
  
  const sig = sign.sign(privKey);
  if(!sig || !Buffer.isBuffer(sig))
    return cb("Returned sig undefined or not a buffer");
  
 
  var verify = Crypto.createVerify('RSA-SHA1');
  verify.update('some data to sign');

  if(!verify.verify(pubKey, sig))
    return cb("Verification failed");

  return cb(undefined);
}

module.exports = {
  rsaTestSignVerifyDER
};
