'use strict';

const addon = require('../build/Release/async-crypto.node')

/**
 * @param {Buffer} buffer
 * @param {function} callback
 */
function reverseByteBuffer(buffer, callback) {
  return addon.reverseByteBuffer(buffer, callback);
}


/**
 * @param {string} pemPriv RSA PEM Private key
 * @param {function} callback
 */
function rsa_pemPrivKeyToDer(pemPriv, callback) {
  return addon.rsa_pemPrivKeyToDer(pemPriv, callback);
}

module.exports = {
  reverseByteBuffer: reverseByteBuffer,
  rsa: {
    pemPrivKeyToDer: rsa_pemPrivKeyToDer
  }
};



