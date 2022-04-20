'use strict';

const addon = require('../build/Release/async-crypto.node')

/**
 * @param {Buffer} buffer
 * @param {function} callback(err, buffer)
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

/**
 * @return {string}
 */
function getOpenSSLVersion() {
  return addon.getOpenSSLVersion();
}

module.exports = {
  reverseByteBuffer: reverseByteBuffer,
  getOpenSSLVersion: getOpenSSLVersion,
  rsa: {
    pemPrivKeyToDer: rsa_pemPrivKeyToDer
  }
};



