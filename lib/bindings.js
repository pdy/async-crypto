'use strict';

const addon = require('../build/Release/async-crypto.node')

function init() {
  return addon.init();
}

function cleanup() {
  return addon.cleanup();
}

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
 * @param {Buffer} derPriv
 * @param {function} callback
 */
function rsa_derPrivKeyToPem(derPriv, callback) {
  addon.rsa_derPrivKeyToPem(derPriv, callback);
}

/**
 * @return {string}
 */
function getOpenSSLVersion() {
  return addon.getOpenSSLVersion();
}

module.exports = {
  init : init,
  cleanup : cleanup,
  reverseByteBuffer: reverseByteBuffer,
  getOpenSSLVersion: getOpenSSLVersion,
  
  rsa: {
    pemPrivKeyToDer: rsa_pemPrivKeyToDer,
    derPrivKeyToPem: rsa_derPrivKeyToPem
  }
};



