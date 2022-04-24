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
  return addon.rsa_derPrivKeyToPem(derPriv, callback);
}

/**
 * @param {Buffer} data
 * @param {Buffer} derKey
 * @param {function} callback
 */
function rsa_signSHA256(data, derKey, callback) {
  return addon.rsa_signSHA256(data, derKey, callback);
}

/**
 * @param {Buffer} signature
 * @param {Buffer} data
 * @param {Buffer} derKey
 * @param {function} callback
 */
function rsa_verifySHA256(signature, data, derKey, callback) {
  return addon.rsa_verifySHA256(signature, data, derKey, callback);
}

/**
 * @return {string}
 */
function getOpenSSLVersion() {
  return addon.getOpenSSLVersion();
}

module.exports = {
  init,
  cleanup,
  reverseByteBuffer,
  getOpenSSLVersion,
  
  rsa: {
    pemPrivKeyToDer: rsa_pemPrivKeyToDer,
    derPrivKeyToPem: rsa_derPrivKeyToPem,
    signSHA256: rsa_signSHA256,
    verifySHA256: rsa_verifySHA256
  }
};



