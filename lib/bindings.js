'use strict';

const addon = require('../build/Release/async-crypto.node')

/*
function init() {
  return addon.init();
}

function cleanup() {
  return addon.cleanup();
}
*/

/**
 * @param {number} keyBits
 * @param {function} callback(err, derPrivBuffer, derPubBuffer)
 */
function rsa_createKey(keyBits, callback) {
  return addon.rsa_createKey(keyBits, callback);
}

/**
 * @param {number} keyBits
 * @param {function} callback(err, pemPrivString, pemPubString)
 */
function rsa_createKeyPem(keyBits, callback) {
  return addon.rsa_createKeyPem(keyBits, callback);
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
 * @param {string} pemPub RSA PEM Private key
 * @param {function} callback
 */
function rsa_pemPubKeyToDer(pemPub, callback) {
  return addon.rsa_pemPubKeyToDer(pemPub, callback);
}

/**
 * @param {Buffer} derPub
 * @param {function} callback
 */
function rsa_derPubKeyToPem(derPub, callback) {
  return addon.rsa_derPubKeyToPem(derPub, callback);
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
  getOpenSSLVersion,
  
  rsa: {
    key: {
      create: rsa_createKey,
      createPem: rsa_createKeyPem,
      pemPrivToDer: rsa_pemPrivKeyToDer,
      derPrivToPem: rsa_derPrivKeyToPem,
      pemPubToDer: rsa_pemPubKeyToDer,
      derPubToPem: rsa_derPubKeyToPem
    },

    signSHA256: rsa_signSHA256,
    verifySHA256: rsa_verifySHA256
  }
};



