'use strict'

var assert = require('assert').strict;
const DATA = require('./data.js');
const async_crypto = require('../index.js');
const rsa = async_crypto.rsa;

const node_crypto = require('crypto');


function cleanup(err, eventType) {
  console.log("Exiting: " + eventType);
}

[`exit`, `SIGINT`, `SIGUSR1`, `SIGUSR2`, `uncaughtException`, `SIGTERM`].forEach((eventType) => {
  process.on(eventType, cleanup.bind(null, eventType));
})

describe('RSA Key', function () {
  describe('#createKey()', function () {
  
    it('3072 ok', function(done) {

      rsa.key.create(3072, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        done();
      });

    });
    
    it('3071 should return err', function(done) {

      rsa.key.create(3071, function(err, priv, pub) {
        assert.ok(err, "Returned err should not be undefined"); 
        assert.equal(priv, undefined, "Returned priv not a undefined");
        assert.equal(pub, undefined, "Returned pub not a undefined");
        done();
      });

    });
  });

  describe('#pemPrivToDer()', function () {
    it('should succeed with correct key', function (done) {
    
      rsa.key.pemPrivToDer(DATA.RSA_PEM_PRIV, (err, der) => {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(der), "Converted DER not a buffer");
        assert.ok(der.equals(DATA.RSA_DER_PRIV), "Converted DER not equal to expected");
        done();
      });

    });

    it('should fail with public key', function (done) {
    
      rsa.key.pemPrivToDer(DATA.RSA_PEM_PUB, (err, der) => {
        assert.ok(err, "Returned err should not be null"); 
        assert.equal(der, undefined, "Returned der not a undefined");
        done();
      });

    });
  });

  describe('#pemPubToDer()', function() {
    it('should succeed with correct key', function(done) {

      rsa.key.pemPubToDer(DATA.RSA_PEM_PUB, (err, der) => {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(der), "Converted DER not a buffer");
        assert.ok(der.equals(DATA.RSA_DER_PUB), "Converted DER not equal o expected");
        done();
      });

    });

    it('should fail with priv key', function(done) {
      
      rsa.key.pemPubToDer(DATA.RSA_PEM_PRIV, (err, der) => {
        assert.ok(err, "Returned err should not be undefined");
        assert.equal(der, undefined, "Returned der not a undefine");
        done();
      });

    });

  });
});
