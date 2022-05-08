'use strict'

var assert = require('assert').strict;
const data = require('./data.js');
const test_utils = require('./utils.js');
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
    
    /* // this one takes a little too much time
    it('7168', function(done) {

      rsa.key.create(7168, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    }).timeout(8000);
    
    it('6144', function(done) {

      rsa.key.create(6144, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    }).timeout(4000);
    */

    it('5120', function(done) {

      rsa.key.create(5120, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    }).timeout(4000);

    it('4096', function(done) {

      rsa.key.create(4096, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });
    it('2048', function(done) {

      rsa.key.create(2048, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });

    it('1024', function(done) {

      rsa.key.create(1024, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });

    it('3072', function(done) {

      rsa.key.create(3072, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(priv), "Private key not a buffer");
        assert.ok(Buffer.isBuffer(pub), "Public key not a buffer");
        test_utils.rsaTestSignVerifyDER(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });

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

  describe('#createKeyPem()', function () {
    
    
    it('5120', function(done) {

      rsa.key.createPem(5120, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(typeof priv === 'string', "Private key not a string");
        assert.ok(typeof pub === 'string', "Public key not a string");
        test_utils.rsaTestSignVerifyPEM(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    }).timeout(4000);

    it('4096', function(done) {

      rsa.key.createPem(4096, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(typeof priv === 'string', "Private key not a string");
        assert.ok(typeof pub === 'string', "Public key not a string");
        test_utils.rsaTestSignVerifyPEM(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });

    it('2048', function(done) {

      rsa.key.createPem(2048, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(typeof priv === 'string', "Private key not a string");
        assert.ok(typeof pub === 'string', "Public key not a string");
        test_utils.rsaTestSignVerifyPEM(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });

    it('1024', function(done) {

      rsa.key.createPem(1024, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(typeof priv === 'string', "Private key not a string");
        assert.ok(typeof pub === 'string', "Public key not a string");
        test_utils.rsaTestSignVerifyPEM(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });

    it('3072', function(done) {

      rsa.key.createPem(3072, function(err, priv, pub) {
        assert.equal(err, undefined, err);
        assert.ok(typeof priv === 'string', "Private key not a string");
        assert.ok(typeof pub === 'string', "Public key not a string");
        test_utils.rsaTestSignVerifyPEM(priv, pub, (err) => {
          assert.equal(err, undefined, err);
          done();
        });
      });

    });
    
    it('3071 should return err', function(done) {

      rsa.key.createPem(3071, function(err, priv, pub) {
        assert.ok(err, "Returned err should not be undefined"); 
        assert.equal(priv, undefined, "Returned priv not a undefined");
        assert.equal(pub, undefined, "Returned pub not a undefined");
        done();
      });

    });
  });

  describe('#pemPrivToDer()', function () {
    it('should succeed with correct key', function (done) {
    
      rsa.key.pemPrivToDer(data.RSA_PEM_PRIV, (err, der) => {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(der), "Converted DER not a buffer");
        assert.ok(der.equals(data.RSA_DER_PRIV), "Converted DER not equal to expected");
        done();
      });

    });

    it('should fail with public key', function (done) {
    
      rsa.key.pemPrivToDer(data.RSA_PEM_PUB, (err, der) => {
        assert.ok(err, "Returned err should not be null"); 
        assert.equal(der, undefined, "Returned der not a undefined");
        done();
      });

    });
  });

  describe('#pemPubToDer()', function() {
    it('should succeed with correct key', function(done) {

      rsa.key.pemPubToDer(data.RSA_PEM_PUB, (err, der) => {
        assert.equal(err, undefined, err);
        assert.ok(Buffer.isBuffer(der), "Converted DER not a buffer");
        assert.ok(der.equals(data.RSA_DER_PUB), "Converted DER not equal o expected");
        done();
      });

    });

    it('should fail with priv key', function(done) {
      
      rsa.key.pemPubToDer(data.RSA_PEM_PRIV, (err, der) => {
        assert.ok(err, "Returned err should not be undefined");
        assert.equal(der, undefined, "Returned der not a undefine");
        done();
      });

    });

  });
});
