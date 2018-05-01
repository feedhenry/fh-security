'use strict';

const assert = require('chai').assert;
const sec = require('../../lib/security.js').security;

describe("AES encrypt/decrypt", function() {
  const keySizes = [128, 256];
  const plaintext = 'This is test text';

  keySizes.forEach(function testUsingKeySize(keySize) {
    it(`encrypts/decrypts with keySize: ${keySize}`, function(done) {
      return sec({act:'keygen', params:{algorithm: 'AES', keysize: keySize}}, function(err, result) {
        assert.isUndefined(err);
        assert.equal(result.iv.length, 32, "IV is incorrect length: " + 32);

        return sec({act:'encrypt', params:{algorithm:'AES', key: result.secretkey, iv: result.iv, plaintext:plaintext}}, function(e, r) {
          assert.isUndefined(e);
          const ciphertext = r.ciphertext;

          return sec({act:'decrypt', params:{algorithm:'AES', key: result.secretkey, iv: result.iv, ciphertext:ciphertext}}, function(de, dr) {
            assert.equal(dr.plaintext, plaintext, "decrypted text not matching original test when encrypting with keySize: " + keySize);
            return done();
          });
        });
      });
    });
  });

  it("fails to encrypt with no keysize param", function(done) {
    return sec({act:'encrypt', params:{algorithm:'AES'}}, function(err, result) {
      assert.isDefined(err);
      return done();
    });
  });
});
