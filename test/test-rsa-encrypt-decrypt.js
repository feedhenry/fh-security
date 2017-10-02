'use strict';

const assert = require('chai').assert;
const sec = require('../lib/security.js').security;

describe("RSA encrypt/decrypt", function() {
  const plaintext = 'This is test text';

  it('works successfully with a keysize of 1024', function(done) {
    return sec({act:'keygen', params:{algorithm:'RSA', keysize: 1024}}, function(err, result) {
      assert.isUndefined(err);

      return sec({act:'encrypt', params:{algorithm:'RSA', plaintext:plaintext, public: result.public}}, function(e, r) {
        assert.isUndefined(e);

        return sec({act:'decrypt', params:{algorithm:'RSA', ciphertext:r.ciphertext, private: result.private}}, function(de, dr) {
          assert.isUndefined(de);
          assert.equal(plaintext, dr.plaintext);
          return done();
        });
      });
    });
  });
});
