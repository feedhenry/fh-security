'use strict';

const assert = require('chai').assert;
const sec = require('../../lib/security.js').security;

describe("Key generation", function() {
  it("generates AES key with keysize 128}", function(done) {
    return sec({act:'keygen', params:{algorithm: 'AES', keysize: 128}}, function(err, result) {
      assert.isUndefined(err);
      assert.isNotNull(result.secretkey);
      assert.isNotNull(result.iv);
      return done(err);
    });
  });

  it("generates RSA key with keysize 1024", function(done) {
    return sec({act:'keygen', params:{algorithm:'RSA', keysize: 1024}}, function(err, result) {
      assert.isUndefined(err);
      assert.isNotNull(result.public);
      assert.isNotNull(result.private);
      assert.isNotNull(result.modulu);
      return done(err);
    });
  });

  it("fails with no params object", function(done) {
    return sec({act:'keygen'}, function(err, result) {
      assert.isDefined(err);
      return done();
    });
  });

  it("fails with no keysize param", function(done) {
    return sec({act:'keygen', params: {algorithm:'AES'}}, function(err, result) {
      assert.isDefined(err);
      return done();
    });
  });
});
