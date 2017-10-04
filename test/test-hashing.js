'use strict';

const assert = require('chai').assert;
const sec = require('../lib/security.js').security;

describe("Hashing", function() {
  const algorithms = ['md5', 'sha1', 'sha256', 'sha512'];

  algorithms.forEach(function testAlgorithm(algorithm) {
    it(`works with the ${algorithm} algorithm`, function(done) {
      const text = 'This is test text';
      return sec({act:'hash', params: {algorithm:algorithm, text: text}}, function(err, result) {
        assert.isUndefined(err);
        assert.isDefined(result.hashvalue);
        return done();
      });
    });
  });

});
