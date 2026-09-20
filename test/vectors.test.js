'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Credential, Params, Request, Policy, sign, signatureBaseOf, verify } = require('../js/index.js');
const { loadVectors, signingCredential, verifyingCredential, bodyOf } = require('./helpers.js');

// Przypadki, których RFC 9421 nie obejmuje, a które występują w praktyce.
// Powstają z implementacji PHP; Node ma je odtworzyć co do bajta.
const vectors = loadVectors('testvectors.json');

function paramsFor(testCase) {
    const params = new Params(testCase.components);
    params.label = testCase.label;
    for (const [name, value] of Object.entries(testCase.params)) params[name] = value;

    return params;
}

for (const testCase of vectors.cases) {
    test(`${testCase.name}: signature base`, () => {
        const request = Request.fromUrl(testCase.method, testCase.url, bodyOf(testCase));
        request.setHeader('content-digest', testCase.headers['Content-Digest']);

        assert.equal(signatureBaseOf(request, paramsFor(testCase)), testCase.signature_base);
    });

    test(`${testCase.name}: headers`, () => {
        const request = Request.fromUrl(testCase.method, testCase.url, bodyOf(testCase));
        const headers = sign(signingCredential(vectors, testCase), request, paramsFor(testCase));

        assert.deepEqual(headers, testCase.headers);
    });

    test(`${testCase.name}: verifies`, () => {
        const request = Request.fromUrl(testCase.method, testCase.url, bodyOf(testCase), testCase.headers);
        const policy = new Policy({ now: testCase.params.created });

        const result = verify(request, verifyingCredential(vectors, testCase), policy);
        assert.equal(result.failed, false, result.reason ?? '');
    });
}

test('legacy credential produces the old Api-Authorization header', () => {
    const credential = new Credential(
        vectors.legacy.key_id,
        Buffer.from(vectors.legacy.key_base64, 'base64'),
        'hmac-sha256',
        'legacy'
    );

    assert.equal(credential.legacyHeader(), vectors.legacy.header);
    assert.deepEqual(sign(credential, Request.fromUrl('POST', 'https://x.example/a')), {
        'Api-Authorization': vectors.legacy.header,
    });
});
