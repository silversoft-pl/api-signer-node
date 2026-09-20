'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Credential, Params, Request, Policy, sign, signatureBaseOf, verify, structuredFields } = require('../js/index.js');
const { loadVectors } = require('./helpers.js');

// RFC 9421, Appendix B. Tych wartości nie wyprodukowała żadna z naszych
// implementacji — i właśnie dlatego są coś warte.
const vectors = loadVectors('rfc9421.json');

function requestFor() {
    const { method, url, body, headers } = vectors.request;

    return Request.fromUrl(method, url, body, headers);
}

function paramsFor(testCase) {
    const params = new Params(testCase.components);
    params.label = testCase.label;
    for (const [name, value] of Object.entries(testCase.params)) params[name] = value;

    return params;
}

for (const testCase of vectors.cases) {
    test(`${testCase.name}: signature base`, () => {
        assert.equal(signatureBaseOf(requestFor(), paramsFor(testCase)), testCase.signature_base);
    });

    test(`${testCase.name}: Signature-Input`, () => {
        const params = paramsFor(testCase);
        const line = `${params.label}=${structuredFields.serializeInnerList(params.components, params.ordered())}`;
        assert.equal(line, testCase.signature_input);
    });

    if (!testCase.key) continue;

    const key = vectors.keys[testCase.key];

    test(`${testCase.name}: produces the published signature`, () => {
        const material = key.key_base64 ? Buffer.from(key.key_base64, 'base64') : key.private_pem;
        const credential = new Credential(testCase.key, material, key.alg);

        assert.equal(sign(credential, requestFor(), paramsFor(testCase)).Signature, testCase.signature);
    });

    test(`${testCase.name}: verifies the published signature`, () => {
        const material = key.public_pem ?? Buffer.from(key.key_base64, 'base64');
        const credential = new Credential(testCase.key, material, key.alg);
        const request = requestFor();
        request.setHeader('Signature-Input', testCase.signature_input);
        request.setHeader('Signature', testCase.signature);

        const result = verify(request, credential, Policy.none());
        assert.equal(result.failed, false, result.reason ?? '');
    });
}
