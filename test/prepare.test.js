'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Credential, Request, Policy, prepare, verify } = require('../js/index.js');

const KEY = Buffer.from('a-shared-secret-of-sufficient-length-0123456789', 'utf8');
const credential = (auth = 'signed') => new Credential('service-a', KEY, 'hmac-sha256', auth);

test('sends exactly the bytes it signed', () => {
    const signed = prepare(credential(), 'POST', 'https://api.example.com/v1/users/update', {
        user: { id: 1, name: 'Żółć' },
    });

    assert.equal(signed.body, '{"user":{"id":1,"name":"Żółć"}}');
    assert.equal(signed.headers['Content-Type'], 'application/json');

    const request = Request.fromUrl('POST', signed.url, signed.body, signed.headers);
    assert.equal(verify(request, credential(), new Policy()).failed, false);
});

test('derives path and query from the full URL', () => {
    const signed = prepare(credential(), 'GET', 'https://service.example.com/v1/items/list?from=2025-01-01&q=a%20b');
    const request = Request.fromUrl('GET', signed.url, signed.body, signed.headers);

    assert.equal(verify(request, credential(), new Policy()).failed, false);
});

test('does not override a caller-supplied Content-Type', () => {
    const signed = prepare(credential(), 'POST', 'https://x.example/a', '<xml/>', {
        headers: { 'Content-Type': 'application/xml' },
    });

    assert.equal(signed.headers['Content-Type'], 'application/xml');
});

test('an empty body still gets a digest, and it verifies', () => {
    const signed = prepare(credential(), 'GET', 'https://auth.example.com/v1/session/token');

    assert.equal(signed.body, '');
    assert.equal(signed.headers['Content-Digest'], 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');

    const request = Request.fromUrl('GET', signed.url, '', signed.headers);
    assert.equal(verify(request, credential(), new Policy()).failed, false);
});

test('legacy mode yields the old header and the same call shape', () => {
    const signed = prepare(credential('legacy'), 'POST', 'https://x.example/a', { x: 1 });

    assert.deepEqual(Object.keys(signed.headers).sort(), ['Api-Authorization', 'Content-Type']);
    assert.equal(signed.headers['Api-Authorization'], credential('legacy').legacyHeader());
    assert.equal(signed.body, '{"x":1}');
});

test('toFetchOptions carries body, method and headers', () => {
    const signed = prepare(credential(), 'POST', 'https://x.example/a', { x: 1 });
    const options = signed.toFetchOptions({ headers: { 'X-Trace': 'abc' } });

    assert.equal(options.method, 'POST');
    assert.equal(options.body, signed.body);
    assert.equal(options.headers['X-Trace'], 'abc');
    assert.ok(options.headers['Signature-Input']);
});

test('rejects a body it cannot serialize', () => {
    assert.throws(() => prepare(credential(), 'POST', 'https://x.example/a', 42));
});
