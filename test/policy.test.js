'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Credential, Params, Request, Policy, sign, verify } = require('../js/index.js');

const KEY = Buffer.from('a-shared-secret-of-sufficient-length-0123456789', 'utf8');
const CREATED = 1758297600;

const credential = () => new Credential('service-a', KEY);

function signed(overrides = {}) {
    const body = overrides.body ?? '{"x":1}';
    const url = overrides.url ?? 'https://api.example.com/v1/users/update';
    const request = Request.fromUrl(overrides.method ?? 'POST', url, body);

    const params = new Params(overrides.components ?? null);
    params.created = overrides.created ?? CREATED;
    params.expires = overrides.expires ?? CREATED + 300;
    params.keyid = 'service-a';
    params.alg = overrides.alg ?? 'hmac-sha256';
    params.nonce = overrides.nonce ?? 'fixednonce000001';
    if (overrides.tag) params.tag = overrides.tag;

    const headers = sign(overrides.credential ?? credential(), request, params);

    return { request, headers, url, body, params };
}

/** Odtwarza żądanie tak, jak widzi je serwer, żeby dało się manipulować nagłówkami. */
function received({ url, body, headers }, mutate = (h) => h) {
    return Request.fromUrl('POST', url, body, mutate({ ...headers }));
}

const at = (now, options = {}) => new Policy({ now, ...options });

test('a well-formed signed request is accepted', () => {
    const result = verify(received(signed()), credential(), at(CREATED));
    assert.equal(result.failed, false, result.reason ?? '');
});

test('tampering with the body is rejected', () => {
    const s = signed();
    const request = Request.fromUrl('POST', s.url, '{"x":2}', s.headers);

    assert.match(verify(request, credential(), at(CREATED)).reason, /Content-Digest/);
});

test('replaying the signature on another path is rejected', () => {
    const s = signed();
    const request = Request.fromUrl('POST', 'https://api.example.com/v1/users/delete', s.body, s.headers);

    assert.equal(verify(request, credential(), at(CREATED)).reason, 'signature does not match');
});

test('replaying the signature with an added query string is rejected', () => {
    const s = signed();
    const request = Request.fromUrl('POST', s.url + '?admin=1', s.body, s.headers);

    assert.equal(verify(request, credential(), at(CREATED)).reason, 'signature does not match');
});

test('editing a signature parameter is rejected', () => {
    const s = signed();
    const request = received(s, (h) => ({
        ...h,
        'Signature-Input': h['Signature-Input'].replace(String(CREATED), String(CREATED + 1)),
    }));

    assert.equal(verify(request, credential(), at(CREATED)).reason, 'signature does not match');
});

test('covering too few components is rejected even though the signature is valid', () => {
    const s = signed({ components: ['@method'] });
    const result = verify(received(s), credential(), at(CREATED));

    assert.equal(result.reason, 'component "@path" is not covered');
});

test('an expired signature is rejected', () => {
    const s = signed();

    assert.equal(verify(received(s), credential(), at(CREATED + 400)).reason, 'signature has expired');
});

test('a signature created in the future is rejected', () => {
    const s = signed({ created: CREATED + 600, expires: CREATED + 900 });

    assert.equal(verify(received(s), credential(), at(CREATED)).reason, 'created is in the future');
});

test('a lifetime beyond the policy maximum is rejected', () => {
    const s = signed({ expires: CREATED + 3600 });

    assert.equal(verify(received(s), credential(), at(CREATED)).reason, 'signature lifetime exceeds the allowed maximum');
});

test('a declared algorithm that does not match the credential is rejected', () => {
    const s = signed();
    const request = received(s, (h) => ({
        ...h,
        'Signature-Input': h['Signature-Input'].replace('hmac-sha256', 'ed25519'),
    }));

    assert.equal(verify(request, credential(), at(CREATED)).reason, 'algorithm does not match the credential');
});

test('a wrong key is rejected', () => {
    const other = new Credential('service-a', Buffer.from('a-different-secret-0123456789abcdef', 'utf8'));

    assert.equal(verify(received(signed()), other, at(CREATED)).reason, 'signature does not match');
});

test('a mismatched tag is rejected', () => {
    const s = signed({ tag: 'api-service-api' });
    const policy = at(CREATED, { requiredTag: 'other-service-api' });

    assert.equal(verify(received(s), credential(), policy).reason, 'tag does not match');
});

test('missing signature headers are rejected', () => {
    const request = Request.fromUrl('POST', 'https://api.example.com/v1/users/update', '{}');

    assert.equal(verify(request, credential(), at(CREATED)).reason, 'missing Signature-Input or Signature header');
});

test('a credential configured for the legacy scheme never verifies a signature', () => {
    const legacy = new Credential('service-a', KEY, 'hmac-sha256', 'legacy');

    assert.equal(verify(received(signed()), legacy, at(CREATED)).reason, 'credential is configured for the legacy scheme');
});

test('a reused nonce is rejected when a nonce store is configured', () => {
    const seen = new Set();
    const store = (keyId, nonce) => {
        const key = `${keyId}:${nonce}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    };

    const s = signed();
    assert.equal(verify(received(s), credential(), at(CREATED, { nonceStore: store })).failed, false);
    assert.equal(verify(received(s), credential(), at(CREATED, { nonceStore: store })).reason, 'nonce has already been used');
});
