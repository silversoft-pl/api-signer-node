'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
    ApiSignerError, Credential, Params, Policy, Request,
    algorithm, digest, prepare, sign, structuredFields, verify,
} = require('../js/index.js');

const KEY = 'a-shared-secret-of-sufficient-length-0123456789';
const credential = () => new Credential('service-a', KEY);

test('a scalar config entry means a legacy key', () => {
    const c = Credential.fromConfig('service-a', 'plain-key');

    assert.equal(c.isLegacy(), true);
    assert.equal(c.legacyHeader(), Buffer.from('service-a|plain-key').toString('base64'));
});

test('fromConfig decodes a base64 key', () => {
    const raw = Buffer.from([0, 255, 32, 98]);
    const c = Credential.fromConfig('service-a', { key_base64: raw.toString('base64') });

    assert.deepEqual(c.key, raw);
    assert.equal(c.auth, 'signed');
});

test('fromConfig rejects invalid base64', () => {
    assert.throws(() => Credential.fromConfig('service-a', { key_base64: 'not base64!!!' }), ApiSignerError);
});

for (const [name, args] of [
    ['empty key id', ['', 'k']],
    ['empty key', ['service-a', '']],
    ['unknown auth mode', ['service-a', 'k', 'hmac-sha256', 'maybe']],
]) {
    test(`credential rejects nonsense: ${name}`, () => {
        assert.throws(() => new Credential(...args), ApiSignerError);
    });
}

test('a legacy credential may have an empty key', () => {
    assert.equal(new Credential('service-a', '', 'hmac-sha256', 'legacy').isLegacy(), true);
});

test('ed25519 rejects unusable key material', () => {
    const short = new Credential('k', Buffer.alloc(17), 'ed25519');

    assert.throws(() => algorithm.sign('base', short), ApiSignerError);
    assert.throws(() => algorithm.verify('base', Buffer.alloc(64), short), ApiSignerError);
});

test('ed25519 rejects a signature of the wrong length', () => {
    const seed = crypto.randomBytes(32);
    const c = new Credential('k', algorithm.ed25519PublicKeyFrom(seed), 'ed25519');

    assert.equal(algorithm.verify('base', Buffer.from('too short'), c), false);
});

test('an unsupported algorithm is refused on both sides', () => {
    const c = new Credential('k', 'secret', 'rsa-pss-sha512');

    assert.throws(() => algorithm.sign('b', c), ApiSignerError);
    assert.throws(() => algorithm.verify('b', Buffer.alloc(32), c), ApiSignerError);
});

test('ed25519 accepts a PEM private key and derives the same public key as from a seed', () => {
    const seed = crypto.randomBytes(32);
    const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
    const pem = `-----BEGIN PRIVATE KEY-----\n${der.toString('base64')}\n-----END PRIVATE KEY-----\n`;

    assert.deepEqual(algorithm.ed25519PublicKeyFrom(pem), algorithm.ed25519PublicKeyFrom(seed));
});

test('digest of a body that is not a string still compares', () => {
    assert.equal(digest.matches(digest.of(''), null), true);
});

const strict = () => new Policy({ now: 1758297600 });

const rejections = [
    ['no headers', {}, 'missing Signature-Input or Signature header', Policy.none()],
    ['no signature for the label', { 'Signature-Input': 'sig1=("@method")', Signature: 'other=:AAAA:' }, 'no signature for label "sig1"', Policy.none()],
    ['signature is not a byte sequence', { 'Signature-Input': 'sig1=("@method")', Signature: 'sig1=1234' }, 'signature is not a byte sequence', Policy.none()],
    ['malformed signature input', { 'Signature-Input': 'sig1=("@method', Signature: 'sig1=:AAAA:' }, 'malformed signature headers', Policy.none()],
    ['empty signature input', { 'Signature-Input': '', Signature: 'sig1=:AAAA:' }, 'Signature-Input carries no signature', Policy.none()],
    ['covers a header that is not there', { 'Signature-Input': 'sig1=("x-absent")', Signature: 'sig1=:AAAA:' }, 'cannot rebuild signature base', Policy.none()],
    ['missing required parameter', { 'Signature-Input': 'sig1=("@method" "@path" "@query" "content-digest")', Signature: 'sig1=:AAAA:' }, 'parameter "keyid" is missing', strict()],
    ['algorithm the policy does not allow', {
        'Signature-Input': 'sig1=("@method" "@path" "@query" "content-digest");keyid="service-a";created=1758297600;expires=1758297900;alg="rsa-pss-sha512"',
        Signature: 'sig1=:AAAA:',
    }, 'is not allowed', strict()],
    ['created is not an integer', {
        'Signature-Input': 'sig1=("@method" "@path" "@query" "content-digest");keyid="service-a";created="soon";expires=1758297900;alg="hmac-sha256"',
        Signature: 'sig1=:AAAA:',
    }, 'created is not an integer', strict()],
    ['expires is not an integer', {
        'Signature-Input': 'sig1=("@method" "@path" "@query" "content-digest");keyid="service-a";created=1758297600;expires="later";alg="hmac-sha256"',
        Signature: 'sig1=:AAAA:',
    }, 'expires is not an integer', strict()],
];

for (const [name, headers, expected, policy] of rejections) {
    test(`verifier rejection: ${name}`, () => {
        const request = Request.fromUrl('POST', 'https://x.example/a', '{}', headers);
        const result = verify(request, credential(), policy);

        assert.ok(String(result.reason).includes(expected), `got: ${result.reason}`);
    });
}

test('a nonce store rejects a request without a nonce', () => {
    const request = Request.fromUrl('POST', 'https://x.example/a', '{}');
    const params = new Params();
    params.created = 1758297600;
    params.expires = 1758297900;
    params.keyid = 'service-a';
    params.alg = 'hmac-sha256';

    const headers = sign(credential(), request, params);
    const received = Request.fromUrl('POST', 'https://x.example/a', '{}', headers);
    const policy = new Policy({ now: 1758297600, nonceStore: () => true });

    assert.equal(verify(received, credential(), policy).reason, 'nonce is required but missing');
});

test('defaults fill in everything a signature needs', () => {
    const params = new Params().withDefaults(credential(), 120);

    assert.equal(params.keyid, 'service-a');
    assert.equal(params.alg, 'hmac-sha256');
    assert.equal(params.expires - params.created, 120);
    assert.match(params.nonce, /^[0-9a-f]{16}$/);
    assert.equal(params.tag, null);
});

test('signing without explicit parameters produces a verifiable request', () => {
    const request = Request.fromUrl('POST', 'https://x.example/a', '{}');
    const headers = sign(credential(), request, null);
    const received = Request.fromUrl('POST', 'https://x.example/a', '{}', headers);

    assert.equal(verify(received, credential(), new Policy()).failed, false);
});

test('serializes boolean parameters', () => {
    assert.equal(structuredFields.serializeInnerList(['@method'], { flag: true, off: false }), '("@method");flag;off=?0');
    assert.deepEqual(structuredFields.parseInnerList('("@method");flag;off=?0').params, { flag: true, off: false });
});

test('headerLines matches the header count', () => {
    const signed = prepare(credential(), 'GET', 'https://x.example/a');

    assert.equal(signed.headerLines().length, Object.keys(signed.headers).length);
});
