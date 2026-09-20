'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Credential, Request, Policy, prepare, verify } = require('../js/index.js');

const credential = () => new Credential('service-a', crypto.randomBytes(32));

function randomCase(rng) {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    const paths = ['/api/a/b', '/v1/users/update_profile', '/x', '/a/b/c-d_e', '/'];
    const queries = ['', '?a=1', '?a=1&b=2', '?q=' + encodeURIComponent('a b ż')];

    return {
        method: methods[rng() % methods.length],
        url: 'https://host.example' + paths[rng() % paths.length] + queries[rng() % queries.length],
        body: rng() % 3 === 0 ? '' : JSON.stringify({ n: rng(), s: 'żółć'.repeat(rng() % 5) }),
    };
}

test('anything it signs, it verifies', () => {
    let seed = 1;
    const rng = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);

    for (let i = 0; i < 200; i++) {
        const c = credential();
        const spec = randomCase(rng);
        const signed = prepare(c, spec.method, spec.url, spec.body);
        const request = Request.fromUrl(spec.method, signed.url, signed.body, signed.headers);

        const result = verify(request, c, new Policy());
        assert.equal(result.failed, false, `${spec.method} ${spec.url}: ${result.reason}`);
    }
});

test('changing a single byte anywhere breaks the signature', () => {
    const c = credential();
    const url = 'https://host.example/v1/users/update?a=1';
    const body = '{"user":{"id":1}}';
    const signed = prepare(c, 'POST', url, body);

    const mutations = [
        ['method', () => Request.fromUrl('PUT', url, body, signed.headers)],
        ['path', () => Request.fromUrl('POST', 'https://host.example/v1/users/updatf?a=1', body, signed.headers)],
        ['query', () => Request.fromUrl('POST', 'https://host.example/v1/users/update?a=2', body, signed.headers)],
        ['body', () => Request.fromUrl('POST', url, '{"user":{"id":2}}', signed.headers)],
        ['digest', () => Request.fromUrl('POST', url, body, {
            ...signed.headers,
            'Content-Digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
        })],
        ['signature', () => Request.fromUrl('POST', url, body, {
            ...signed.headers,
            Signature: signed.headers.Signature.replace(/^sig1=:./, 'sig1=:A'),
        })],
    ];

    for (const [name, build] of mutations) {
        const result = verify(build(), c, new Policy());
        assert.equal(result.failed, true, `mutation "${name}" was accepted`);
    }
});
