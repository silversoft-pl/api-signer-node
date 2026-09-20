'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Request, components, ApiSignerError } = require('../js/index.js');

const request = (url, headers = {}) => Request.fromUrl('POST', url, '', headers);

// RFC 9421 §2.2.7: przy braku query stringu wartością komponentu jest samo
// wiodące „?”. Co najmniej jedna niezależna implementacja robi to źle,
// dlatego przypadek jest tu przypięty.
test('@query of a request without a query string is a lone question mark', () => {
    assert.equal(components.value('@query', request('https://example.com/foo')), '?');
    assert.equal(components.value('@query', request('https://example.com/foo?')), '?');
});

test('@query keeps percent-encoding untouched', () => {
    const value = components.value('@query', request('https://example.com/p?param=value&baz=bat%2Dman'));

    assert.equal(value, '?param=value&baz=bat%2Dman');
});

// RFC 9421 §2.2.6: pusta ścieżka to pojedynczy ukośnik.
test('@path of a request without a path is a single slash', () => {
    assert.equal(components.value('@path', request('https://example.com')), '/');
});

test('@method is upper-cased', () => {
    assert.equal(components.value('@method', Request.fromUrl('post', 'https://example.com/a')), 'POST');
});

test('@authority is lower-cased and keeps a non-default port', () => {
    assert.equal(components.value('@authority', request('https://Example.COM:8443/a')), 'example.com:8443');
});

test('@query-param decodes the named parameter', () => {
    const r = request('https://example.com/p?param=value&Pet=dog&e=a%20b');

    assert.equal(components.value('@query-param;name="Pet"', r), 'dog');
    assert.equal(components.value('@query-param;name="e"', r), 'a b');
});

test('covering a header the request does not carry is an error, not an empty line', () => {
    assert.throws(() => components.value('x-missing', request('https://example.com/a')), ApiSignerError);
});

test('@status is refused because this library signs requests', () => {
    assert.throws(() => components.value('@status', request('https://example.com/a')), ApiSignerError);
});

test('the ESM entry point exposes the same named exports as the CommonJS one', async () => {
    const esm = await import('../index.mjs');
    const cjs = require('../js/index.js');

    for (const name of Object.keys(cjs)) {
        assert.equal(typeof esm[name], typeof cjs[name], `named export "${name}" is missing from index.mjs`);
    }
});
