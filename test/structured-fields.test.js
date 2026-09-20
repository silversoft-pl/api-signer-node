'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const sf = require('../js/structured-fields.js');
const { ApiSignerError } = require('../js/errors.js');

test('round-trips an inner list with parameters', () => {
    const components = ['@method', '@path', '@query', 'content-digest'];
    const params = { created: 1, expires: 2, keyid: 'my service', alg: 'hmac-sha256' };
    const line = sf.serializeInnerList(components, params);

    assert.equal(line, '("@method" "@path" "@query" "content-digest");created=1;expires=2;keyid="my service";alg="hmac-sha256"');
    assert.deepEqual(sf.parseInnerList(line), { items: components, params });
});

test('escapes and unescapes quotes and backslashes', () => {
    const value = 'a"b\\c';
    const line = sf.serializeInnerList(['@method'], { keyid: value });

    assert.equal(line, '("@method");keyid="a\\"b\\\\c"');
    assert.equal(sf.parseInnerList(line).params.keyid, value);
});

test('keeps dictionary member values verbatim', () => {
    const raw = 'sig1=("@method"  "@path");created=1';

    assert.equal(sf.parseDictionary(raw).sig1, '("@method"  "@path");created=1');
});

test('parses an empty inner list', () => {
    assert.deepEqual(sf.parseInnerList('();created=1').items, []);
});

test('parses byte sequences', () => {
    const raw = crypto.randomBytes(32);

    assert.deepEqual(sf.parseParams(';v=' + sf.serializeByteSequence(raw)).v, raw);
});

test('rejects non-ASCII in strings', () => {
    assert.throws(() => sf.serializeString('Żółć'), ApiSignerError);
});

const malformed = [
    'sig1=("@method";created=1',
    'sig1=("@method);created=1',
    'sig1=("@method");created=',
    'sig1=(@method);created=1',
    'sig1=("@method");;',
    '=("@method")',
    'sig1=:not base64!:',
    'sig1=("@method") trailing',
];

for (const input of malformed) {
    test(`rejects malformed input cleanly: ${input}`, () => {
        assert.throws(
            () => {
                const members = sf.parseDictionary(input);
                for (const value of Object.values(members)) sf.parseInnerList(value);
            },
            (error) => error instanceof ApiSignerError,
        );
    });
}

test('never throws anything but ApiSignerError on random bytes', () => {
    for (let i = 0; i < 2000; i++) {
        const input = crypto.randomBytes(1 + (i % 40)).toString('latin1');
        try {
            const members = sf.parseDictionary(input);
            for (const value of Object.values(members)) sf.parseInnerList(value);
        } catch (error) {
            assert.ok(error instanceof ApiSignerError, `unexpected ${error.name} for ${JSON.stringify(input)}`);
        }
    }
});
