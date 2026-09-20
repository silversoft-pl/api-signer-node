'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Request, keyIdOf } = require('../js/index.js');

const cases = [
    ['signed', { 'Signature-Input': 'sig1=("@method");keyid="service-a";created=1' }, 'service-a'],
    ['key id with a space', { 'Signature-Input': 'sig1=("@method");keyid="my service"' }, 'my service'],
    ['second signature carries the key id', { 'Signature-Input': 'proxy=("@method"), sig1=("@method");keyid="service-a"' }, 'service-a'],
    ['signed without a key id', { 'Signature-Input': 'sig1=("@method");created=1' }, null],
    ['malformed signature input', { 'Signature-Input': 'sig1=("@method' }, null],
    ['legacy', { 'Api-Authorization': 'c2VydmljZS1hfHNla3JldA==' }, 'service-a'],
    ['legacy without a separator', { 'Api-Authorization': 'c2VydmljZS1h' }, null],
    ['legacy with an empty name', { 'Api-Authorization': 'fHNla3JldA==' }, null],
    ['nothing at all', {}, null],
];

for (const [name, headers, expected] of cases) {
    test(`keyIdOf: ${name}`, () => {
        assert.equal(keyIdOf(new Request('POST', '/a', '', '', headers)), expected);
    });
}

test('keyIdOf: the signed scheme takes precedence over the legacy header', () => {
    const request = new Request('POST', '/a', '', '', {
        'Signature-Input': 'sig1=("@method");keyid="New"',
        'Api-Authorization': 'T2xkfHNlY3JldA==',
    });

    assert.equal(keyIdOf(request), 'New');
});
