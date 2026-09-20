'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Credential, algorithm } = require('../js/index.js');

const root = path.join(__dirname, '..');

const loadVectors = (name) => JSON.parse(fs.readFileSync(path.join(root, 'vectors', name), 'utf8'));

/** Odtwarza poświadczenie, którym podpisuje dany wektor. */
function signingCredential(vectors, testCase) {
    const key = vectors.keys[testCase.algorithm === 'ed25519' ? 'ed25519' : 'hmac'];
    const material = Buffer.from(key.key_base64 ?? key.seed_base64, 'base64');

    return new Credential(testCase.key_id, material, testCase.algorithm);
}

/** Klucz w postaci, w jakiej widzi go weryfikator: publiczny dla ed25519, wspólny dla HMAC. */
function verifyingCredential(vectors, testCase) {
    const signing = signingCredential(vectors, testCase);
    if (testCase.algorithm !== 'ed25519') return signing;

    return new Credential(testCase.key_id, algorithm.ed25519PublicKeyFrom(signing.key), 'ed25519');
}

/**
 * Wektor może opisać swoje ciało zamiast je wklejać — inaczej przypadek 256 KiB
 * zdominowałby plik.
 */
function bodyOf(testCase) {
    if (testCase.body_repeat) return testCase.body_repeat.chunk.repeat(testCase.body_repeat.times);

    return testCase.body;
}

module.exports = { root, loadVectors, signingCredential, verifyingCredential, bodyOf };
