'use strict';

const crypto = require('node:crypto');
const { ApiSignerError } = require('./errors');
const { Credential } = require('./credential');

const SUPPORTED = [Credential.ALG_HMAC_SHA256, Credential.ALG_ED25519];

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function ed25519PrivateKey(key) {
    if (key.includes('-----BEGIN ')) {
        return crypto.createPrivateKey({ key: key.toString('utf8'), format: 'pem' });
    }
    // 64-bajtowy klucz prywatny to ziarno || klucz publiczny; sodium i Node wyprowadzają z ziarna.
    const seed = key.length === 64 ? key.subarray(0, 32) : key;
    if (seed.length !== 32) {
        throw new ApiSignerError('Ed25519 private key must be a 32-byte seed, a 64-byte secret key or a PEM.');
    }

    return crypto.createPrivateKey({
        key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
        format: 'der',
        type: 'pkcs8',
    });
}

function ed25519PublicKey(key) {
    if (key.includes('-----BEGIN ')) {
        return crypto.createPublicKey({ key: key.toString('utf8'), format: 'pem' });
    }
    if (key.length !== 32) {
        throw new ApiSignerError('Ed25519 public key must be 32 bytes or a PEM.');
    }

    return crypto.createPublicKey({
        key: Buffer.concat([SPKI_ED25519_PREFIX, key]),
        format: 'der',
        type: 'spki',
    });
}

/**
 * Wyprowadza klucz publiczny Ed25519 do przekazania weryfikatorom, jako surowe
 * 32 bajty. Przyjmuje ziarno, klucz prywatny albo PEM.
 */
function ed25519PublicKeyFrom(privateKey) {
    const key = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, 'utf8');
    const der = crypto.createPublicKey(ed25519PrivateKey(key)).export({ format: 'der', type: 'spki' });

    return der.subarray(-32);
}

function sign(base, credential) {
    const message = Buffer.from(base, 'utf8');

    if (credential.alg === Credential.ALG_HMAC_SHA256) {
        return crypto.createHmac('sha256', credential.key).update(message).digest();
    }
    if (credential.alg === Credential.ALG_ED25519) {
        return crypto.sign(null, message, ed25519PrivateKey(credential.key));
    }

    throw new ApiSignerError(`Unsupported algorithm "${credential.alg}".`);
}

function verify(base, signature, credential) {
    const message = Buffer.from(base, 'utf8');

    if (credential.alg === Credential.ALG_HMAC_SHA256) {
        const expected = crypto.createHmac('sha256', credential.key).update(message).digest();
        return expected.length === signature.length && crypto.timingSafeEqual(expected, signature);
    }
    if (credential.alg === Credential.ALG_ED25519) {
        if (signature.length !== 64) return false;
        return crypto.verify(null, message, ed25519PublicKey(credential.key), signature);
    }

    throw new ApiSignerError(`Unsupported algorithm "${credential.alg}".`);
}

module.exports = { sign, verify, ed25519PublicKeyFrom, SUPPORTED };
