'use strict';

const crypto = require('node:crypto');

const DEFAULT_COMPONENTS = ['@method', '@path', '@query', 'content-digest'];
const DEFAULT_LIFETIME = 300;
const ORDER = ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag'];

class Params {
    constructor(components = null) {
        this.components = components ?? [...DEFAULT_COMPONENTS];
        this.label = 'sig1';
        this.created = null;
        this.expires = null;
        this.keyid = null;
        this.alg = null;
        this.nonce = null;
        this.tag = null;
    }

    /** Uzupełnia created, expires, nonce, keyid i alg tam, gdzie nie zostały ustawione. */
    withDefaults(credential, lifetime = DEFAULT_LIFETIME) {
        const filled = Object.assign(new Params(this.components), this);
        filled.created = this.created ?? Math.floor(Date.now() / 1000);
        filled.expires = this.expires ?? filled.created + lifetime;
        filled.nonce = this.nonce ?? crypto.randomBytes(8).toString('hex');
        filled.keyid = this.keyid ?? credential.keyId;
        filled.alg = this.alg ?? credential.alg;

        return filled;
    }

    /** Parametry podpisu w kolejności serializacji. */
    ordered() {
        const ordered = {};
        for (const name of ORDER) {
            if (this[name] !== null && this[name] !== undefined) ordered[name] = this[name];
        }

        return ordered;
    }
}

Params.DEFAULT_COMPONENTS = DEFAULT_COMPONENTS;
Params.DEFAULT_LIFETIME = DEFAULT_LIFETIME;

module.exports = { Params };
