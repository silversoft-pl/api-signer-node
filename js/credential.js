'use strict';

const { ApiSignerError } = require('./errors');

const AUTH_SIGNED = 'signed';
const AUTH_LEGACY = 'legacy';
const ALG_HMAC_SHA256 = 'hmac-sha256';
const ALG_ED25519 = 'ed25519';

class Credential {
    /**
     * @param {string} keyId
     * @param {string|Buffer} key surowy materiał klucza: sekret HMAC, ziarno/klucz prywatny Ed25519 albo klucz publiczny
     * @param {string} [alg]
     * @param {string} [auth]
     */
    constructor(keyId, key, alg = ALG_HMAC_SHA256, auth = AUTH_SIGNED) {
        if (!keyId) throw new ApiSignerError('Credential requires a non-empty key id.');
        if (auth !== AUTH_SIGNED && auth !== AUTH_LEGACY) {
            throw new ApiSignerError(`Unknown auth mode "${auth}".`);
        }

        this.keyId = keyId;
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key ?? '', 'utf8');
        this.alg = alg;
        this.auth = auth;

        if (auth === AUTH_SIGNED && this.key.length === 0) {
            throw new ApiSignerError('Credential requires a non-empty key.');
        }
    }

    /**
     * Buduje poświadczenie z wpisu konfiguracyjnego, np. z `api_keys.php`
     * albo `api_keys.js`. Wartość skalarna oznacza klucz w starym schemacie.
     */
    static fromConfig(keyId, entry) {
        if (typeof entry !== 'object' || entry === null) {
            return new Credential(keyId, String(entry), ALG_HMAC_SHA256, AUTH_LEGACY);
        }

        let key;
        if (entry.key_base64 !== undefined) {
            key = Buffer.from(entry.key_base64, 'base64');
            if (key.toString('base64') !== entry.key_base64) {
                throw new ApiSignerError(`Key for "${keyId}" is not valid base64.`);
            }
        } else {
            key = entry.key ?? '';
        }

        return new Credential(keyId, key, entry.alg ?? ALG_HMAC_SHA256, entry.auth ?? AUTH_SIGNED);
    }

    isLegacy() {
        return this.auth === AUTH_LEGACY;
    }

    legacyHeader() {
        return Buffer.concat([Buffer.from(this.keyId + '|', 'utf8'), this.key]).toString('base64');
    }
}

Credential.AUTH_SIGNED = AUTH_SIGNED;
Credential.AUTH_LEGACY = AUTH_LEGACY;
Credential.ALG_HMAC_SHA256 = ALG_HMAC_SHA256;
Credential.ALG_ED25519 = ALG_ED25519;

module.exports = { Credential };
