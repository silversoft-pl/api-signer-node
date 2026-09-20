'use strict';

const algorithm = require('./algorithm');
const { Params } = require('./params');

/**
 * Wymagania weryfikatora wykraczające poza sam podpis.
 *
 * Poprawny podpis obejmujący zbyt mało komponentów jest bezwartościowy: żądanie
 * pokrywające samo `@method` da się odtworzyć wobec dowolnej ścieżki z dowolną
 * treścią. Polityka jest więc częścią protokołu, nie opcją.
 */
class Policy {
    constructor(options = {}) {
        this.requiredComponents = options.requiredComponents ?? ['@method', '@path', '@query', 'content-digest'];
        this.requiredParams = options.requiredParams ?? ['keyid', 'created', 'expires', 'alg'];
        this.allowedAlgorithms = options.allowedAlgorithms ?? [...algorithm.SUPPORTED];
        this.maxLifetime = options.maxLifetime ?? Params.DEFAULT_LIFETIME;
        this.clockSkew = options.clockSkew ?? 30;
        this.requiredTag = options.requiredTag ?? null;
        this.nonceStore = options.nonceStore ?? null;
        this.now = options.now ?? null;
    }

    /** Weryfikuje wyłącznie podpis. Tylko do wektorów testowych. */
    static none() {
        return new Policy({ requiredComponents: [], requiredParams: [], maxLifetime: 0 });
    }

    currentTime() {
        return this.now ?? Math.floor(Date.now() / 1000);
    }
}

module.exports = { Policy };
