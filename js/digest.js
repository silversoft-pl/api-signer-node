'use strict';

const crypto = require('node:crypto');
const { ApiSignerError } = require('./errors');
const sf = require('./structured-fields');

const ALGORITHMS = { 'sha-256': 'sha256', 'sha-512': 'sha512' };

function hashName(algorithm) {
    const name = ALGORITHMS[String(algorithm).toLowerCase()];
    if (!name) throw new ApiSignerError(`Unsupported digest algorithm "${algorithm}".`);

    return name;
}

const format = (algorithm, raw) => `${String(algorithm).toLowerCase()}=${sf.serializeByteSequence(raw)}`;

function ofString(body, algorithm = 'sha-256') {
    return format(algorithm, crypto.createHash(hashName(algorithm)).update(body ?? '').digest());
}

/**
 * Liczy skrót bez trzymania ciała w pamięci — to jest powód, dla którego duże
 * ładunki są w ogóle wykonalne.
 *
 * @param {import('node:stream').Readable} stream
 */
function ofStream(stream, algorithm = 'sha-256') {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash(hashName(algorithm));
        stream.on('error', reject);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve(format(algorithm, hash.digest())));
    });
}

const of = (body, algorithm = 'sha-256') => ofString(body, algorithm);

/**
 * Przelicza skrót z ciała i porównuje z tym, co zadeklarował nadawca. Bez tego
 * podpis obejmowałby jedynie deklarację o ciele, a nie samo ciało.
 */
function matches(headerValue, body) {
    let claimed;
    try {
        claimed = sf.parseDictionary(headerValue);
    } catch (e) {
        return false;
    }

    let checked = 0;
    for (const [algorithm, raw] of Object.entries(claimed)) {
        if (!ALGORITHMS[algorithm.toLowerCase()]) continue;

        const expected = Buffer.from(of(body, algorithm), 'utf8');
        const actual = Buffer.from(`${algorithm}=${raw}`, 'utf8');
        if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
            return false;
        }
        checked++;
    }

    return checked > 0;
}

module.exports = { of, ofString, ofStream, matches };
