'use strict';

const algorithm = require('./algorithm');
const digest = require('./digest');
const signatureBase = require('./signature-base');
const sf = require('./structured-fields');
const { ApiSignerError } = require('./errors');
const { Policy } = require('./policy');
const { Result } = require('./result');

function checkTiming(policy, params) {
    const now = policy.currentTime();
    const created = params.created;
    const expires = params.expires;

    if (created !== undefined) {
        if (!Number.isInteger(created)) return 'created is not an integer';
        if (created > now + policy.clockSkew) return 'created is in the future';
    }
    if (expires !== undefined) {
        if (!Number.isInteger(expires)) return 'expires is not an integer';
        if (now > expires + policy.clockSkew) return 'signature has expired';
    }
    if (policy.maxLifetime > 0 && Number.isInteger(created) && Number.isInteger(expires)) {
        if (expires - created > policy.maxLifetime) return 'signature lifetime exceeds the allowed maximum';
    }

    return null;
}

function checkPolicy(credential, policy, components, params) {
    if (credential.isLegacy()) return 'credential is configured for the legacy scheme';

    const covered = components.map((c) => c.toLowerCase());
    for (const required of policy.requiredComponents) {
        if (!covered.includes(required.toLowerCase())) return `component "${required}" is not covered`;
    }
    for (const required of policy.requiredParams) {
        if (params[required] === undefined) return `parameter "${required}" is missing`;
    }
    if (params.alg !== undefined && !policy.allowedAlgorithms.includes(params.alg)) {
        return `algorithm "${params.alg}" is not allowed`;
    }
    if (policy.requiredTag !== null && (params.tag ?? null) !== policy.requiredTag) {
        return 'tag does not match';
    }

    return checkTiming(policy, params);
}

function verifyOne(request, credential, policy, label, paramsLine, values) {
    if (values[label] === undefined) return Result.rejected(`no signature for label "${label}"`);

    let parsed;
    let signature;
    try {
        parsed = sf.parseInnerList(paramsLine);
        signature = sf.parseParams(';v=' + values[label]).v;
    } catch (e) {
        if (!(e instanceof ApiSignerError)) throw e;
        return Result.rejected(`malformed signature headers: ${e.message}`);
    }

    if (!Buffer.isBuffer(signature)) return Result.rejected('signature is not a byte sequence');

    const rejection = checkPolicy(credential, policy, parsed.items, parsed.params);
    if (rejection !== null) return Result.rejected(rejection);

    let base;
    try {
        base = signatureBase.build(parsed.items, paramsLine, request);
    } catch (e) {
        if (!(e instanceof ApiSignerError)) throw e;
        return Result.rejected(`cannot rebuild signature base: ${e.message}`);
    }

    if (parsed.params.alg !== undefined && parsed.params.alg !== credential.alg) {
        return Result.rejected('algorithm does not match the credential');
    }
    if (!algorithm.verify(base, signature, credential)) {
        return Result.rejected('signature does not match');
    }

    if (parsed.items.some((c) => c.toLowerCase() === 'content-digest')) {
        const header = request.header('content-digest');
        if (header === null || !digest.matches(header, request.body)) {
            return Result.rejected('Content-Digest does not match the body');
        }
    }

    if (policy.nonceStore !== null) {
        const nonce = parsed.params.nonce;
        if (typeof nonce !== 'string' || nonce === '') return Result.rejected('nonce is required but missing');
        const ttl = 2 * Math.max(policy.maxLifetime, 1) + policy.clockSkew;
        if (policy.nonceStore(credential.keyId, nonce, ttl) !== true) {
            return Result.rejected('nonce has already been used');
        }
    }

    return Result.accepted(label, parsed.params, parsed.items);
}

/**
 * Identyfikator klucza deklarowany przez żądanie — serwer musi go poznać, zanim
 * cokolwiek zweryfikuje. Czyta oba schematy, co jest potrzebne w okresie
 * przejściowym.
 *
 * Wartość jest z definicji nieuwierzytelniona: wybiera klucz do sprawdzenia,
 * niczego nie przyznaje.
 */
function keyIdOf(request) {
    const input = request.header('signature-input');
    if (input !== null) {
        try {
            for (const paramsLine of Object.values(sf.parseDictionary(input))) {
                const keyId = sf.parseInnerList(paramsLine).params.keyid;
                if (typeof keyId === 'string' && keyId !== '') return keyId;
            }
        } catch (e) {
            if (!(e instanceof ApiSignerError)) throw e;
            return null;
        }

        return null;
    }

    const legacy = request.header('api-authorization');
    if (legacy === null) return null;

    const decoded = Buffer.from(legacy, 'base64').toString('utf8');
    const separator = decoded.indexOf('|');

    return separator > 0 ? decoded.slice(0, separator) : null;
}

function verify(request, credential, policy = null) {
    const effective = policy ?? new Policy();

    const input = request.header('signature-input');
    const signatures = request.header('signature');
    if (input === null || signatures === null) {
        return Result.rejected('missing Signature-Input or Signature header');
    }

    let inputs;
    let values;
    try {
        inputs = sf.parseDictionary(input);
        values = sf.parseDictionary(signatures);
    } catch (e) {
        if (!(e instanceof ApiSignerError)) throw e;
        return Result.rejected(`malformed signature headers: ${e.message}`);
    }

    const labels = Object.keys(inputs);
    if (labels.length === 0) return Result.rejected('Signature-Input carries no signature');

    let last = null;
    for (const label of labels) {
        last = verifyOne(request, credential, effective, label, inputs[label], values);
        if (!last.failed) return last;
    }

    return last;
}

module.exports = { verify, keyIdOf };
