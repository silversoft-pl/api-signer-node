'use strict';

const { ApiSignerError } = require('./errors');
const { Params } = require('./params');
const { Request } = require('./request');
const signer = require('./signer');

const JSON_REPLACER = null;

/**
 * Punkt wejścia dla klientów. Istnieje po to, żeby trzy typowe pomyłki były
 * niedostępne: ciało jest serializowane raz, ścieżka i query pochodzą z URL-a,
 * a nagłówki wychodzą kompletem.
 */
function prepare(credential, method, url, body = null, options = {}) {
    let contentType = null;

    if (body === null || body === undefined) {
        body = '';
    } else if (typeof body === 'string' || Buffer.isBuffer(body)) {
        // wysyłane tak, jak podano
    } else if (typeof body === 'object') {
        body = JSON.stringify(body, JSON_REPLACER);
        if (body === undefined) throw new ApiSignerError('Body cannot be encoded as JSON.');
        contentType = 'application/json';
    } else {
        throw new ApiSignerError('Body must be a string, a Buffer, a plain object or null.');
    }

    const headers = { ...(options.headers ?? {}) };
    const hasContentType = Object.keys(headers).some((n) => n.toLowerCase() === 'content-type');
    if (contentType !== null && !hasContentType) headers['Content-Type'] = contentType;

    const request = Request.fromUrl(method, url, body, headers);
    const signed = signer.sign(credential, request, params(credential, options));

    return new SignedRequest(request.method, url, body, { ...headers, ...signed });
}

function params(credential, options) {
    if (credential.isLegacy()) return null;

    const built = new Params(options.components ?? null);
    for (const name of ['label', 'created', 'expires', 'nonce', 'tag']) {
        if (options[name] !== undefined) built[name] = options[name];
    }

    return built.withDefaults(credential, options.lifetime ?? Params.DEFAULT_LIFETIME);
}

/**
 * Żądanie gotowe do wysłania: dokładnie te bajty, które zostały podpisane,
 * oraz nagłówki, które je podpisują.
 */
class SignedRequest {
    constructor(method, url, body, headers) {
        this.method = method;
        this.url = url;
        this.body = body;
        this.headers = headers;
    }

    /** Obiekt opcji dla fetch/undici, z domieszanymi podpisanymi nagłówkami. */
    toFetchOptions(init = {}) {
        return {
            ...init,
            method: this.method,
            body: this.body,
            headers: { ...(init.headers ?? {}), ...this.headers },
        };
    }

    /** Nagłówki jako linie „Nazwa: wartość”. */
    headerLines() {
        return Object.entries(this.headers).map(([name, value]) => `${name}: ${value}`);
    }
}

module.exports = { prepare, SignedRequest };
