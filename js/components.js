'use strict';

const { ApiSignerError } = require('./errors');
const sf = require('./structured-fields');

const DERIVED = ['@method', '@target-uri', '@authority', '@scheme', '@request-target', '@path', '@query', '@query-param'];

function requireValue(value, component) {
    if (!value) throw new ApiSignerError(`Request carries no value for "${component}".`);

    return value;
}

function headerValue(name, request) {
    if (!/^[a-z0-9!#$%&'*+\-.^_`|~]+$/.test(name)) {
        throw new ApiSignerError(`Invalid component identifier "${name}".`);
    }

    const value = request.header(name);
    if (value === null) throw new ApiSignerError(`Request has no "${name}" header to cover.`);

    return value.trim();
}

function queryParam(request, params) {
    if (typeof params.name !== 'string') {
        throw new ApiSignerError('@query-param requires a "name" parameter.');
    }

    const wanted = decodeURIComponent(params.name);
    for (const pair of request.query.split('&')) {
        if (pair === '') continue;
        const index = pair.indexOf('=');
        const name = index === -1 ? pair : pair.slice(0, index);
        if (decodeURIComponent(name) === wanted) {
            return index === -1 ? '' : decodeURIComponent(pair.slice(index + 1));
        }
    }

    throw new ApiSignerError(`Request has no query parameter "${wanted}" to cover.`);
}

function value(component, request) {
    const semicolon = component.indexOf(';');
    const name = semicolon === -1 ? component : component.slice(0, semicolon);
    const params = semicolon === -1 ? {} : sf.parseParams(component.slice(semicolon));

    if (name === '' || name[0] !== '@') return headerValue(name, request);

    switch (name) {
        case '@method': return request.method;
        case '@authority': return requireValue(request.authority, '@authority');
        case '@scheme': return requireValue(request.scheme, '@scheme');
        case '@path': return request.path;
        case '@query': return '?' + request.query;
        case '@request-target': return request.requestTarget();
        case '@target-uri':
            return `${requireValue(request.scheme, '@target-uri')}://${requireValue(request.authority, '@target-uri')}${request.requestTarget()}`;
        case '@query-param': return queryParam(request, params);
        case '@status':
            throw new ApiSignerError('@status applies to responses, which this library does not sign.');
        default:
            throw new ApiSignerError(`Unknown derived component "${name}".`);
    }
}

module.exports = { value, DERIVED };
