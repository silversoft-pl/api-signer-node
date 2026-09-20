'use strict';

const { ApiSignerError } = require('./errors');

class Request {
    /**
     * @param {string} method
     * @param {string} path ścieżka bezwzględna
     * @param {string} [query] bez wiodącego „?”
     * @param {string|Buffer|null} [body]
     * @param {Object<string,string>} [headers]
     * @param {string} [authority] host[:port]
     * @param {string} [scheme]
     */
    constructor(method, path, query = '', body = null, headers = {}, authority = '', scheme = '') {
        this.method = String(method).toUpperCase();
        this.path = path === '' ? '/' : path;
        this.query = String(query).replace(/^\?/, '');
        this.body = body;
        this.authority = String(authority).toLowerCase();
        this.scheme = String(scheme).toLowerCase();
        this.headers = {};

        for (const [name, value] of Object.entries(headers)) {
            this.setHeader(name, value);
        }
    }

    static fromUrl(method, url, body = null, headers = {}) {
        let parsed;
        try {
            parsed = new URL(url, 'http://localhost');
        } catch (e) {
            throw new ApiSignerError(`Cannot parse URL "${url}".`);
        }

        const absolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);

        return new Request(
            method,
            parsed.pathname,
            parsed.search,
            body,
            headers,
            absolute ? parsed.host : '',
            absolute ? parsed.protocol.replace(/:$/, '') : ''
        );
    }

    setHeader(name, value) {
        this.headers[String(name).toLowerCase()] = String(value);
    }

    header(name) {
        const value = this.headers[String(name).toLowerCase()];
        return value === undefined ? null : value;
    }

    requestTarget() {
        return this.query === '' ? this.path : `${this.path}?${this.query}`;
    }
}

module.exports = { Request };
