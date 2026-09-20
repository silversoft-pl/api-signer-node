'use strict';

class ApiSignerError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ApiSignerError';
    }
}

module.exports = { ApiSignerError };
