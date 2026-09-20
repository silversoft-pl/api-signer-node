'use strict';

const { ApiSignerError } = require('./errors');
const components = require('./components');
const sf = require('./structured-fields');

/**
 * @param {string[]} covered
 * @param {string} paramsLine zserializowana lista wewnętrzna z parametrami, używana dosłownie
 */
function build(covered, paramsLine, request) {
    const seen = new Set();
    let base = '';

    for (const component of covered) {
        const key = component.toLowerCase();
        if (seen.has(key)) throw new ApiSignerError(`Component "${component}" is covered twice.`);
        seen.add(key);

        base += `${sf.serializeComponentIdentifier(component)}: ${components.value(component, request)}\n`;
    }

    return base + `"@signature-params": ${paramsLine}`;
}

module.exports = { build };
