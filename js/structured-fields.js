'use strict';

const { ApiSignerError } = require('./errors');

// Podzbiór RFC 8941 wymagany przez RFC 9421: słowniki list wewnętrznych
// i sekwencji bajtów, z parametrami. Struktura celowo identyczna jak
// w implementacji PHP, żeby obie nie rozjechały się niepostrzeżenie.

function splitTopLevel(input, separator) {
    const parts = [];
    let current = '';
    let depth = 0;
    let inQuotes = false;
    let inBytes = false;

    for (let i = 0; i < input.length; i++) {
        const char = input[i];

        if (inQuotes) {
            current += char;
            if (char === '\\' && i + 1 < input.length) {
                current += input[++i];
            } else if (char === '"') {
                inQuotes = false;
            }
            continue;
        }
        if (inBytes) {
            current += char;
            if (char === ':') inBytes = false;
            continue;
        }
        if (char === '"') { inQuotes = true; current += char; continue; }
        if (char === ':') { inBytes = true; current += char; continue; }
        if (char === '(') depth++;
        else if (char === ')') {
            depth--;
            if (depth < 0) throw new ApiSignerError('Unbalanced parentheses.');
        }
        if (char === separator && depth === 0) {
            parts.push(current);
            current = '';
            continue;
        }
        current += char;
    }

    if (inQuotes || inBytes || depth !== 0) {
        throw new ApiSignerError('Unterminated structured field value.');
    }
    parts.push(current);

    return parts;
}

function splitTopLevelOnce(input, separator) {
    let depth = 0;
    let inQuotes = false;
    let inBytes = false;

    for (let i = 0; i < input.length; i++) {
        const char = input[i];
        if (inQuotes) {
            if (char === '\\') i++;
            else if (char === '"') inQuotes = false;
            continue;
        }
        if (inBytes) {
            if (char === ':') inBytes = false;
            continue;
        }
        if (char === '"') { inQuotes = true; continue; }
        if (char === ':') { inBytes = true; continue; }
        if (char === '(') { depth++; continue; }
        if (char === ')') { depth--; continue; }
        if (char === separator && depth === 0) {
            return [input.slice(0, i), input.slice(i + 1)];
        }
    }

    return null;
}

function findClosingParen(raw) {
    let inQuotes = false;
    for (let i = 1; i < raw.length; i++) {
        const char = raw[i];
        if (inQuotes) {
            if (char === '\\') i++;
            else if (char === '"') inQuotes = false;
            continue;
        }
        if (char === '"') { inQuotes = true; continue; }
        if (char === ')') return i;
    }
    throw new ApiSignerError('Unterminated inner list.');
}

function findClosingQuote(raw, start) {
    for (let i = start + 1; i < raw.length; i++) {
        if (raw[i] === '\\') { i++; continue; }
        if (raw[i] === '"') return i;
    }
    throw new ApiSignerError('Unterminated string.');
}

const unescapeString = (raw) => raw.replace(/\\(.)/g, '$1');

/** @returns {Object<string, string>} etykieta => surowa wartość członu, zachowana dosłownie */
function parseDictionary(input) {
    const members = {};

    for (const rawMember of splitTopLevel(input, ',')) {
        const member = rawMember.trim();
        if (member === '') continue;

        const split = splitTopLevelOnce(member, '=');
        if (split === null) {
            members[member] = '?1';
            continue;
        }

        const key = split[0].trim();
        if (key === '') throw new ApiSignerError('Structured dictionary member has an empty key.');
        members[key] = split[1].trim();
    }

    return members;
}

function parseBareItem(raw, state) {
    if (state.i >= raw.length) throw new ApiSignerError('Parameter value is missing.');

    if (raw[state.i] === '"') {
        const end = findClosingQuote(raw, state.i);
        const value = unescapeString(raw.slice(state.i + 1, end));
        state.i = end + 1;
        return value;
    }

    if (raw[state.i] === ':') {
        const end = raw.indexOf(':', state.i + 1);
        if (end === -1) throw new ApiSignerError('Unterminated byte sequence.');
        const encoded = raw.slice(state.i + 1, end);
        const decoded = Buffer.from(encoded, 'base64');
        if (decoded.toString('base64') !== encoded) {
            throw new ApiSignerError('Byte sequence is not valid base64.');
        }
        state.i = end + 1;
        return decoded;
    }

    const start = state.i;
    while (state.i < raw.length && raw[state.i] !== ';') state.i++;
    const token = raw.slice(start, state.i).replace(/\s+$/, '');

    if (token === '?1') return true;
    if (token === '?0') return false;
    if (/^-?\d+$/.test(token)) return parseInt(token, 10);

    return token;
}

function parseParams(raw) {
    const params = {};
    const state = { i: 0 };

    while (state.i < raw.length) {
        if (raw[state.i] !== ';') {
            if (raw.slice(state.i).trim() === '') break;
            throw new ApiSignerError(`Unexpected content in parameters: ${raw.slice(state.i)}`);
        }

        state.i++;
        while (state.i < raw.length && raw[state.i] === ' ') state.i++;

        const start = state.i;
        while (state.i < raw.length && raw[state.i] !== '=' && raw[state.i] !== ';') state.i++;
        const key = raw.slice(start, state.i);
        if (key === '') throw new ApiSignerError('Parameter with an empty name.');

        if (state.i >= raw.length || raw[state.i] === ';') {
            params[key] = true;
            continue;
        }

        state.i++;
        params[key] = parseBareItem(raw, state);
    }

    return params;
}

/** Zamienia `"@query-param";name="Pet"` na wewnętrzną postać `@query-param;name="Pet"`. */
function parseComponentIdentifier(item) {
    const trimmed = item.trim();
    if (trimmed === '' || trimmed[0] !== '"') {
        throw new ApiSignerError(`Component identifier must be a string: ${item}`);
    }

    const end = findClosingQuote(trimmed, 0);

    return unescapeString(trimmed.slice(1, end)) + trimmed.slice(end + 1);
}

/** @returns {{items: string[], params: Object}} */
function parseInnerList(raw) {
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed[0] !== '(') throw new ApiSignerError('Expected an inner list.');

    const close = findClosingParen(trimmed);
    const items = [];
    for (const item of splitTopLevel(trimmed.slice(1, close), ' ')) {
        if (item.trim() !== '') items.push(parseComponentIdentifier(item));
    }

    return { items, params: parseParams(trimmed.slice(close + 1)) };
}

function serializeString(value) {
    if (!/^[\x20-\x7e]*$/.test(value)) {
        throw new ApiSignerError('Structured field strings must be printable ASCII.');
    }

    return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function serializeComponentIdentifier(component) {
    const semicolon = component.indexOf(';');
    if (semicolon === -1) return serializeString(component);

    return serializeString(component.slice(0, semicolon)) + component.slice(semicolon);
}

function serializeBareItem(value) {
    if (Number.isInteger(value)) return String(value);
    if (value === false) return '?0';

    return serializeString(String(value));
}

function serializeParams(params) {
    let out = '';
    for (const [key, value] of Object.entries(params)) {
        out += ';' + key;
        if (value === true) continue;
        out += '=' + serializeBareItem(value);
    }

    return out;
}

function serializeInnerList(components, params) {
    return '(' + components.map(serializeComponentIdentifier).join(' ') + ')' + serializeParams(params);
}

const serializeByteSequence = (raw) => ':' + Buffer.from(raw).toString('base64') + ':';

module.exports = {
    parseDictionary,
    parseInnerList,
    parseParams,
    parseComponentIdentifier,
    serializeInnerList,
    serializeComponentIdentifier,
    serializeParams,
    serializeBareItem,
    serializeString,
    serializeByteSequence,
};
