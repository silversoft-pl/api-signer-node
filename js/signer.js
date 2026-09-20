'use strict';

const algorithm = require('./algorithm');
const digest = require('./digest');
const signatureBase = require('./signature-base');
const sf = require('./structured-fields');
const { Params } = require('./params');

const covers = (components, name) => components.some((c) => c.toLowerCase() === name);

/**
 * Podpisuje żądanie. Podane `params` są używane **dosłownie** — nic nie jest
 * dopisywane za plecami wołającego, dzięki czemu wektory testowe odtwarzają się
 * co do bajta. `null` daje sensowne wartości domyślne.
 *
 * Ustawia `Content-Digest`, gdy ten komponent jest pokryty, a nagłówka jeszcze
 * nie ma.
 *
 * @returns {Object<string,string>} nagłówki do dodania do żądania
 */
function sign(credential, request, params = null) {
    if (credential.isLegacy()) {
        return { 'Api-Authorization': credential.legacyHeader() };
    }

    const effective = params ?? new Params().withDefaults(credential);
    const headers = {};

    if (covers(effective.components, 'content-digest') && request.header('content-digest') === null) {
        const value = digest.of(request.body);
        request.setHeader('content-digest', value);
        headers['Content-Digest'] = value;
    }

    const paramsLine = sf.serializeInnerList(effective.components, effective.ordered());
    const base = signatureBase.build(effective.components, paramsLine, request);
    const signature = algorithm.sign(base, credential);

    headers['Signature-Input'] = `${effective.label}=${paramsLine}`;
    headers.Signature = `${effective.label}=${sf.serializeByteSequence(signature)}`;

    return headers;
}

/** Baza podpisu, wystawiona po to, żeby wektory testowe mogły ją sprawdzać wprost. */
function base(request, params) {
    const paramsLine = sf.serializeInnerList(params.components, params.ordered());

    return signatureBase.build(params.components, paramsLine, request);
}

module.exports = { sign, base };
