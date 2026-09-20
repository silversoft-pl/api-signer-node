/**
 * Kontrola interop z niezależną implementacją RFC 9421.
 *
 * Własne testy mogą pokazać tylko to, że nadal zgadzamy się ze sobą. To pokazuje,
 * że biblioteka napisana przez kogoś innego, z tej samej specyfikacji, wyprowadza
 * identyczną bazę podpisu z naszych podpisanych żądań — a to jest ta część
 * standardu, którą łatwo subtelnie popsuć.
 *
 * Zależność jest wyłącznie deweloperska; sama paczka nie ma żadnej.
 *
 * Znana rozbieżność, odnotowana zamiast ukrytej: dla żądania bez query stringu
 * RFC 9421 §2.2.7 mówi, że wartością komponentu @query jest „samo wiodące ?”,
 * czyli linia `"@query": ?`. Testowana biblioteka emituje wartość pustą.
 * My trzymamy się specyfikacji. Gdyby ją poprawiono, ten skrypt zgłosi błąd
 * i wyjątek zniknie.
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Credential, Params, Request, sign, signatureBaseOf } from '../../index.mjs';

const require = createRequire(import.meta.url);
const { RFC9421SignatureBaseFactory } = require('@misskey-dev/node-http-message-signatures');
const { bodyOf } = require('../vectors.js');

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const vectors = JSON.parse(readFileSync(path.join(root, 'vectors', 'testvectors.json'), 'utf8'));

const EMPTY_QUERY_DEVIATION = ['"@query": ?', '"@query": '];

/** Prawda, gdy jedyną różnicą jest znana rozbieżność pustego query. */
function isKnownDeviation(ours, theirs) {
    const left = ours.split('\n');
    const right = theirs.split('\n');
    if (left.length !== right.length) return false;

    let deviations = 0;
    for (let i = 0; i < left.length; i++) {
        if (left[i] === right[i]) continue;
        if (left[i] === EMPTY_QUERY_DEVIATION[0] && right[i] === EMPTY_QUERY_DEVIATION[1]) {
            deviations++;
            continue;
        }
        return false;
    }

    return deviations > 0;
}

let failures = 0;
let agreed = 0;
let deviated = 0;

for (const testCase of vectors.cases) {
    const key = vectors.keys[testCase.algorithm === 'ed25519' ? 'ed25519' : 'hmac'];
    const credential = new Credential(
        testCase.key_id,
        Buffer.from(key.key_base64 ?? key.seed_base64, 'base64'),
        testCase.algorithm
    );

    const params = new Params(testCase.components);
    params.label = testCase.label;
    for (const [name, value] of Object.entries(testCase.params)) params[name] = value;

    const request = Request.fromUrl(testCase.method, testCase.url, bodyOf(testCase));
    const headers = sign(credential, request, params);
    const ours = signatureBaseOf(request, params);

    const theirs = new RFC9421SignatureBaseFactory({
        url: testCase.url,
        method: testCase.method,
        headers: { ...headers, host: new URL(testCase.url).host },
    }).generate(testCase.label);

    if (ours === theirs) {
        agreed++;
        console.log(`ok        ${testCase.name}`);
    } else if (isKnownDeviation(ours, theirs)) {
        deviated++;
        console.log(`deviation ${testCase.name} (empty @query, RFC 9421 s2.2.7 — we are right)`);
    } else {
        failures++;
        console.error(`FAIL      ${testCase.name}`);
        console.error('--- ours ---\n' + ours);
        console.error('--- theirs ---\n' + theirs);
    }
}

console.log(`\nagreed: ${agreed}, known deviation: ${deviated}, unexplained: ${failures}`);

if (deviated === 0) {
    console.error('The empty-query deviation no longer occurs; drop the exemption from this script.');
    process.exit(1);
}

process.exit(failures === 0 ? 0 : 1);
