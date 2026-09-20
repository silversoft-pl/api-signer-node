'use strict';

/**
 * Test krzyżowy: każda implementacja weryfikuje to, co przed chwilą wyprodukowała
 * druga, a obie muszą dać identyczne bajty dla identycznego wejścia.
 *
 * Wektory statyczne dowodzą tylko tego, że implementacja nadal zgadza się
 * z nagraniem. To dowodzi, że obie paczki zgadzają się ze sobą — a odkąd mieszkają
 * w osobnych repozytoriach, jest też jedyną rzeczą, która powstrzymuje je przed
 * rozjechaniem się z wydania na wydanie.
 *
 * Wymaga obu repozytoriów; sposób znalezienia PHP-owego jest w tools/repo.js.
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { algorithm, Credential } = require('../../js/index.js');
const { NODE_ROOT, phpRootOrExit } = require('../repo.js');
const { bodyOf } = require('../vectors.js');

const PHP_ROOT = phpRootOrExit();
const php = process.env.PHP_BIN || 'php';

const readVectors = (root, name) =>
    fs.readFileSync(path.join(root, 'vectors', name), 'utf8');

let failures = 0;

const fail = (message) => {
    console.error('  FAIL ' + message);
    failures++;
};

// Rozjechane wektory unieważniłyby każde dalsze porównanie, więc najpierw kontrola.
for (const name of ['rfc9421.json', 'testvectors.json']) {
    if (readVectors(NODE_ROOT, name) !== readVectors(PHP_ROOT, name)) {
        fail(`vectors/${name} differs between the two repositories — run "npm run sync-vectors"`);
    }
}

if (failures > 0) {
    process.exit(1);
}

const vectors = JSON.parse(readVectors(NODE_ROOT, 'testvectors.json'));

const run = (command, args, cwd, input) =>
    JSON.parse(execFileSync(command, args, { input, encoding: 'utf8', cwd }));

const signers = {
    php: (job) => run(php, ['tools/cross/sign.php'], PHP_ROOT, JSON.stringify(job)),
    node: (job) => run(process.execPath, ['tools/cross/sign.js'], NODE_ROOT, JSON.stringify(job)),
};

const verifiers = {
    php: (job) => run(php, ['tools/cross/verify.php'], PHP_ROOT, JSON.stringify(job)),
    node: (job) => run(process.execPath, ['tools/cross/verify.js'], NODE_ROOT, JSON.stringify(job)),
};

console.log(`php:  ${PHP_ROOT}`);
console.log(`node: ${NODE_ROOT}\n`);

for (const testCase of vectors.cases) {
    const key = vectors.keys[testCase.algorithm === 'ed25519' ? 'ed25519' : 'hmac'];
    const keyBase64 = key.key_base64 ?? key.seed_base64;
    const material = Buffer.from(keyBase64, 'base64');

    const verifyKeyBase64 = testCase.algorithm === 'ed25519'
        ? algorithm.ed25519PublicKeyFrom(material).toString('base64')
        : keyBase64;

    const job = {
        key_id: testCase.key_id,
        alg: testCase.algorithm,
        key_base64: keyBase64,
        method: testCase.method,
        url: testCase.url,
        body: bodyOf(testCase),
        components: testCase.components,
        params: testCase.params,
        label: testCase.label,
    };

    console.log(testCase.name);

    const signed = {};
    for (const [name, signer] of Object.entries(signers)) {
        signed[name] = signer(job);
    }

    if (JSON.stringify(signed.php.headers) !== JSON.stringify(signed.node.headers)) {
        fail('PHP and Node produced different headers');
        console.error('    php : ' + JSON.stringify(signed.php.headers));
        console.error('    node: ' + JSON.stringify(signed.node.headers));
    }

    for (const [signerName, produced] of Object.entries(signed)) {
        for (const [verifierName, verifier] of Object.entries(verifiers)) {
            const outcome = verifier({
                key_id: testCase.key_id,
                alg: testCase.algorithm,
                verify_key_base64: verifyKeyBase64,
                method: testCase.method,
                url: testCase.url,
                body: produced.body,
                headers: produced.headers,
                now: testCase.params.created,
            });

            if (outcome.failed !== false) {
                fail(`${signerName} signed, ${verifierName} rejected: ${outcome.reason}`);
            }
        }
    }
}

const legacy = new Credential(vectors.legacy.key_id, Buffer.from(vectors.legacy.key_base64, 'base64'), 'hmac-sha256', 'legacy');
if (legacy.legacyHeader() !== vectors.legacy.header) {
    fail('legacy header differs from the recorded value');
}

console.log(failures === 0
    ? `\nPHP <-> Node: ${vectors.cases.length} cases, signatures identical, each verifies the other`
    : `\nFAILURES: ${failures}`);

process.exit(failures === 0 ? 0 : 1);
