'use strict';

/**
 * Kopiuje wektory testowe z paczki PHP, która jest ich właścicielem: generator
 * jest w PHP, więc tam powstają. Ta paczka ma je tylko odtwarzać.
 */

const fs = require('node:fs');
const path = require('node:path');
const { NODE_ROOT, phpRootOrExit } = require('./repo.js');

const PHP_ROOT = phpRootOrExit();
let changed = 0;

for (const name of ['rfc9421.json', 'testvectors.json']) {
    const from = path.join(PHP_ROOT, 'vectors', name);
    const to = path.join(NODE_ROOT, 'vectors', name);
    const source = fs.readFileSync(from, 'utf8');

    if (fs.existsSync(to) && fs.readFileSync(to, 'utf8') === source) {
        console.log(`unchanged  vectors/${name}`);
        continue;
    }

    fs.writeFileSync(to, source);
    console.log(`updated    vectors/${name}`);
    changed++;
}

console.log(changed === 0 ? '\nAlready in sync.' : `\n${changed} file(s) updated — commit them.`);
