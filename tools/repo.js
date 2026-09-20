'use strict';

const fs = require('node:fs');
const path = require('node:path');

const NODE_ROOT = path.join(__dirname, '..');

/**
 * Znajduje odpowiednik w PHP, który mieszka we własnym repozytorium.
 *
 * Obie paczki realizują jeden format drutowy, więc jedyny test naprawdę
 * dowodzący ich zgodności wymaga obu. `API_SIGNER_PHP` wskazuje gdzie;
 * katalog obok jest domyślny, bo tak zwykle się je klonuje.
 */
function phpRoot() {
    const candidate = process.env.API_SIGNER_PHP || path.join(NODE_ROOT, '..', 'api-signer-php');
    const resolved = path.resolve(candidate);

    if (!fs.existsSync(path.join(resolved, 'tools', 'cross', 'sign.php'))) {
        throw new Error(
            `Cannot find the PHP package at ${resolved}.\n` +
            'Clone https://github.com/silversoft-pl/api-signer-php next to this repository, ' +
            'or point API_SIGNER_PHP at your checkout.'
        );
    }

    if (!fs.existsSync(path.join(resolved, 'vendor', 'autoload.php'))) {
        throw new Error(`The PHP package at ${resolved} has no vendor/ — run "composer install" there first.`);
    }

    return resolved;
}

/**
 * To samo co phpRoot(), ale brak repozytorium daje komunikat do przeczytania,
 * a nie stos wywołań do rozszyfrowania.
 */
function phpRootOrExit() {
    try {
        return phpRoot();
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { NODE_ROOT, phpRoot, phpRootOrExit };
