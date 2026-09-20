'use strict';

/** Czyta zadanie podpisania ze stdin, wypisuje wynikowe nagłówki i ciało na stdout. */

const { Credential, Params, Request, sign } = require('../../js/index.js');

const job = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));

const credential = new Credential(job.key_id, Buffer.from(job.key_base64, 'base64'), job.alg);
const request = Request.fromUrl(job.method, job.url, job.body);

const params = new Params(job.components);
params.label = job.label;
for (const [name, value] of Object.entries(job.params)) params[name] = value;

process.stdout.write(JSON.stringify({ headers: sign(credential, request, params), body: job.body }) + '\n');
