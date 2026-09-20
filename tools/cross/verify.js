'use strict';

/** Czyta podpisane żądanie ze stdin, wypisuje wynik weryfikacji na stdout. */

const { Credential, Policy, Request, verify } = require('../../js/index.js');

const job = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));

const credential = new Credential(job.key_id, Buffer.from(job.verify_key_base64, 'base64'), job.alg);
const request = Request.fromUrl(job.method, job.url, job.body, job.headers);
const result = verify(request, credential, new Policy({ now: job.now }));

process.stdout.write(JSON.stringify({ failed: result.failed, reason: result.reason }) + '\n');
