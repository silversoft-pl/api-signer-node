'use strict';

const { ApiSignerError } = require('./errors');
const { Credential } = require('./credential');
const { Request } = require('./request');
const { Params } = require('./params');
const { Policy } = require('./policy');
const { Result } = require('./result');
const signer = require('./signer');
const verifier = require('./verifier');
const digest = require('./digest');
const algorithm = require('./algorithm');
const structuredFields = require('./structured-fields');
const signatureBase = require('./signature-base');
const components = require('./components');
const apiSigner = require('./api-signer');

module.exports = {
    ApiSignerError,
    Credential,
    Request,
    Params,
    Policy,
    Result,
    SignedRequest: apiSigner.SignedRequest,
    prepare: apiSigner.prepare,
    sign: signer.sign,
    signatureBaseOf: signer.base,
    verify: verifier.verify,
    keyIdOf: verifier.keyIdOf,
    digest,
    algorithm,
    structuredFields,
    signatureBase,
    components,
};
