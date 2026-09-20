import api from './js/index.js';

export const {
    ApiSignerError,
    Credential,
    Request,
    Params,
    Policy,
    Result,
    SignedRequest,
    prepare,
    sign,
    signatureBaseOf,
    verify,
    keyIdOf,
    digest,
    algorithm,
    structuredFields,
    signatureBase,
    components,
} = api;

export default api;
