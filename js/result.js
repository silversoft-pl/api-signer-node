'use strict';

/**
 * `reason` jest przeznaczony do logu serwera. Odpowiedź HTTP zawsze niesie
 * jeden ogólny komunikat, żeby atakujący nie odróżnił „nieznany klucz”
 * od „zły podpis”.
 */
class Result {
    constructor(failed, reason = null, label = null, params = {}, components = []) {
        this.failed = failed;
        this.reason = reason;
        this.label = label;
        this.params = params;
        this.components = components;
    }

    static accepted(label, params, components) {
        return new Result(false, null, label, params, components);
    }

    static rejected(reason) {
        return new Result(true, reason);
    }
}

module.exports = { Result };
