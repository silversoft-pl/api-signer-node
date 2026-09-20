'use strict';

/**
 * Wektor może opisać swoje ciało zamiast je wklejać — inaczej przypadek 256 KiB
 * zdominowałby plik.
 */
function bodyOf(testCase) {
    if (testCase.body_repeat) return testCase.body_repeat.chunk.repeat(testCase.body_repeat.times);

    return testCase.body;
}

module.exports = { bodyOf };
