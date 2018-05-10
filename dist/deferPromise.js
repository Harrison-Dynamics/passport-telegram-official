"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function deferPromise() {
    const Promise = global.Promise;
    let resolve, reject;
    const promise = new Promise((_resolve, _reject) => {
        resolve = _resolve;
        reject = _reject;
    });
    return {
        then: f => promise.then(f),
        callback: (err, ...data) => err ? reject(err) : resolve(data),
        promise
    };
}
exports.default = deferPromise;
//# sourceMappingURL=deferPromise.js.map