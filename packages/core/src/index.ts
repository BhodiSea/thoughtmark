// SPDX-License-Identifier: Apache-2.0
// Public entry for @thoughtmark/core. The `browser` export condition routes to ./browser.js; Node and the
// type surface resolve here / to ./node.js.

export { canonVersion, ensureReady, runOp } from "./node.js";
export type { OpName } from "./types.js";
