/**
 * `ajv-draft-04`'s own shipped `dist/index.d.ts` writes `export default Ajv;`
 * (ESM-style) for a CommonJS-format module (no `"type": "module"` in its
 * package.json). Under this project's `"module"/"moduleResolution": "NodeNext"`
 * + `esModuleInterop`, TypeScript resolves `import Ajv from 'ajv-draft-04'`
 * (and every equivalent spelling — namespace import + `.default`,
 * `import Ajv = require(...)`) to the whole module namespace instead of the
 * class, so `new Ajv(...)` fails to type-check with TS2351 "not constructable".
 * Confirmed independent of import style and not specific to this repo's
 * tsconfig: plain `ajv`'s own default export hits the identical bug (its
 * named export, `import { Ajv } from 'ajv'`, is the one documented escape
 * hatch — but `ajv-draft-04` never names its class as an export, only
 * default-exports it, so that escape hatch does not exist for this package).
 *
 * This is a defect in the package's shipped types, not in this project's
 * code — the class really is constructable at runtime (`dist/index.js` ends
 * with `exports.default = Ajv`). Re-declaring the module here, built on
 * `ajv`'s own working named import, corrects the type to match what actually
 * runs, without a cast. Scoped to the one symbol `report.test.ts` uses.
 */
declare module 'ajv-draft-04' {
  import { Ajv as AjvCore, Options } from 'ajv';

  export default class Ajv extends AjvCore {
    constructor(opts?: Options);
  }
}
