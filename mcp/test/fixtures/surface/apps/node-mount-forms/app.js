// Fixture for the mount-resolution claim in guardian-import-esm's comment
// (configs/semgrep/routes.yml): does resolveNodeMounts (resolvers/node.ts)
// actually follow a router bound via a NAMED import, and via a NAMESPACE
// import, the same way it already follows a default import? Both are
// Semgrep-version-dependent — see that rule's comment for the full
// mechanism and the version-conditional covering assertion in
// test/e2e/rulePackFixture.test.ts ("maps every route the fixture
// declares, and nothing else") for the pinned, measured result on each
// path.
//
// named-router.js's router is imported by name and mounted directly.
// On a Semgrep reporting real metavariables (checked via
// `docker run semgrep/semgrep:1.86.0` against this file), $ROUTER for
// `app.use(prefix, namedRouter)` is "namedRouter namedRouter" — Semgrep's
// own constant-propagation doubles a name also bound by a destructured
// import in the same file — which does not equal the import's $SYMBOL, so
// resolveNodeMounts correctly leaves it path_partial: true.
//
// ns-router.js's router is imported as a namespace and mounted via member
// access (`ns.router`). On the same real-metavariable Semgrep, $ROUTER is
// the whole expression "ns.router", which does not equal the import's
// $SYMBOL (the bare alias "ns") either — also correctly path_partial: true.
//
// On THIS project's actual pipeline (a redacting Semgrep, recovered by
// recoverMetavars.ts), BOTH resolve instead — but not because
// resolveNodeMounts understands either shape. recoverMetavars.ts's
// synthesizeMount (a separate, pre-existing function this diff does not
// touch) never reads Semgrep's own rendering; it slices $ROUTER out of the
// raw source as a single identifier. That coincidentally undoes the
// doubling (there is no constant-propagation pass in a regex over bytes)
// and coincidentally truncates "ns.router" down to "ns" — both land back on
// the import's own $SYMBOL by accident, not by a correct reading of either
// form. See guardian-import-esm's comment for the full mechanism and why it
// is reported, not fixed, here.
import express from 'express';
import { namedRouter } from './named-router.js';
import * as ns from './ns-router.js';

const app = express();
app.use('/named', namedRouter);
app.use('/ns', ns.router);

export default app;
