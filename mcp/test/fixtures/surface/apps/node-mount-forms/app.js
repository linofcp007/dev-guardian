// Fixture for the mount-resolution claim in guardian-import-esm's comment
// (configs/semgrep/routes.yml): does resolveNodeMounts (resolvers/node.ts)
// actually follow a router bound via a NAMED import, and via a NAMESPACE
// import, the same way it already follows a default import? See the e2e
// assertion (test/e2e/rulePackFixture.test.ts) for the pinned, measured
// result.
//
// named-router.js's router is imported by name and mounted directly —
// exactly the shape resolveNodeMounts's exact-string symbol match expects.
// Measured: resolves, path_partial: false.
//
// ns-router.js's router is imported as a namespace and mounted via member
// access (`ns.router`). buildPrefixIndex (resolvers/node.ts) requires
// `imports.find(i => i.symbol === mount.router_var)`, and the import
// record's $SYMBOL is the namespace alias alone ("ns"). Reasoning from
// buildPrefixIndex in isolation says this should fail: $ROUTER for
// `app.use(prefix, ns.router)` is the whole member-access expression
// ("ns.router") on a Semgrep that reports real metavariables, which is not
// "ns". Measured anyway rather than trusted: on THIS project's actual
// pipeline (a redacting Semgrep, recovered by recoverMetavars.ts), it also
// resolves — but only because recoverMetavars.ts's synthesizeMount (a
// different, pre-existing function this diff does not touch) recovers
// $ROUTER as a single identifier and stops at the first non-identifier
// character, so "ns.router" recovers as bare "ns", which then
// coincidentally equals the import's own $SYMBOL. See guardian-import-esm's
// comment for what that implies and why it is reported, not fixed, here.
import express from 'express';
import { namedRouter } from './named-router.js';
import * as ns from './ns-router.js';

const app = express();
app.use('/named', namedRouter);
app.use('/ns', ns.router);

export default app;
