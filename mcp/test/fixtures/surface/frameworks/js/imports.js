// L30 default import, single quotes
import express from 'express';
// L31 named import
import { Router, json } from 'express';
// L32 renamed named import  (documented gap?)
import { Router as R2 } from 'express';
// L33 default + named mixed
import def, { helperA } from './helpers.js';
// L34 namespace import
import * as ns from './ns.js';
// L35 side-effect only import
import './polyfill.js';
// L36 re-export
export { thing } from './thing.js';
// L37 export star
export * from './all.js';
// L38 dynamic import
const lazy = await import('./lazy.js');
// L39 destructuring require
const { readFile } = require('node:fs/promises');
// L40 renamed destructuring require (documented gap)
const { writeFile: wf } = require('node:fs/promises');
// L41 plain require
const path = require('node:path');
// L42 require without assignment
require('dotenv/config');
