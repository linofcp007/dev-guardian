/**
 * Storage facade.
 *
 * Tools and resources hold one `Storage` and never touch the raw `Database`
 * handle. This is the only module that knows the DB is SQLite — swapping
 * the engine later only touches files in this folder.
 */

import type { Database as DB } from 'better-sqlite3';
import { BaselinesRepo } from './baselinesRepo.js';
import { CvesRepo } from './cvesRepo.js';
import { FindingsRepo } from './findingsRepo.js';
import { RuntimeMetaRepo } from './runtimeMetaRepo.js';
import { ScansRepo } from './scansRepo.js';
import { StackRepo } from './stackRepo.js';
import { SuppressionsRepo } from './suppressionsRepo.js';

export class Storage {
  readonly scans: ScansRepo;
  readonly findings: FindingsRepo;
  readonly cves: CvesRepo;
  readonly suppressions: SuppressionsRepo;
  readonly baselines: BaselinesRepo;
  readonly stack: StackRepo;
  readonly runtimeMeta: RuntimeMetaRepo;

  constructor(private readonly db: DB) {
    this.scans = new ScansRepo(db);
    this.findings = new FindingsRepo(db);
    this.cves = new CvesRepo(db);
    this.suppressions = new SuppressionsRepo(db);
    this.baselines = new BaselinesRepo(db);
    this.stack = new StackRepo(db);
    this.runtimeMeta = new RuntimeMetaRepo(db);
  }

  close(): void {
    this.db.close();
  }

  rawHandle(): DB {
    return this.db;
  }
}

export { openDatabase } from './db.js';
export type { OpenedDatabase, OpenOptions } from './db.js';
