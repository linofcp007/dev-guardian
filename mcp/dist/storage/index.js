/**
 * Storage facade.
 *
 * Tools and resources hold one `Storage` and never touch the raw `Database`
 * handle. This is the only module that knows the DB is SQLite — swapping
 * the engine later only touches files in this folder.
 */
import { AgentAuditRepo } from './agentAuditRepo.js';
import { BaselinesRepo } from './baselinesRepo.js';
import { CveIntelRepo } from './cveIntelRepo.js';
import { CvesRepo } from './cvesRepo.js';
import { FindingsRepo } from './findingsRepo.js';
import { RuntimeMetaRepo } from './runtimeMetaRepo.js';
import { ScansRepo } from './scansRepo.js';
import { StackRepo } from './stackRepo.js';
import { SuppressionsRepo } from './suppressionsRepo.js';
import { SurfaceRepo } from './surfaceRepo.js';
import { ValidationsRepo } from './validationsRepo.js';
export class Storage {
    db;
    scans;
    findings;
    cves;
    cveIntel;
    suppressions;
    baselines;
    stack;
    runtimeMeta;
    surface;
    validations;
    agentAudit;
    constructor(db) {
        this.db = db;
        this.scans = new ScansRepo(db);
        this.findings = new FindingsRepo(db);
        this.cves = new CvesRepo(db);
        this.cveIntel = new CveIntelRepo(db);
        this.suppressions = new SuppressionsRepo(db);
        this.baselines = new BaselinesRepo(db);
        this.stack = new StackRepo(db);
        this.runtimeMeta = new RuntimeMetaRepo(db);
        this.surface = new SurfaceRepo(db);
        this.validations = new ValidationsRepo(db);
        this.agentAudit = new AgentAuditRepo(db);
    }
    close() {
        this.db.close();
    }
    rawHandle() {
        return this.db;
    }
}
export { openDatabase, openDatabaseAtPath, resolveFallbackDbPath } from './db.js';
//# sourceMappingURL=index.js.map