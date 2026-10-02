import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(exec);

export async function runReport(name: string): Promise<string> {
  // The report name reaches a shell unquoted.
  const { stdout } = await run(`report-tool --name ${name}`);
  return stdout;
}
