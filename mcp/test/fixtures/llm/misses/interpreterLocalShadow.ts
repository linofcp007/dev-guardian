// A LOCAL name that shadows the import: the call is the local's, and there is nothing to report. One function for
// every way of giving the name another value — the name of an imported FUNCTION (`exec`, `spawn`) first, then the
// name of the MODULE (`cp`): `const`, `let` and `var`, plain and by destructuring, a loop variable, a catch
// variable and a function declaration. Each line fires without its own exclusion (the ablation reads it).
//
// The function declaration of the module's name uses a second default import of the module (`childProc`), not `cp`: measured with
// Semgrep 1.182.0, in a file where the SAME name is also declared by a destructuring in another function, the
// function-declaration exclusion is not applied and the call fires, as it did before this exclusion existed.
import OpenAI from 'openai';
import { spawn, exec } from 'node:child_process';
import cp from 'node:child_process';
import childProc from 'child_process';

type Text = OpenAI.Chat.ChatCompletion;
type Db = { exec: (s: string) => number };
type Holder = Record<string, Db>;

export function aConst(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  const spawn = (job: string) => job.length;
  spawn(text); // a local const
}

export function aLet(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  let exec = (s: string) => s.length;
  exec(text); // a local let
}

export function aVar(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  var exec = (s: string) => s.length;
  exec(text); // a local var
}

export function aConstDestructuring(completion: Text, db: Db) {
  const text = completion.choices[0].message.content ?? '';
  const { exec } = db;
  exec(text); // const, destructured from another object
}

export function aLetDestructuring(completion: Text, db: Db) {
  const text = completion.choices[0].message.content ?? '';
  let { exec } = db;
  exec(text); // let, destructured from another object
}

export function aVarDestructuring(completion: Text, db: Db) {
  const text = completion.choices[0].message.content ?? '';
  var { exec } = db;
  exec(text); // var, destructured from another object
}

export function aLoopVariable(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  for (const exec of [(s: string) => s.length]) exec(text); // a loop variable
}

export function aCatchVariable(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  try { throw new Error('x'); } catch (exec) { (exec as unknown as (s: string) => void)(text); } // a catch variable
}

export function aFunctionDeclaration(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  function spawn(job: string) { return job.length; }
  spawn(text); // a local function declaration
}

export function moduleConst(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  {
    const cp = { exec: (sql: string) => sql.length };
    cp.exec(text); // the module's name: a local const, in an inner block
  }
}

export function moduleLet(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  let cp = { exec: (sql: string) => sql.length };
  cp.exec(text); // the module's name: a local let
}

export function moduleVar(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  var cp = { exec: (sql: string) => sql.length };
  cp.exec(text); // the module's name: a local var
}

export function moduleConstDestructuring(completion: Text, holder: Holder) {
  const text = completion.choices[0].message.content ?? '';
  const { cp } = holder;
  cp.exec(text); // the module's name: const, destructured from another object
}

export function moduleLetDestructuring(completion: Text, holder: Holder) {
  const text = completion.choices[0].message.content ?? '';
  let { cp } = holder;
  cp.exec(text); // the module's name: let, destructured from another object
}

export function moduleVarDestructuring(completion: Text, holder: Holder) {
  const text = completion.choices[0].message.content ?? '';
  var { cp } = holder;
  cp.exec(text); // the module's name: var, destructured from another object
}

export function moduleLoopVariable(completion: Text, pools: Db[]) {
  const text = completion.choices[0].message.content ?? '';
  for (const cp of pools) cp.exec(text); // the module's name: a loop variable
}

export function moduleCatchVariable(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  try { throw new Error('x'); } catch (cp) { (cp as Db).exec(text); } // the module's name: a catch variable
}

export function moduleFunctionDeclaration(completion: Text) {
  const text = completion.choices[0].message.content ?? '';
  function childProc() { return 0; }
  childProc.exec(text); // the module's name (its second import): a local function declaration
}
