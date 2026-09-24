/**
 * Write the OP_CHECKMLDSA44 rows signed by this library (see mldsa44-crossimpl-rows.ts):
 *
 *   npx tsx scripts/generate-mldsa44-crossimpl.ts                 # vectors/mldsa44_crossimpl_rows.json
 *   npx tsx scripts/generate-mldsa44-crossimpl.ts --core <tree>   # also splice them into Core
 *
 * With `--core`, the rows go into `<tree>/src/test/data/script_tests.json` of a Bitcoin Core tree
 * with the M1 patch series, as their own block just above the block headed
 * "P2MR OP_CHECKMLDSA44 tests", replacing an earlier copy of this block. Core's Python generators
 * rewrite only their own blocks, from their header down, so this block stays in place.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BLOCK_HEADER, buildRows, formatRows } from './mldsa44-crossimpl-rows.js';

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'mldsa44_crossimpl_rows.json');
const M1_HEADER = '\n["P2MR OP_CHECKMLDSA44 tests';

function splice(path: string, text: string): void {
  // A Windows checkout may have CRLF line endings; work in LF and write back what was there
  const raw = readFileSync(path, 'utf8');
  const crlf = raw.includes('\r\n');
  let content = crlf ? raw.replaceAll('\r\n', '\n') : raw;
  const own = content.indexOf(`\n[${JSON.stringify(BLOCK_HEADER)}]`);
  if (own !== -1) {
    const end = content.indexOf(M1_HEADER, own + 1);
    if (end === -1) throw new Error(`${path}: the block ends nowhere; expected the OP_CHECKMLDSA44 block below it`);
    content = content.slice(0, own) + content.slice(end);
  }
  const anchor = content.indexOf(M1_HEADER);
  if (anchor === -1) throw new Error(`${path}: no "P2MR OP_CHECKMLDSA44 tests" block to put these rows above`);
  const head = content.slice(0, anchor).replace(/\n+$/, '');
  const result = `${head}\n\n${text}\n${content.slice(anchor)}`;
  writeFileSync(path, crlf ? result.replaceAll('\n', '\r\n') : result);
}

const rows = buildRows();
writeFileSync(OUT, `${JSON.stringify([[BLOCK_HEADER], ...rows], null, 1)}\n`);
console.error(`wrote ${rows.length} rows to ${OUT}`);

const i = process.argv.indexOf('--core');
if (i !== -1) {
  const tree = process.argv[i + 1];
  if (tree === undefined) throw new Error('--core needs the path of a Bitcoin Core tree');
  const path = resolve(tree, 'src', 'test', 'data', 'script_tests.json');
  splice(path, formatRows(rows));
  console.error(`spliced ${rows.length} rows into ${path}`);
}
