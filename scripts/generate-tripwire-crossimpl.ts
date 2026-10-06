/**
 * Write the tripwired leaf rows signed by this library (see tripwire-crossimpl-rows.ts):
 *
 *   npx tsx scripts/generate-tripwire-crossimpl.ts               # vectors/tripwire_crossimpl_rows.json
 *   npx tsx scripts/generate-tripwire-crossimpl.ts --out <file>  # and the same file to <file>
 *
 * The file is a JSON array of entries of Bitcoin Core's `src/test/data/script_tests.json`: the
 * header row of the block, then the rows.
 */
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BLOCK_HEADER, buildRows } from './tripwire-crossimpl-rows.js';

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'tripwire_crossimpl_rows.json');

const rows = buildRows();
const text = `${JSON.stringify([[BLOCK_HEADER], ...rows], null, 1)}\n`;
writeFileSync(OUT, text);
console.error(`wrote ${rows.length} rows to ${OUT}`);

const i = process.argv.indexOf('--out');
if (i !== -1) {
  const path = process.argv[i + 1];
  if (path === undefined) throw new Error('--out needs a file path');
  writeFileSync(path, text);
  console.error(`wrote ${rows.length} rows to ${resolve(path)}`);
}
