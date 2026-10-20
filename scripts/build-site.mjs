import { writeFile } from 'node:fs/promises';
import { demoEvidence, demoTimestamp } from '../examples/demo.mjs';
import { assess } from '../src/engine.mjs';
import { renderHtml } from '../src/report.mjs';

const evidence = demoEvidence();
const assessment = assess(evidence, { now: new Date(demoTimestamp) });
await Promise.all([
  writeFile(new URL('../site/index.html', import.meta.url), await renderHtml(assessment)),
  writeFile(new URL('../examples/demo-evidence.json', import.meta.url), `${JSON.stringify(evidence, null, 2)}\n`)
]);
console.log(`Built standalone site and synthetic example: ${assessment.results.length} controls.`);
