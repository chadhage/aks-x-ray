import { writeFile } from 'node:fs/promises';
import { demoEvidence, demoTimestamp } from '../examples/demo.mjs';
import { assess } from '../src/engine.mjs';
import { renderHtml } from '../src/report.mjs';

const evidence = demoEvidence();
const assessment = assess(evidence, { now: new Date(demoTimestamp) });
const [homepage, sample] = await Promise.all([renderHtml(), renderHtml(assessment)]);
await Promise.all([
  writeFile(new URL('../site/index.html', import.meta.url), homepage),
  writeFile(new URL('../site/sample.html', import.meta.url), sample),
  writeFile(new URL('../examples/demo-evidence.json', import.meta.url), `${JSON.stringify(evidence, null, 2)}\n`)
]);
console.log(`Built getting-started homepage and separate synthetic sample: ${assessment.results.length} controls.`);
