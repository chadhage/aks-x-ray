import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { assessmentStrategies, validationStages, evidenceTiers } from '../src/diagnosis/strategies.mjs';
import { diagnose, validateDiagnosis } from '../src/diagnosis/engine.mjs';
import { diagnosisDemo } from '../examples/diagnosis-demo.mjs';

test('all diagnosis schemas parse, resolve local references and document the actual strategy/tier contracts', async () => {
  const names = (await readdir(new URL('../schemas/', import.meta.url))).filter((name) => name.endsWith('.json'));
  const schemas = Object.fromEntries(await Promise.all(names.map(async (name) => [name,
    JSON.parse(await readFile(new URL(`../schemas/${name}`, import.meta.url), 'utf8'))])));
  const walk = (value, file) => {
    if (!value || typeof value !== 'object') return;
    if (value.$ref) {
      const [name, fragment] = value.$ref.split('#');
      let resolved = schemas[name || file];
      assert.ok(resolved, `Missing schema ${value.$ref}`);
      for (const segment of (fragment ?? '').split('/').slice(1)) {
        const key = segment.replaceAll('~1', '/').replaceAll('~0', '~');
        assert.ok(Object.hasOwn(resolved, key), `Unresolved ${file}: ${value.$ref}`);
        resolved = resolved[key];
      }
    }
    for (const child of Object.values(value)) walk(child, file);
  };
  for (const [file, schema] of Object.entries(schemas)) walk(schema, file);
  assert.deepEqual(schemas['assessment-options.schema.json'].properties.strategies.items.enum, assessmentStrategies);
  assert.deepEqual(schemas['assessment-options.schema.json'].properties.stages.items.enum, validationStages);
  assert.deepEqual(schemas['diagnosis.schema.json'].$defs.finding.properties.evidenceTier.enum, evidenceTiers);
});

test('the complete synthetic strategy combination survives JSON persistence and runtime revalidation', () => {
  const input = diagnosisDemo(assessmentStrategies);
  const report = diagnose(input.bundles, input);
  const persisted = JSON.parse(JSON.stringify(report));
  assert.equal(validateDiagnosis(persisted), persisted);
  assert.ok(persisted.findings.length > 0);
  assert.ok(persisted.findings.every((finding) => finding.risk.score === null || finding.risk.score >= 1 && finding.risk.score <= 100));
  assert.ok(persisted.graph.sources.every((source) => /^[0-9a-f]{64}$/.test(source.digest)));
});
