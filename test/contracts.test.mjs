import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { sourceIds } from '../src/projection.mjs';
import { assess } from '../src/engine.mjs';
import { demoEvidence } from '../examples/demo.mjs';
import { validateAssessment, readJson } from '../src/report.mjs';
import { validateEvidence } from '../src/evidence.mjs';
import { validateAuditConfig } from '../src/audit.mjs';

test('documented JSON schemas enumerate every evidence source and all scored report surfaces', async () => {
  const [evidence, assessment, config] = await Promise.all(['evidence', 'assessment', 'audit-config'].map(async (name) =>
    JSON.parse(await readFile(new URL(`../schemas/${name}.schema.json`, import.meta.url), 'utf8'))));
  assert.deepEqual([...evidence.properties.sources.propertyNames.enum].sort(), [...sourceIds].sort());
  assert.ok(evidence.properties.target.properties.tenant);
  for (const name of ['strategies', 'authorization', 'authorizedSubscriptions', 'scenario', 'relatedResourceIds', 'maxRelatedResources']) {
    assert.ok(evidence.properties.scope.properties[name], name);
  }
  assert.ok(evidence.$defs.source.properties.failures);
  assert.ok(assessment.required.includes('ratings'));
  assert.ok(assessment.required.includes('namespaceResults'));
  assert.ok(assessment.properties.results.items.required.includes('score'));
  assert.deepEqual(assessment.properties.results.items.properties.score.type, ['integer', 'null']);
  assert.ok(config.required.includes('tenant'));
  assert.ok(config.required.includes('authorization'));
  const schemas = { 'evidence.schema.json': evidence, 'assessment.schema.json': assessment, 'audit-config.schema.json': config };
  const checkReferences = (value, file) => {
    if (!value || typeof value !== 'object') return;
    if (typeof value.$ref === 'string') {
      const [name, pointer] = value.$ref.split('#');
      let resolved = schemas[name || file];
      for (const segment of (pointer ?? '').split('/').slice(1)) {
        const key = segment.replaceAll('~1', '/').replaceAll('~0', '~');
        assert.ok(resolved && Object.hasOwn(resolved, key), `${file}: unresolved schema reference ${value.$ref}`);
        resolved = resolved[key];
      }
    }
    for (const child of Object.values(value)) checkReferences(child, file);
  };
  for (const [file, schema] of Object.entries(schemas)) checkReferences(schema, file);
});

test('parameterized example requires replacement of placeholders and explicit invoker consent', async () => {
  const text = await readFile(new URL('../examples/audit-config.json', import.meta.url), 'utf8');
  const value = JSON.parse(text);
  assert.equal(value.authorization.readOnly, false);
  assert.equal(value.tenant, '<tenant-guid>');
  assert.throws(() => validateAuditConfig(value), /GUID/);
});

test('extended evidence and assessment scope cannot forge tenant or subscription authorization', () => {
  for (const validate of [validateEvidence, validateAssessment]) {
    const value = validate === validateEvidence ? demoEvidence() : assess(demoEvidence());
    value.target.tenant = 'not-a-tenant';
    assert.throws(() => validate(value), /tenant|scope|authorization/i);
  }
});

test('input JSON syntax errors do not print snippets of private file contents', async () => {
  await assert.rejects(() => readJson(new URL('../test/fixtures/malformed-input.txt', import.meta.url)), (failure) =>
    !failure.message.includes('NEVER') && /JSON/.test(failure.message));
});
