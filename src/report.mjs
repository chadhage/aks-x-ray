import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { categories, controls, sourceCatalog, catalogVersion, catalogDigest, statuses } from './catalog.mjs';
import { validateScope } from './evidence.mjs';
import { summarize } from './engine.mjs';
import { isObject } from './projection.mjs';

export async function readJson(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size > 20 * 1024 * 1024) throw new Error('Input must be a JSON file no larger than 20 MiB.');
  return JSON.parse(await readFile(path, 'utf8'));
}

export function validateAssessment(value) {
  if (!isObject(value) || value.schemaVersion !== '1.0' || value.catalogVersion !== catalogVersion
    || value.catalogDigest !== catalogDigest) throw new Error('Assessment schema or catalogue revision does not match this repository revision.');
  validateScope(value.scope);
  if (!isObject(value.target) || !['cloud', 'local'].includes(value.target.platform)
    || typeof value.target.context !== 'string' || !['verified', 'unverified', 'mismatch'].includes(value.target.binding?.status)) {
    throw new Error('Assessment target is incomplete.');
  }
  if (['subscription', 'resourceGroup', 'cluster'].some((key) => typeof value.target[key] !== 'string' || !value.target[key])) {
    throw new Error('Assessment Azure target identifiers are incomplete.');
  }
  if (!Number.isFinite(Date.parse(value.assessedAt)) || !Number.isFinite(Date.parse(value.collectedAt))) {
    throw new Error('Assessment timestamps are invalid.');
  }
  if (typeof value.synthetic !== 'boolean' || typeof value.toolVersion !== 'string'
    || !Array.isArray(value.collection) || value.collection.some((record) => !isObject(record)
      || typeof record.sourceId !== 'string' || !['ok', 'error', 'notCollected', 'notApplicable'].includes(record.status))) {
    throw new Error('Assessment provenance is invalid.');
  }
  if (value.activeRun !== undefined && (!isObject(value.activeRun) || !isObject(value.activeRun.cleanup)
    || !['pending', 'deleted', 'notFound', 'notNeeded', 'error'].includes(value.activeRun.cleanup.status))) {
    throw new Error('Active-run cleanup provenance is invalid.');
  }
  if (!Array.isArray(value.results) || value.results.length > controls.length) throw new Error('Assessment results are invalid.');
  const ids = new Set();
  for (const result of value.results) {
    const control = controls.find((item) => item.id === result.id);
    if (!control || !value.scope.categories.includes(control.category) || ids.has(result.id) || !statuses.includes(result.status)
      || typeof result.message !== 'string' || typeof result.incomplete !== 'boolean'
      || !Array.isArray(result.evidence)) throw new Error(`Invalid assessment result: ${result.id}`);
    ids.add(result.id);
  }
  const expectedIds = controls.filter((control) => value.scope.categories.includes(control.category)).map((control) => control.id);
  if (expectedIds.length !== ids.size || expectedIds.some((id) => !ids.has(id))) throw new Error('Assessment is missing controls from its declared category scope.');
  const expected = summarize(value.results, value.target.binding.status);
  if (!isDeepStrictEqual(expected, value.summary)) throw new Error('Assessment summary does not match its findings.');
  return value;
}

export function scriptJson(value) {
  return JSON.stringify(value).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026').replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029');
}

export async function renderHtml(assessment = null) {
  if (assessment !== null) validateAssessment(assessment);
  const [template, style, script] = await Promise.all([
    readFile(new URL('../site/template.html', import.meta.url), 'utf8'),
    readFile(new URL('../site/styles.css', import.meta.url), 'utf8'),
    readFile(new URL('../site/app.js', import.meta.url), 'utf8')
  ]);
  const data = { assessment, categories, controls, sourceCatalog, catalogVersion, catalogDigest };
  return template.replace('<!--XRAY_STYLE-->', () => style)
    .replace('<!--XRAY_SAMPLE_LINK-->', () => assessment === null
      ? '<a class="button" href="sample.html">View a sample assessment (synthetic)</a>' : '')
    .replace('<!--XRAY_DATA-->', () => scriptJson(data))
    .replace('<!--XRAY_SCRIPT-->', () => script);
}

const cell = (value) => String(value).replaceAll('|', '\\|').replace(/[\r\n]/g, ' ');

export function renderMarkdown(assessment) {
  validateAssessment(assessment);
  const lines = [
    '# AKS X-Ray assessment',
    '', assessment.synthetic ? '**SYNTHETIC DEMO. Not a live cluster assessment.**' : '**Configuration observations from this collection. Not a compliance certification or penetration-test report.**',
    '', `- Platform: ${cell(assessment.target.platform)}`,
    `- Context: ${cell(assessment.target.context)}`,
    `- Binding: ${cell(assessment.target.binding.status)}`,
    `- Collected: ${assessment.collectedAt}`, `- Assessed: ${assessment.assessedAt}`,
    `- Catalogue: ${catalogVersion} (${catalogDigest})`,
    `- Profile: ${assessment.scope.profile}`,
    `- Categories: ${assessment.scope.categories.join(', ')}`,
    `- Namespaces: ${assessment.scope.namespaces?.join(', ') ?? 'all reachable'}; excluded: ${assessment.scope.excludedNamespaces.join(', ') || 'none'}`,
    `- Pass rate (evaluated controls): ${assessment.summary.alignmentPercent ?? 'unavailable'}${assessment.summary.alignmentPercent === null ? '' : '% of pass/fail controls only'}`,
    `- Evidence coverage: ${assessment.summary.evidenceCoveragePercent ?? 'unavailable'}% of applicable controls`,
    '', 'Manual review, unknown, error and not-run results are not passes. See the HTML report and JSON for observations and collection errors.',
    '', '| Control | Status | Severity | Finding |', '|---|---|---|---|'
  ];
  for (const result of assessment.results) {
    const control = controls.find((item) => item.id === result.id);
    lines.push(`| ${result.id} | ${result.status} | ${control.severity} | ${cell(result.message)} |`);
  }
  lines.push('', '## Official Microsoft guidance', '');
  for (const source of sourceCatalog.sources) lines.push(`- [${source.title}](${source.url})`);
  return `${lines.join('\n')}\n`;
}

export async function prepareOutput(path) {
  const directory = resolve(path ?? join('artifacts', `xray-${new Date().toISOString().replace(/[-:.]/g, '')}-${randomUUID().slice(0, 6)}`));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if ((await readdir(directory)).length) throw new Error(`Output directory must be empty; existing evidence is never overwritten: ${directory}`);
  return directory;
}

async function atomicWrite(path, text, replace) {
  if (!replace) {
    await writeFile(path, text, { flag: 'wx', mode: 0o600 });
    return;
  }
  const temporary = `${path}.pending`;
  await writeFile(temporary, text, { flag: 'w', mode: 0o600 });
  await rename(temporary, path);
}

export async function writeArtifacts(directory, { evidence, assessment, manifest }, { replace = false } = {}) {
  const files = {
    ...(evidence ? { 'evidence.json': `${JSON.stringify(evidence, null, 2)}\n` } : {}),
    'assessment.json': `${JSON.stringify(assessment, null, 2)}\n`,
    'report.html': await renderHtml(assessment),
    'assessment.md': renderMarkdown(assessment),
    ...(manifest ? { 'active-manifest.json': `${JSON.stringify(manifest, null, 2)}\n` } : {})
  };
  const checksums = { algorithm: 'sha256', files: {} };
  for (const [name, content] of Object.entries(files)) {
    await atomicWrite(join(directory, name), content, replace);
    checksums.files[name] = createHash('sha256').update(content).digest('hex');
  }
  await atomicWrite(join(directory, 'checksums.json'), `${JSON.stringify(checksums, null, 2)}\n`, replace);
}

export async function verifyArtifacts(directory) {
  const checksums = await readJson(join(directory, 'checksums.json'));
  const allowed = ['evidence.json', 'assessment.json', 'report.html', 'assessment.md', 'active-manifest.json'];
  if (checksums.algorithm !== 'sha256' || !isObject(checksums.files) || !Object.keys(checksums.files).length) throw new Error('Invalid checksum manifest.');
  for (const [name, expected] of Object.entries(checksums.files)) {
    if (!allowed.includes(name) || !/^[0-9a-f]{64}$/.test(expected)) throw new Error('Invalid checksum entry.');
    const actual = createHash('sha256').update(await readFile(join(directory, name))).digest('hex');
    if (actual !== expected) throw new Error(`Integrity mismatch: ${name}`);
  }
  return Object.keys(checksums.files).length;
}
