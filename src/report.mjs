import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { categories, controls, sourceCatalog, catalogVersion, catalogDigest, statuses } from './catalog.mjs';
import { validateScope } from './evidence.mjs';
import { summarize } from './engine.mjs';
import { isObject, namespacedSources } from './projection.mjs';
import { rating, ratingRuntime } from './scoring.mjs';
import { validateIdentityScope } from './scope.mjs';

export async function readJson(path, { maxBytes = 20 * 1024 * 1024 } = {}) {
  const info = await stat(path);
  if (!info.isFile() || info.size > maxBytes) throw new Error(`Input must be a JSON file no larger than ${Math.round(maxBytes / 1024 / 1024)} MiB.`);
  const text = await readFile(path, 'utf8');
  try { return JSON.parse(text); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error('Input contains malformed JSON; file contents are not printed.');
    throw error;
  }
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
  validateIdentityScope(value.target, value.scope);
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
  rating.validate(value);
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
  const data = { assessment, categories, controls, sourceCatalog, catalogVersion, catalogDigest, namespacedSources: [...namespacedSources] };
  return template.replace('<!--XRAY_STYLE-->', () => style)
    .replace('<!--XRAY_SAMPLE_LINK-->', () => assessment === null
      ? '<a class="button" href="sample.html">View a sample assessment (synthetic)</a>' : '')
    .replace('<!--XRAY_DATA-->', () => scriptJson(data))
    .replace('<!--XRAY_SCRIPT-->', () => `${ratingRuntime.toString()}\n${script}`);
}

export const markdownCell = (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('|', '\\|').replace(/[\r\n]/g, ' ');
const cell = markdownCell;
const scoreText = (value) => value === null ? 'Unscored' : `${value}/100`;

export function renderMarkdown(assessment) {
  validateAssessment(assessment);
  const lines = [
    '# AKS X-Ray assessment',
    '', assessment.synthetic ? '**SYNTHETIC DEMO. Not a live cluster assessment.**' : '**Configuration observations from this collection. Not a compliance certification or penetration-test report.**',
    '', `- Platform: ${cell(assessment.target.platform)}`,
    `- Context: ${cell(assessment.target.context)}`,
    `- Binding: ${cell(assessment.target.binding.status)}${assessment.target.binding.mode === 'arm-only' ? ' (ARM only; Kubernetes correlation was not authorized)' : ''}`,
    `- Collected: ${assessment.collectedAt}`, `- Assessed: ${assessment.assessedAt}`,
    `- Catalogue: ${catalogVersion} (${catalogDigest})`,
    `- Profile: ${assessment.scope.profile}`,
    ...(assessment.scope.scenario ? [`- Scenario: ${cell(assessment.scope.scenario.name)}`,
      `- Intended API: ${assessment.scope.scenario.apiAccess}; minimum replicas: ${assessment.scope.scenario.minimumReplicas}; minimum zones: ${assessment.scope.scenario.minimumZones}`,
      `- Approved registries: ${assessment.scope.scenario.allowedRegistries.map(cell).join(', ') || 'not specified'}`] : []),
    ...(assessment.target.tenant ? [`- Tenant: ${cell(assessment.target.tenant)}`,
      `- Strategies: ${assessment.scope.strategies.join(', ')}`] : []),
    `- Categories: ${assessment.scope.categories.join(', ')}`,
    `- Namespaces: ${assessment.scope.namespaces?.join(', ') ?? 'all reachable'}; excluded: ${assessment.scope.excludedNamespaces.join(', ') || 'none'}`,
    `- Pass rate (evaluated controls): ${assessment.summary.alignmentPercent ?? 'unavailable'}${assessment.summary.alignmentPercent === null ? '' : '% of pass/fail controls only'}`,
    `- Evidence coverage: ${assessment.summary.evidenceCoveragePercent ?? 'unavailable'}% of applicable controls`,
    '', 'Manual review, unknown, error and not-run results are not passes. See the HTML report and JSON for observations and collection errors.',
    '', `Overall scored subset: **${scoreText(assessment.ratings.overall.score)}**; coverage: ${assessment.ratings.overall.coveragePercent ?? 'unavailable'}%.`,
    '', assessment.ratings.methodology.explanation
  ];
  for (const [title, groups] of [
    ['Configuration-area scores', assessment.ratings.areas],
    ['Azure Well-Architected pillars', assessment.ratings.pillars],
    ['Namespace scores', assessment.ratings.namespaces]
  ]) {
    lines.push('', `## ${title}`, '', '| Area / namespace | Score (1-100) | Coverage | Unscored |', '|---|---|---|---|');
    for (const group of groups) lines.push(`| ${cell(group.title)} | ${scoreText(group.score)} | ${group.coveragePercent ?? 'unavailable'}% | ${group.unscored} |`);
    if (!groups.length) lines.push('', 'No namespace-scoped inventory was available in the selected collection scope; this is not evidence of namespace security.');
  }
  lines.push('', '## Configuration assertions', '', '| Control | Status | Severity | Score (1-100) | Finding |', '|---|---|---|---|---|');
  for (const result of assessment.results) {
    const control = controls.find((item) => item.id === result.id);
    lines.push(`| ${result.id} | ${result.status} | ${control.severity} | ${scoreText(result.score)} | ${cell(result.message)} |`);
  }
  for (const entry of assessment.namespaceResults) {
    lines.push('', `### Namespace: ${cell(entry.namespace)}`, '', '| Control | Status | Score (1-100) | Finding |', '|---|---|---|---|');
    for (const result of entry.results) lines.push(`| ${result.id} | ${result.status} | ${scoreText(result.score)} | ${cell(result.message)} |`);
  }
  const failures = assessment.collection.filter((source) => source.status === 'error');
  if (failures.length) {
    lines.push('', '## Collection errors', '');
    for (const source of failures) {
      lines.push(`- ${cell(source.sourceId)}: ${cell(source.error.code)}: ${cell(source.error.message)}`);
      for (const failure of source.failures ?? []) lines.push(`  - ${cell(failure.resourceId)}: ${cell(failure.error.code)}: ${cell(failure.error.message)}`);
    }
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
  return writeArtifactFiles(directory, files, { replace });
}

export async function writeArtifactFiles(directory, files, { replace = false } = {}) {
  if (!isObject(files) || !Object.keys(files).length) throw new Error('Artifact files are required.');
  const checksums = { algorithm: 'sha256', files: {} };
  for (const [name, content] of Object.entries(files)) {
    if (!/^[a-z0-9][a-z0-9.-]*$/i.test(name) || name === 'checksums.json' || typeof content !== 'string') throw new Error('Invalid artifact filename or content.');
    await atomicWrite(join(directory, name), content, replace);
    checksums.files[name] = createHash('sha256').update(content).digest('hex');
  }
  await atomicWrite(join(directory, 'checksums.json'), `${JSON.stringify(checksums, null, 2)}\n`, replace);
  return checksums;
}

export async function writeAuditIndex(directory, index) {
  const lines = ['# AKS X-Ray multi-target audit', '', `Scenario: ${cell(index.scope.scenario.name)}.`,
    '', 'Each target has its own configuration-area and namespace report. No live exploitation or secret collection was performed.',
    '', '| Target | Binding | Score (1-100) | Coverage | Exit code | Report |', '|---|---|---|---|---|---|'];
  for (const run of index.runs) {
    lines.push(`| ${cell(run.target.cluster)} | ${run.target.binding.status} | ${scoreText(run.rating.score)} | ${run.rating.coveragePercent ?? 'unavailable'}% | ${run.code} | [HTML report](./${run.directory}/report.html) |`);
  }
  const files = { 'audit.json': `${JSON.stringify(index, null, 2)}\n`, 'audit.md': `${lines.join('\n')}\n` };
  return writeArtifactFiles(directory, files);
}

export async function verifyArtifacts(directory) {
  const checksums = await readJson(join(directory, 'checksums.json'));
  const allowed = ['evidence.json', 'assessment.json', 'report.html', 'assessment.md', 'active-manifest.json', 'audit.json', 'audit.md',
    'diagnosis.json', 'graph.json', 'assessment-plan.json', 'diagnosis-evidence.json', 'diagnosis.md', 'validation-records.json'];
  if (checksums.algorithm !== 'sha256' || !isObject(checksums.files) || !Object.keys(checksums.files).length) throw new Error('Invalid checksum manifest.');
  for (const [name, expected] of Object.entries(checksums.files)) {
    if (!allowed.includes(name) || !/^[0-9a-f]{64}$/.test(expected)) throw new Error('Invalid checksum entry.');
    const actual = createHash('sha256').update(await readFile(join(directory, name))).digest('hex');
    if (actual !== expected) throw new Error(`Integrity mismatch: ${name}`);
  }
  return Object.keys(checksums.files).length;
}
