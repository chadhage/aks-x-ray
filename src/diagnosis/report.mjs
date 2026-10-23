import { createHash } from 'node:crypto';
import { mkdir, readFile, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { markdownCell as cell, prepareOutput, readJson, scriptJson, writeArtifactFiles, writeArtifacts } from '../report.mjs';
import { validateEvidence } from '../evidence.mjs';
import { normalizeAssessment } from './config.mjs';
import { validateDiagnosis } from './engine.mjs';
import { targetClusterId } from '../collector.mjs';

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const artifactLimit = 100 * 1024 * 1024;

export async function renderDiagnosisHtml(value) {
  validateDiagnosis(value);
  const [template, baseStyle, style, script] = await Promise.all([
    readFile(new URL('../../site/diagnosis.html', import.meta.url), 'utf8'),
    readFile(new URL('../../site/styles.css', import.meta.url), 'utf8'),
    readFile(new URL('../../site/diagnosis.css', import.meta.url), 'utf8'),
    readFile(new URL('../../site/diagnosis.js', import.meta.url), 'utf8')
  ]);
  return template.replace('<!--DIAG_STYLE-->', () => `${baseStyle}\n${style}`)
    .replace('<!--DIAG_DATA-->', () => scriptJson(value)).replace('<!--DIAG_SCRIPT-->', () => script);
}

export function renderDiagnosisMarkdown(value) {
  validateDiagnosis(value);
  const lines = ['# AKS workload diagnosis', '',
    value.synthetic ? '**SYNTHETIC EXAMPLE. All observations and validation receipts are simulated. No live resources were tested.**'
      : '**Evidence-led diagnosis. Not a compliance certification, CVSS assessment or proof that every attack path was tested.**',
    '', `- Assessed: ${value.assessedAt}`, `- Strategies: ${value.selection.strategies.join(', ')}`,
    `- Scenario: ${cell(value.scenario.name)}; criticality: ${value.scenario.businessCriticality}; sensitivity: ${value.scenario.dataSensitivity}`,
    `- Highest review priority: ${value.summary.highestRisk ?? 'Unscored'}; higher is worse`,
    `- Source coverage: ${value.coverage.sources.available}/${value.coverage.sources.total}; graph: ${value.graph.nodes.length} nodes, ${value.graph.edges.length} edges`,
    '', value.methodology.risk, '', value.methodology.confidence,
    '', '## Reconciled risk findings', '', '| Finding | Status | Evidence tier | Risk | Confidence | Strategies |',
    '|---|---|---|---|---|---|'];
  for (const finding of value.findings) lines.push(`| ${cell(finding.title)} | ${finding.status} | ${finding.evidenceTier} | ${finding.risk.score ?? 'Unscored'} | ${finding.confidence.score} | ${finding.strategies.join(', ')} |`);
  lines.push('', '## Attack hypotheses and prerequisites', '');
  const nodes = new Map(value.graph.nodes.map((node) => [node.id, node]));
  for (const finding of value.findings.filter((item) => item.paths.length)) {
    lines.push(`### ${cell(finding.title)}`, '', cell(finding.description), '');
    for (const path of finding.paths) {
      lines.push(`- Path: ${path.nodes.map((id) => cell(nodes.get(id)?.name ?? id)).join(' -> ')}`);
      for (const prerequisite of path.prerequisites) lines.push(`  - ${cell(prerequisite.id)}: **${prerequisite.status}**. ${cell(prerequisite.description)}`);
    }
  }
  lines.push('', '## Permission-aware stage plan', '', '| Stage | Test | Context | Namespace | Status | Permission | Reason |', '|---|---|---|---|---|---|---|');
  for (const action of value.plan.actions) lines.push(`| ${action.stage} | ${action.testId} | ${cell(action.context)} | ${cell(action.ownedNamespace ?? action.namespace ?? 'cluster / owned canary')} | ${action.status} | ${action.permissionStatus} | ${cell(action.reasons.join(' '))} |`);
  lines.push('', '## Namespace and configuration-area views', '', 'These are projections of the reconciled findings, not independent scoring engines.', '');
  for (const [title, views] of [['Namespaces', value.views.namespaces], ['Configuration areas', value.views.areas]]) {
    lines.push(`### ${title}`, '', '| View | Findings | Highest risk | Conflicts |', '|---|---|---|---|');
    for (const view of views) lines.push(`| ${cell(view.id)} | ${view.findingIds.length} | ${view.highestRisk ?? 'Unscored'} | ${view.conflicts} |`);
    lines.push('');
  }
  lines.push('## Evidence gaps and limits', '');
  if (!value.gaps.length) lines.push('No recorded gaps in the selected evidence. This is not proof of complete discovery or vulnerability absence.');
  for (const gap of value.gaps) lines.push(`- **${cell(gap.code)}**: ${cell(gap.reason ?? gap.subject ?? gap.sourceId ?? 'See structured graph evidence.')}`);
  lines.push('', '## Finding evidence and reconciliation', '');
  for (const finding of value.findings) {
    lines.push(`### ${cell(finding.title)}`, '', cell(finding.description), '', `- Subject: ${cell(finding.subject)}`,
      `- Namespace: ${cell(finding.scope.namespace ?? 'global / Azure resource')}`,
      `- Evidence references: ${finding.evidenceRefs.map(cell).join(', ')}`,
      `- Validation receipts: ${finding.validationIds.map(cell).join(', ') || 'none'}`,
      `- Next action: ${cell(finding.recommendation)}`);
    for (const limitation of finding.confidence.limitations) lines.push(`- Limitation: ${cell(limitation)}`);
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

export async function writeDiagnosisFiles(directory, diagnosis, { manifest, replace = false } = {}) {
  validateDiagnosis(diagnosis);
  const files = {
    'diagnosis.json': json(diagnosis), 'graph.json': json(diagnosis.graph), 'assessment-plan.json': json(diagnosis.plan),
    'validation-records.json': json(diagnosis.validationRecords),
    ...(manifest ? { 'diagnosis-evidence.json': json(manifest) } : {}),
    'diagnosis.md': renderDiagnosisMarkdown(diagnosis), 'report.html': await renderDiagnosisHtml(diagnosis)
  };
  if (Object.values(files).some((content) => Buffer.byteLength(content) > artifactLimit)) throw new Error('Diagnosis artifact exceeds the 100 MiB limit; narrow the assessment scope.');
  return writeArtifactFiles(directory, files, { replace });
}

export async function writeDiagnosisWorkspace(path, bundles, diagnosis, { prepared = false } = {}) {
  const directory = prepared ? resolve(path) : await prepareOutput(path);
  const references = [];
  const ordered = [...bundles].sort((a, b) => (a.sources.cluster?.data?.id ?? targetClusterId(a.target)).localeCompare(b.sources.cluster?.data?.id ?? targetClusterId(b.target), 'en'));
  for (const [index, evidence] of ordered.entries()) {
    const name = `cluster-${String(index + 1).padStart(3, '0')}`;
    const child = join(directory, name);
    await mkdir(child, { recursive: true, mode: 0o700 });
    const checksums = await writeArtifactFiles(child, { 'evidence.json': json(evidence) }, { replace: prepared });
    references.push({ path: `${name}/evidence.json`, sha256: checksums.files['evidence.json'] });
    const assessment = diagnosis.configurationAssessments.find((report) => report.target.context === evidence.target.context);
    if (assessment) {
      const configuration = join(child, 'configuration');
      await mkdir(configuration, { recursive: true, mode: 0o700 });
      await writeArtifacts(configuration, { evidence, assessment }, { replace: prepared });
    }
  }
  const manifest = {
    schemaVersion: '2.0', kind: 'aks-xray-diagnosis-evidence',
    tenant: diagnosis.graph.scope.tenant, subscriptions: diagnosis.graph.scope.subscriptions,
    scenario: diagnosis.scenario, assessment: diagnosis.assessment, bundles: references,
    validationRecords: diagnosis.validationRecords
  };
  await writeDiagnosisFiles(directory, diagnosis, { manifest, replace: prepared });
  return { directory, manifest };
}

export async function readDiagnosisInput(path) {
  let input = resolve(path);
  const info = await stat(input);
  if (info.isDirectory()) {
    try { await stat(join(input, 'diagnosis-evidence.json')); input = join(input, 'diagnosis-evidence.json'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      input = join(input, 'evidence.json');
    }
  }
  const value = await readJson(input, { maxBytes: artifactLimit });
  if (value.schemaVersion === '1.0' && value.sources) {
    const evidence = validateEvidence(value);
    return { bundles: [evidence], tenant: evidence.target.tenant,
      subscriptions: evidence.scope.authorizedSubscriptions ?? [evidence.target.subscription],
      scenario: evidence.scope.scenario, assessment: normalizeAssessment({ strategies: ['graph', 'exposure', 'attack-paths'], stages: ['passive'] }),
      validations: [] };
  }
  if (value.schemaVersion !== '2.0' || value.kind !== 'aks-xray-diagnosis-evidence' || !Array.isArray(value.bundles)
    || !value.bundles.length || value.bundles.length > 100) throw new Error('Use a diagnosis evidence manifest or a versioned evidence bundle.');
  const root = await realpath(dirname(input));
  const bundles = [];
  let totalBytes = 0;
  for (const reference of value.bundles) {
    if (!/^cluster-\d{3}\/evidence\.json$/.test(reference.path) || !/^[0-9a-f]{64}$/.test(reference.sha256)) throw new Error('Invalid diagnosis evidence path reference or hash.');
    const resolved = await realpath(join(root, ...reference.path.split('/')));
    const child = relative(root, resolved);
    if (isAbsolute(child) || child === '..' || child.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) throw new Error('Evidence reference resolves outside its dataset scope.');
    const size = (await stat(resolved)).size;
    totalBytes += size;
    if (size > artifactLimit || totalBytes > artifactLimit) throw new Error('Diagnosis evidence exceeds the 100 MiB total input limit; narrow the scope.');
    const bytes = await readFile(resolved);
    if (createHash('sha256').update(bytes).digest('hex') !== reference.sha256) throw new Error('Diagnosis evidence integrity hash mismatch.');
    bundles.push(validateEvidence(await readJson(resolved, { maxBytes: artifactLimit })));
  }
  return { bundles, tenant: value.tenant ?? undefined, subscriptions: value.subscriptions,
    scenario: value.scenario, assessment: normalizeAssessment(value.assessment), validations: value.validationRecords ?? [] };
}
