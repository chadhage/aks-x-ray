import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { collect } from '../collector.mjs';
import { prepareOutput, writeArtifactFiles } from '../report.mjs';
import { runCommand } from '../process.mjs';
import { diagnose, diagnosisExitCode } from './engine.mjs';
import { buildGraph, GraphLimitError } from './graph.mjs';
import { writeDiagnosisWorkspace } from './report.mjs';
import { executeValidationStages } from './validation.mjs';

export async function runDiagnosisAudit(config, {
  output, runner = runCommand, log = console.log, error = console.error, now = () => new Date(),
  failOn = 'none', signal, configurationEvaluator
} = {}) {
  const directory = await prepareOutput(output);
  log(`Output: ${directory}`);
  const bundles = [];
  let evidenceBytes = 0;
  for (const [index, target] of config.targets.entries()) {
    const child = await prepareOutput(join(directory, `cluster-${String(index + 1).padStart(3, '0')}`));
    const evidence = await collect(target, config.scope, {
      runner: (file, args, options) => runner(file, args, { ...options, signal }), now, progress: error
    });
    const content = `${JSON.stringify(evidence, null, 2)}\n`;
    await writeArtifactFiles(child, { 'evidence.json': content });
    evidenceBytes += Buffer.byteLength(content);
    if (evidenceBytes > 100 * 1024 * 1024) throw new Error(`Diagnosis evidence exceeds the 100 MiB in-memory dataset limit. Collected evidence is retained in ${directory}; split the assessment scope.`);
    bundles.push(evidence);
  }
  let graphLimited = false;
  try {
    buildGraph(bundles, { tenant: config.tenant, subscriptions: config.subscriptions, strategies: config.assessment.strategies,
      maxNodes: config.assessment.maxGraphNodes, maxEdges: config.assessment.maxGraphEdges });
  } catch (failure) {
    if (!(failure instanceof GraphLimitError)) throw failure;
    graphLimited = true;
    error('Graph size limit reached. Validation is not executed against an incomplete assessment context.');
  }
  const validation = graphLimited ? { bundles, records: [] } : await executeValidationStages(bundles, config.assessment, {
    runner, now, signal, progress: error,
    persist: async (partial, manifest, { action }) => {
      const child = join(directory, 'validations', action.id.split(':')[1]);
      await mkdir(child, { recursive: true, mode: 0o700 });
      await writeArtifactFiles(child, {
        'evidence.json': `${JSON.stringify(partial, null, 2)}\n`,
        'active-manifest.json': `${JSON.stringify(manifest, null, 2)}\n`
      }, { replace: true });
    }
  });
  const diagnosis = diagnose(validation.bundles, {
    tenant: config.tenant, subscriptions: config.subscriptions, scenario: config.scope.scenario,
    assessment: config.assessment, validations: validation.records, now: now(), configurationEvaluator
  });
  await writeDiagnosisWorkspace(directory, validation.bundles, diagnosis, { prepared: true });
  log(`${diagnosis.synthetic ? 'SYNTHETIC | ' : ''}Diagnosis strategies: ${diagnosis.selection.strategies.join(', ')} | ${diagnosis.findings.length} reconciled findings | ${diagnosis.graph.nodes.length} nodes | ${diagnosis.graph.edges.length} edges.`);
  log(`Open ${join(directory, 'report.html')}`);
  return { code: diagnosisExitCode(diagnosis, failOn), directory, diagnosis };
}
