#!/usr/bin/env node
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { categories, catalogVersion, controls, selectControls, toolVersion } from '../src/catalog.mjs';
import { collect } from '../src/collector.mjs';
import { defaultScope } from '../src/evidence.mjs';
import { assess, exitCode } from '../src/engine.mjs';
import { runActive } from '../src/active.mjs';
import { prepareOutput, readJson, validateAssessment, verifyArtifacts, writeArtifacts } from '../src/report.mjs';
import { runCommand, commandFailure } from '../src/process.mjs';
import { demoEvidence } from '../examples/demo.mjs';

const help = `AKS X-Ray ${toolVersion} | Microsoft-guidance catalogue ${catalogVersion}

Commands:
  doctor   Check local Node, Azure CLI, kubectl and (for Local) aksarc availability
  catalog  List controls; no credentials or cluster required
  demo     Write synthetic evidence, JSON, Markdown and a standalone HTML report
  collect  Read-only Azure + Kubernetes collection, assessment and report
  assess   Reassess saved evidence offline
  report   Render a saved assessment offline
  active   Explicitly authorized isolated synthetic tests, then reassess
  verify   Verify an output directory's SHA-256 manifest

Read-only collection:
  node bin/aks-xray.mjs collect --platform cloud --context <context>
    --subscription <guid> --resource-group <group> --cluster <name>
    [--categories networking,storage] [--namespaces payments,orders]
    [--profile production|development] [--include-system]
    [--output <empty-directory>] [--fail-on high|medium|low|info|none]

Azure Local: use --platform local with AKS enabled by Arc on Azure Local.
Preinstall the aksarc Azure CLI extension. Collection never installs extensions,
logs in, downloads credentials, changes context, or applies cluster resources.

Offline:
  node bin/aks-xray.mjs catalog [--categories security] [--platform local] [--json]
  node bin/aks-xray.mjs demo [--platform cloud|local] [--output <empty-directory>]
  node bin/aks-xray.mjs assess --input <evidence.json> [--categories storage]
  node bin/aks-xray.mjs report --input <assessment.json>
  node bin/aks-xray.mjs verify --input <output-directory>

Active tests (never implied by collect, even with all categories):
  node bin/aks-xray.mjs active --input <evidence.json> --suite all
    --authorize-active --confirm-context <exact-context>
    [--requests 40] [--concurrency 2] [--duration-seconds 10]
    [--latency-budget-ms 2000] [--error-budget-percent 0]
    [--output <empty-directory>] [--fail-on high]
  Suites: connectivity, end-to-end, load, security, all.
  Hard caps: 200 requests, 4 workers, 30 seconds, 100 ms worker pacing.
  Synthetic jobs have 240-second deadlines. Exact owned namespace cleanup is
  attempted even on errors. No exploitation, node disruption or production load.

Exit codes: 0 completed (no selected severity gate failed); 1 severity gate failed;
2 invalid input, unavailable/partial evidence, unverified target or cleanup error.
Manual review and deliberately not-run tests are NOT passes.
Artifacts are sensitive inventory. Keep them private; the microsite is offline.
`;

const booleanOptions = new Set(['help', 'json', 'include-system', 'authorize-active']);
const valueOptions = new Set(['platform', 'context', 'subscription', 'resource-group', 'cluster', 'categories',
  'namespaces', 'profile', 'output', 'input', 'fail-on', 'suite', 'confirm-context',
  'requests', 'concurrency', 'duration-seconds', 'latency-budget-ms', 'error-budget-percent']);
const allowed = {
  doctor: ['platform'], catalog: ['categories', 'platform', 'json'], demo: ['platform', 'output', 'categories', 'profile'],
  collect: ['platform', 'context', 'subscription', 'resource-group', 'cluster', 'categories', 'namespaces', 'profile', 'include-system', 'output', 'fail-on'],
  assess: ['input', 'categories', 'output', 'fail-on'], report: ['input', 'output'], verify: ['input'],
  active: ['input', 'suite', 'authorize-active', 'confirm-context', 'requests', 'concurrency', 'duration-seconds',
    'latency-budget-ms', 'error-budget-percent', 'output', 'fail-on']
};

export function parseArgs(argv) {
  if (!argv.length || argv[0] === '--help' || argv[0] === '-h') return { command: 'help', options: {} };
  const command = argv[0];
  if (!(command in allowed)) throw new Error(`Unknown command: ${command}. Use --help.`);
  const options = {};
  for (let index = 1; index < argv.length; index++) {
    const match = argv[index].match(/^--([a-z-]+)(?:=(.*))?$/s);
    if (!match) throw new Error(`Unexpected argument: ${argv[index]}`);
    const key = match[1];
    if (Object.hasOwn(options, key)) throw new Error(`Duplicate option: --${key}`);
    if (key !== 'help' && !allowed[command].includes(key)) throw new Error(`Option --${key} is not valid for ${command}.`);
    if (booleanOptions.has(key)) {
      if (match[2] !== undefined) throw new Error(`--${key} does not accept a value.`);
      options[key] = true;
    } else if (valueOptions.has(key)) {
      const value = match[2] ?? argv[++index];
      if (!value || value.startsWith('--')) throw new Error(`--${key} needs a value.`);
      options[key] = value;
    } else throw new Error(`Unknown option: --${key}`);
  }
  return { command: options.help ? 'help' : command, options };
}

function csv(value, allowAll = false) {
  if (value === undefined || allowAll && value === 'all') return undefined;
  const values = value.split(',').map((part) => part.trim());
  if (values.some((part) => !part)) throw new Error('Comma-separated scope values cannot be empty.');
  return values;
}

function platformOption(value = 'cloud') {
  if (!['cloud', 'local'].includes(value)) throw new Error('--platform must be cloud or local.');
  return value;
}

function numberOption(value, name) {
  if (value === undefined) return undefined;
  if (!/^\d+(?:\.\d+)?$/.test(value) || !Number.isFinite(Number(value))) throw new Error(`--${name} must be a finite nonnegative number.`);
  return Number(value);
}

async function doctor(platform, log) {
  let errors = 0;
  log(`Node: ${process.version}`);
  for (const [file, args] of [
    ['az', ['version', '--output', 'json']], ['kubectl', ['version', '--client', '--output=json']],
    ...(platform === 'local' ? [['az', ['extension', 'show', '--name', 'aksarc', '--output', 'json']]] : [])
  ]) {
    try {
      const response = await runCommand(file, args);
      const data = JSON.parse(response.stdout);
      log(`${file}${args[0] === 'extension' ? ' aksarc' : ''}: available (${data['azure-cli'] ?? data.clientVersion?.gitVersion ?? data.version ?? 'installed'})`);
    } catch (error) {
      errors++;
      const failure = commandFailure(error);
      log(`${file}: ERROR ${failure.code}: ${failure.message}`);
    }
  }
  return errors ? 2 : 0;
}

export async function main(argv = process.argv.slice(2), { log = console.log, error = console.error } = {}) {
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node.js 22 or later is required.');
  const { command, options } = parseArgs(argv);
  if (command === 'help') { log(help); return 0; }
  if (command === 'catalog') {
    const selected = selectControls(csv(options.categories, true)).filter((control) => !options.platform || control.platforms.includes(platformOption(options.platform)));
    log(options.json ? JSON.stringify(selected, null, 2)
      : `${selected.length} controls; catalogue ${catalogVersion}\n${selected.map((control) =>
        `${control.id.padEnd(8)} ${control.category.padEnd(20)} ${control.mode.padEnd(8)} ${control.title}`).join('\n')}`);
    return 0;
  }
  if (command === 'doctor') return doctor(platformOption(options.platform), log);
  if (!['demo', 'collect'].includes(command) && !options.input) throw new Error(`--input is required for ${command}.`);
  if (command === 'verify') {
    log(`Verified ${await verifyArtifacts(resolve(options.input))} artifacts.`);
    return 0;
  }
  const scope = ['collect', 'demo'].includes(command) ? defaultScope({
    categories: csv(options.categories, true), namespaces: csv(options.namespaces),
    profile: options.profile, includeSystem: options['include-system'] === true
  }) : undefined;
  if (options['fail-on'] !== undefined && !['none', 'high', 'medium', 'low', 'info'].includes(options['fail-on'])) throw new Error('Invalid --fail-on severity.');
  let evidence;
  let assessment;
  if (command === 'demo') evidence = demoEvidence(platformOption(options.platform), scope);
  if (['assess', 'active'].includes(command)) evidence = await readJson(resolve(options.input));
  if (command === 'report') assessment = validateAssessment(await readJson(resolve(options.input)));
  if (command === 'assess') assessment = assess(evidence, { categories: csv(options.categories, true) ?? evidence.scope.categories });
  const directory = await prepareOutput(options.output);
  log(`Output: ${directory}`);
  if (command === 'collect') {
    evidence = await collect({
      platform: platformOption(options.platform), context: options.context, subscription: options.subscription,
      resourceGroup: options['resource-group'], cluster: options.cluster
    }, scope, { progress: error });
  }
  if (command === 'active') {
    const abort = new AbortController();
    const cancel = () => { error('Cancellation requested; attempting owned namespace cleanup.'); abort.abort(); };
    process.on('SIGINT', cancel);
    process.on('SIGTERM', cancel);
    try {
      evidence = await runActive(evidence, {
        suite: options.suite, authorizeActive: options['authorize-active'], confirmContext: options['confirm-context'],
        requests: numberOption(options.requests, 'requests'), concurrency: numberOption(options.concurrency, 'concurrency'),
        durationSeconds: numberOption(options['duration-seconds'], 'duration-seconds'),
        latencyBudgetMs: numberOption(options['latency-budget-ms'], 'latency-budget-ms'),
        errorBudgetPercent: numberOption(options['error-budget-percent'], 'error-budget-percent')
      }, {
        signal: abort.signal, progress: error,
        persist: (partial, manifest) => writeArtifacts(directory, { evidence: partial, assessment: assess(partial), manifest }, { replace: true })
      });
    } finally {
      process.off('SIGINT', cancel);
      process.off('SIGTERM', cancel);
    }
  }
  assessment ??= assess(evidence);
  if (command !== 'active') await writeArtifacts(directory, { evidence, assessment });
  log(`${assessment.synthetic ? 'SYNTHETIC DEMO | ' : ''}${assessment.results.length} controls | ${Object.entries(assessment.summary.counts)
    .map(([key, count]) => `${key}: ${count}`).join(' | ')}`);
  log(`Target binding: ${assessment.target.binding.status}. Open ${resolve(directory, 'report.html')}`);
  return command === 'report' ? 0 : exitCode(assessment, options['fail-on'] ?? 'none');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then((code) => { process.exitCode = code; }).catch((failure) => {
    console.error(`AKS X-Ray ERROR: ${failure.message}`);
    process.exitCode = 2;
  });
}
