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
import { applyRuntimeParameters, buildAuditPlan, deviceLogin, discoverClusters, runAudit } from '../src/audit.mjs';
import { diagnose, diagnosisExitCode, validateDiagnosis } from '../src/diagnosis/engine.mjs';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';
import { readDiagnosisInput, writeDiagnosisFiles, writeDiagnosisWorkspace } from '../src/diagnosis/report.mjs';
import { diagnosisDemo } from '../examples/diagnosis-demo.mjs';

const help = `AKS X-Ray ${toolVersion} | Microsoft-guidance catalogue ${catalogVersion}

Commands:
  login    Explicit Azure CLI device-code login and tenant/subscription verification
  discover List AKS targets only in explicitly authorized tenant/subscriptions
  audit    Assess a parameterized, explicitly authorized multi-target JSON config
  diagnose Reconcile saved evidence using one or multiple independent strategies
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
logs in implicitly, downloads credentials, changes context, or applies resources.

Parameterized Blue Team workflow:
  node bin/aks-xray.mjs login --tenant <guid> --subscriptions <guid,guid>
  node bin/aks-xray.mjs discover --tenant <guid> --subscriptions <guid,guid>
    --authorize-readonly
  node bin/aks-xray.mjs audit --config <audit-config.json> [--dry-run]
    [--tenant <guid>] [--subscriptions <guid,guid>]
    [--target-selection named|default-subscription-only|all-accessible-clusters]
    [--output <empty-directory>] [--fail-on high|medium|low|info|none]
  Tenant and subscription GUIDs are invoker runtime parameters. Supply them in
  a local config copy and/or overlay them with --tenant and --subscriptions.
  They are never inferred from the CLI default account or Azure MCP default.
  Both Azure CLI device-code login and an already signed-in Azure MCP identity
  are supported collection planes; this CLI collects through Azure CLI.
  targetSelection: named (explicit targets), default-subscription-only
  (exactly one subscription, discover clusters) or all-accessible-clusters
  (discover every AKS cluster in the authorized subscriptions).
  Only login signs in. Device codes remain in the terminal, never in reports.
  With assessment.strategies, audit uses the graph/risk-first diagnosis engine.
  Select graph, exposure, attack-paths, validation, and/or configuration.
  --assessment-strategies graph,exposure,attack-paths overrides that selection.
  Collection strategies are separate: choosing an analysis never grants more access.
  Non-mutating/intrusive stages require separate exact-context expiring approvals.
  Intrusive mutation additionally requires a fresh complete permission preflight.

Offline diagnosis and alternative-strategy demo:
  node bin/aks-xray.mjs diagnose --input <diagnosis-evidence.json|evidence.json>
    --assessment-strategies graph,exposure,attack-paths [--output <empty-directory>]
  node bin/aks-xray.mjs demo --assessment-strategies graph,exposure,attack-paths,validation

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
Artifacts contain sensitive inventory. Keep them private; HTML reports run offline.
`;

const booleanOptions = new Set(['help', 'json', 'include-system', 'authorize-active', 'authorize-readonly', 'dry-run']);
const valueOptions = new Set(['platform', 'context', 'subscription', 'resource-group', 'cluster', 'categories',
  'namespaces', 'profile', 'output', 'input', 'fail-on', 'suite', 'confirm-context',
  'requests', 'concurrency', 'duration-seconds', 'latency-budget-ms', 'error-budget-percent', 'tenant', 'subscriptions', 'config',
  'assessment-strategies', 'validation-stages', 'target-selection']);
const allowed = {
  login: ['tenant', 'subscriptions'], discover: ['tenant', 'subscriptions', 'authorize-readonly'],
  audit: ['config', 'dry-run', 'output', 'fail-on', 'assessment-strategies', 'validation-stages',
    'tenant', 'subscriptions', 'target-selection'],
  diagnose: ['input', 'output', 'assessment-strategies', 'fail-on'],
  doctor: ['platform'], catalog: ['categories', 'platform', 'json'], demo: ['platform', 'output', 'categories', 'profile', 'assessment-strategies'],
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

export async function main(argv = process.argv.slice(2), { log = console.log, error = console.error, runner = runCommand } = {}) {
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node.js 22 or later is required.');
  const { command, options } = parseArgs(argv);
  if (command === 'help') { log(help); return 0; }
  if (options['fail-on'] !== undefined && !['none', 'high', 'medium', 'low', 'info'].includes(options['fail-on'])) throw new Error('Invalid --fail-on severity.');
  if (command === 'catalog') {
    const selected = selectControls(csv(options.categories, true)).filter((control) => !options.platform || control.platforms.includes(platformOption(options.platform)));
    log(options.json ? JSON.stringify(selected, null, 2)
      : `${selected.length} controls; catalogue ${catalogVersion}\n${selected.map((control) =>
        `${control.id.padEnd(8)} ${control.category.padEnd(20)} ${control.mode.padEnd(8)} ${control.title}`).join('\n')}`);
    return 0;
  }
  if (command === 'doctor') return doctor(platformOption(options.platform), log);
  if (command === 'login' || command === 'discover') {
    const input = { tenant: options.tenant, subscriptions: csv(options.subscriptions), authorizeReadOnly: options['authorize-readonly'] };
    const result = await (command === 'login' ? deviceLogin : discoverClusters)(input, { runner });
    log(JSON.stringify(result, null, 2));
    return 0;
  }
  if (command === 'audit') {
    if (!options.config) throw new Error('--config is required for audit.');
    let config = applyRuntimeParameters(await readJson(resolve(options.config)), {
      tenant: options.tenant,
      subscriptions: csv(options.subscriptions),
      targetSelection: options['target-selection']
    });
    if (options['assessment-strategies'] !== undefined || options['validation-stages'] !== undefined) config = {
      ...config, assessment: { ...(config.assessment ?? { strategies: ['graph', 'exposure', 'attack-paths'] }),
        ...(options['assessment-strategies'] ? { strategies: csv(options['assessment-strategies']) } : {}),
        ...(options['validation-stages'] ? { stages: csv(options['validation-stages']) } : {}) }
    };
    if (options['dry-run']) {
      log(JSON.stringify(buildAuditPlan(config), null, 2));
      return 0;
    }
    const abort = new AbortController();
    const cancel = () => { error('Cancellation requested; stopping validation and attempting owned canary cleanup.'); abort.abort(); };
    process.on('SIGINT', cancel);
    process.on('SIGTERM', cancel);
    try { return (await runAudit(config, { output: options.output, failOn: options['fail-on'], runner, log, error, signal: abort.signal })).code; }
    finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
  }
  if (command === 'diagnose' || command === 'demo' && options['assessment-strategies']) {
    if (command === 'diagnose' && !options.input) throw new Error('--input is required for diagnose.');
    const input = command === 'demo' ? diagnosisDemo(csv(options['assessment-strategies'])) : await readDiagnosisInput(resolve(options.input));
    const assessment = normalizeAssessment({ ...input.assessment, stages: ['passive'],
      ...(options['assessment-strategies'] ? { strategies: csv(options['assessment-strategies']) } : {}) });
    const result = diagnose(input.bundles, { ...input, assessment, now: input.now ?? new Date() });
    const directory = await prepareOutput(options.output);
    await writeDiagnosisWorkspace(directory, input.bundles, result, { prepared: true });
    if (command === 'diagnose') log('Offline reconciliation only: no collection or new validation was executed. Recorded receipts retain their original scope and timestamps.');
    log(`${result.synthetic ? 'SYNTHETIC | ' : ''}${result.selection.strategies.join(', ')} | ${result.findings.length} reconciled findings. Open ${resolve(directory, 'report.html')}`);
    return diagnosisExitCode(result, options['fail-on'] ?? 'none');
  }
  if (command === 'report' && options.input) {
    const input = await readJson(resolve(options.input), { maxBytes: 100 * 1024 * 1024 });
    if (input.kind === 'aks-xray-diagnosis') {
      const diagnosis = validateDiagnosis(input);
      const directory = await prepareOutput(options.output);
      await writeDiagnosisFiles(directory, diagnosis);
      log(`Open ${resolve(directory, 'report.html')}`);
      return 0;
    }
  }
  if (!['demo', 'collect'].includes(command) && !options.input) throw new Error(`--input is required for ${command}.`);
  if (command === 'verify') {
    log(`Verified ${await verifyArtifacts(resolve(options.input))} artifacts.`);
    return 0;
  }
  const scope = ['collect', 'demo'].includes(command) ? defaultScope({
    categories: csv(options.categories, true), namespaces: csv(options.namespaces),
    profile: options.profile, includeSystem: options['include-system'] === true
  }) : undefined;
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
    }, scope, { progress: error, runner });
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
