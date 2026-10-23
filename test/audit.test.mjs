import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, parseArgs } from '../bin/aks-xray.mjs';
import { demoEvidence, demoRaw } from '../examples/demo.mjs';
import { CommandError } from '../src/process.mjs';

const tenant = '10000000-0000-0000-0000-000000000001';
const subscription = demoEvidence().target.subscription;
const otherSubscription = '00000000-0000-0000-0000-000000000002';
const audit = () => import('../src/audit.mjs');
const configuration = () => ({
  tenant, subscriptions: [subscription],
  authorization: { readOnly: true },
  strategies: ['azure', 'kubernetes', 'iam', 'policy', 'defender', 'advisor', 'dependencies'],
  scenario: { name: 'Private production', profile: 'production', apiAccess: 'private', minimumReplicas: 3, minimumZones: 3 },
  targets: [{ ...demoEvidence().target, binding: undefined }]
});
const account = (id = subscription, tenantId = tenant) => ({ id, tenantId, state: 'Enabled', accessToken: 'NEVER_EXPORT' });

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'aks-xray-audit-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('CLI exposes device login, scoped discovery, and a dry-run audit without accepting implicit active approval', () => {
  assert.equal(parseArgs(['login', '--tenant', tenant, '--subscriptions', subscription]).command, 'login');
  assert.equal(parseArgs(['discover', '--tenant', tenant, '--subscriptions', subscription, '--authorize-readonly']).options['authorize-readonly'], true);
  assert.equal(parseArgs(['audit', '--config', 'assessment-config.json', '--dry-run']).options['dry-run'], true);
  assert.equal(parseArgs(['audit', '--config', 'assessment-config.json', '--tenant', tenant,
    '--subscriptions', subscription, '--target-selection', 'all-accessible-clusters']).options['target-selection'],
    'all-accessible-clusters');
  assert.throws(() => parseArgs(['audit', '--authorize-active']), /not valid/);
  assert.throws(() => parseArgs(['discover', '--authorize-readonly=false']), /does not accept/);
});

test('audit configuration normalizes explicit runtime scope without modifying caller input', async () => {
  const { validateAuditConfig } = await audit();
  const input = configuration();
  delete input.targets[0].binding;
  const before = structuredClone(input);
  const config = validateAuditConfig(input);
  assert.deepEqual(input, before);
  assert.equal(config.tenant, tenant);
  assert.deepEqual(config.subscriptions, [subscription]);
  assert.equal(config.targets[0].tenant, tenant);
  assert.equal(config.scope.profile, 'production');
  assert.equal(config.scope.scenario.minimumReplicas, 3);
  assert.deepEqual(config.scope.strategies, input.strategies);
  assert.deepEqual(config.scope.authorizedSubscriptions, [subscription]);
  assert.equal(config.scope.authorization.readOnly, true);
});

test('audit config refuses missing consent, tenant and subscription ambiguity, unknown strategies and scope expansion', async () => {
  const { validateAuditConfig } = await audit();
  const cases = [
    [(value) => { value.authorization.readOnly = false; }, /readOnly.*true/],
    [(value) => { value.authorization.readOnly = 'true'; }, /readOnly.*true/],
    [(value) => { delete value.tenant; }, /tenant.*GUID/i],
    [(value) => { value.subscriptions = ['default']; }, /subscription.*GUID/i],
    [(value) => { value.subscriptions.push(subscription.toUpperCase()); }, /duplicate.*subscription/i],
    [(value) => { value.targets[0].subscription = otherSubscription; }, /authorized subscription/i],
    [(value) => { value.strategies.push('exploit'); }, /strategy/i],
    [(value) => { value.strategies = ['kubernetes']; }, /azure.*required/i],
    [(value) => { value.strategies.push('azure'); }, /duplicate.*strateg/i],
    [(value) => { value.targets.push({ ...value.targets[0] }); }, /duplicate.*target/i],
    [(value) => { value.targets[0].context = '--current'; }, /context/i],
    [(value) => { value.scenario.minimumReplicas = 0; }, /minimumReplicas/],
    [(value) => { value.scenario.minimumZones = 4; }, /minimumZones/],
    [(value) => { value.scenario.apiAccess = 'unrestricted'; }, /apiAccess/],
    [(value) => { value.scenario.miniumReplicas = 3; }, /Unknown.*scenario/],
    [(value) => { value.stratgeies = []; }, /Unknown.*config/i],
    [(value) => { value.relatedResourceIds = [`/subscriptions/${otherSubscription}/resourceGroups/dependencies/providers/Microsoft.KeyVault/vaults/private-vault`]; }, /authorized subscription/i],
    [(value) => { value.targetSelection = 'everywhere'; }, /targetSelection/],
    [(value) => { value.targetSelection = 'default-subscription-only'; value.subscriptions.push(otherSubscription); }, /exactly one/],
    [(value) => { value.targetSelection = 'named'; value.targets = []; }, /Named target selection/],
    [(value) => { value.targetSelection = 'all-accessible-clusters'; value.targets = []; }, /context mapping/]
  ];
  for (const [mutate, expected] of cases) {
    const value = configuration();
    delete value.targets[0].binding;
    mutate(value);
    assert.throws(() => validateAuditConfig(value), expected);
  }
});

test('device login uses only the requested tenant, inherited terminal IO and bounded wait, then verifies every subscription', async () => {
  const { deviceLogin } = await audit();
  const calls = [];
  const result = await deviceLogin({ tenant, subscriptions: [subscription, otherSubscription] }, {
    runner: async (file, args, options) => {
      calls.push({ file, args, options });
      return { stdout: args[0] === 'login' ? '' : JSON.stringify(account(args[args.indexOf('--subscription') + 1])) };
    }
  });
  assert.deepEqual(calls[0].args, ['login', '--tenant', tenant, '--use-device-code', '--output', 'none']);
  assert.equal(calls[0].options.interactive, true);
  assert.equal(calls[0].options.timeoutMs, 600_000);
  assert.equal(calls[0].options.env.AZURE_CORE_LOGIN_EXPERIENCE_V2, 'off');
  assert.deepEqual(calls.slice(1).map(({ args }) => args[args.indexOf('--subscription') + 1]), [subscription, otherSubscription]);
  assert.ok(calls.every(({ file }) => file === 'az'));
  assert.ok(!calls.some(({ args }) => args.includes('set') || args.includes('get-access-token')));
  assert.deepEqual(result.subscriptions, [account(subscription), account(otherSubscription)].map(({ id, tenantId, state }) => ({ id, tenantId, state })));
  assert.ok(!JSON.stringify(result).includes('NEVER_EXPORT'));
});

test('login validates before executing and propagates authentication failures instead of claiming success', async () => {
  const { deviceLogin } = await audit();
  let calls = 0;
  await assert.rejects(() => deviceLogin({ tenant: 'default', subscriptions: [subscription] }, {
    runner: () => { calls++; }
  }), /tenant.*GUID/i);
  assert.equal(calls, 0);
  await assert.rejects(() => deviceLogin({ tenant, subscriptions: [subscription] }, {
    runner: async () => { throw new CommandError('COMMAND_FAILED', 'Device login failed.'); }
  }), /Device login failed/);
});

test('discovery validates consent and all tenant bindings before issuing any AKS inventory requests', async () => {
  const { discoverClusters } = await audit();
  const calls = [];
  const runner = async (file, args) => {
    calls.push(args);
    return { stdout: JSON.stringify(account(args[args.indexOf('--subscription') + 1],
      args.includes(otherSubscription) ? '10000000-0000-0000-0000-000000000002' : tenant)) };
  };
  await assert.rejects(() => discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: false }, { runner }), /authoriz/i);
  assert.equal(calls.length, 0);
  await assert.rejects(() => discoverClusters({ tenant, subscriptions: [subscription, otherSubscription], authorizeReadOnly: true }, { runner }), /tenant/i);
  assert.ok(!calls.some((args) => args[0] === 'aks'));
});

test('discovery is explicitly subscription-scoped, minimizes returned metadata and rejects forged cluster IDs', async () => {
  const { discoverClusters } = await audit();
  const target = demoEvidence().target;
  const id = demoEvidence().sources.cluster.data.id;
  const calls = [];
  const runner = async (file, args) => {
    calls.push(args);
    return { stdout: JSON.stringify(args[0] === 'account' ? account()
      : [{ id, name: target.cluster, resourceGroup: target.resourceGroup, location: 'eastus2', credentials: 'NEVER_EXPORT' }]) };
  };
  const result = await discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: true }, { runner });
  assert.equal(result.clusters.length, 1);
  assert.equal(result.clusters[0].subscription, subscription);
  assert.ok(!JSON.stringify(result).includes('NEVER_EXPORT'));
  assert.ok(calls.find((args) => args[0] === 'aks').includes(subscription));
  await assert.rejects(() => discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: true }, {
    runner: async (file, args) => ({ stdout: JSON.stringify(args[0] === 'account' ? account()
      : [{ id: id.replace(subscription, otherSubscription), name: target.cluster, resourceGroup: target.resourceGroup }]) })
  }), /subscription|target/i);
});

test('discovery treats malformed account responses, disabled subscriptions and missing inventory as errors', async () => {
  const { discoverClusters } = await audit();
  for (const response of [null, {}, { ...account(), state: 'Disabled' }, { ...account(), id: otherSubscription }]) {
    await assert.rejects(() => discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: true }, {
      runner: async () => ({ stdout: JSON.stringify(response) })
    }), /account|subscription/i);
  }
  await assert.rejects(() => discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: true }, {
    runner: async (file, args) => ({ stdout: JSON.stringify(args[0] === 'account' ? account() : {}) })
  }), /list|inventory/i);
});

test('audit dry-run validates a multi-target plan, lists strategy exclusions, and performs no Azure or Kubernetes calls', async (t) => {
  const directory = await temporary(t);
  const configPath = join(directory, 'config.json');
  const value = configuration();
  delete value.targets[0].binding;
  value.strategies = ['azure'];
  value.subscriptions.push(otherSubscription);
  value.targets.push({ ...value.targets[0], subscription: otherSubscription, cluster: 'second-cluster', context: 'second-context' });
  await writeFile(configPath, JSON.stringify(value));
  const logs = [];
  const code = await main(['audit', '--config', configPath, '--dry-run'], {
    log: (line) => logs.push(line), error: assert.fail,
    runner: async () => assert.fail('A dry-run must not execute any external command.')
  });
  assert.equal(code, 0);
  const plan = JSON.parse(logs.join('\n'));
  assert.equal(plan.targets.length, 2);
  assert.equal(plan.readOnly, true);
  assert.ok(plan.targets[0].sources.some((source) => source.id === 'pods' && source.authorized === false));
  assert.ok(!plan.targets[0].sources.some((source) => source.authorized && source.strategy !== 'azure'));
  assert.equal(await readFile(configPath, 'utf8'), JSON.stringify(value));
});

test('a parameterized multi-target audit persists separate reports and a fleet index with no implicit login', async (t) => {
  const directory = await temporary(t);
  const value = configuration();
  delete value.targets[0].binding;
  value.strategies = ['azure'];
  value.targets.push({ ...value.targets[0], resourceGroup: 'rg-second', cluster: 'second-cluster', context: 'second-context' });
  const path = join(directory, 'config.json');
  await writeFile(path, JSON.stringify(value));
  const calls = [];
  const runner = async (file, args, options) => {
    calls.push({ file, args, options });
    assert.equal(file, 'az');
    if (args[0] === 'account') return { stdout: JSON.stringify(account(args[args.indexOf('--subscription') + 1])) };
    const raw = demoRaw();
    if (file === 'az' && args[0] === 'aks' && args[1] === 'show' && args.includes('second-cluster')) {
      raw.cluster.name = 'second-cluster';
      raw.cluster.id = raw.cluster.id.replace('/rg-xray-demo/', '/rg-second/').replace('/xray-demo', '/second-cluster');
    }
    const id = args.includes('nodepool') ? 'nodepools' : args.includes('diagnostic-settings') ? 'diagnostics'
      : args.includes('maintenanceconfiguration') ? 'maintenance' : 'cluster';
    return { stdout: JSON.stringify(raw[id]) };
  };
  const output = join(directory, 'result');
  const logs = [];
  assert.equal(await main(['audit', '--config', path, '--output', output], { runner,
    log: (line) => logs.push(line), error: (line) => logs.push(line) }), 0);
  const index = JSON.parse(await readFile(join(output, 'audit.json'), 'utf8'));
  assert.equal(index.runs.length, 2);
  assert.equal(index.tenant, tenant);
  for (const run of index.runs) {
    const assessment = JSON.parse(await readFile(join(output, run.directory, 'assessment.json'), 'utf8'));
    assert.equal(assessment.target.binding.status, 'verified');
    assert.ok(assessment.results.length > 0);
    assert.ok((await readFile(join(output, run.directory, 'report.html'), 'utf8')).includes('xray-data'));
  }
  assert.ok((await readFile(join(output, 'audit.md'), 'utf8')).includes('cluster-002/report.html'));
  assert.ok(!calls.some(({ args }) => args.includes('login')));
});

test('explicit null configuration values cannot silently widen collection or replace scenario intent', async () => {
  const { validateAuditConfig } = await audit();
  for (const mutate of [
    (value) => { value.categories = null; },
    (value) => { value.relatedResourceIds = null; },
    (value) => { value.maxRelatedResources = null; },
    (value) => { value.scenario.apiAccess = null; },
    (value) => { value.scenario.minimumReplicas = null; },
    (value) => { value.scenario.allowedRegistries = null; }
  ]) {
    const value = configuration();
    delete value.targets[0].binding;
    mutate(value);
    assert.throws(() => validateAuditConfig(value), /config|scenario|categories|relatedResourceIds|maxRelatedResources/i);
  }
});

test('malformed Azure authentication and discovery JSON never enters terminal diagnostics', async () => {
  const { verifySubscriptions, discoverClusters } = await audit();
  const malformed = 'NEVER_EXPORT_PRIVATE_RESPONSE';
  for (const operation of [
    () => verifySubscriptions({ tenant, subscriptions: [subscription] }, { runner: async () => ({ stdout: malformed }) }),
    () => discoverClusters({ tenant, subscriptions: [subscription], authorizeReadOnly: true }, {
      runner: async (file, args) => ({ stdout: args[0] === 'account' ? JSON.stringify(account()) : malformed })
    })
  ]) {
    await assert.rejects(operation, (failure) => !failure.message.includes('NEVER') && /JSON/i.test(failure.message));
  }
});

test('invalid authorization creates no output and invalid dry-run severity options are rejected before any command', async (t) => {
  const { runAudit } = await audit();
  const directory = await temporary(t);
  const output = join(directory, 'must-not-exist');
  const value = configuration();
  delete value.targets[0].binding;
  value.authorization.readOnly = false;
  await assert.rejects(() => runAudit(value, { output, runner: assert.fail }), /readOnly/);
  await assert.rejects(() => stat(output), (failure) => failure.code === 'ENOENT');
  value.authorization.readOnly = true;
  const path = join(directory, 'config.json');
  await writeFile(path, JSON.stringify(value));
  await assert.rejects(() => main(['audit', '--config', path, '--dry-run', '--fail-on', 'urgent'], {
    runner: assert.fail, log: assert.fail, error: assert.fail
  }), /fail-on/);
  await assert.rejects(() => main(['audit', '--dry-run'], { log: assert.fail }), /--config/);
});

test('all three target selection modes are accepted and discovery dry-run does not inventory clusters', async () => {
  const { validateAuditConfig, buildAuditPlan } = await audit();
  const named = configuration();
  delete named.targets[0].binding;
  named.targetSelection = 'named';
  assert.equal(validateAuditConfig(named).targetSelection, 'named');

  const single = configuration();
  delete single.targets[0].binding;
  single.targetSelection = 'default-subscription-only';
  single.strategies = ['azure'];
  single.targets = [];
  const singlePlan = buildAuditPlan(single);
  assert.equal(singlePlan.targetSelection, 'default-subscription-only');
  assert.equal(singlePlan.targets.length, 0);
  assert.ok(singlePlan.limitations.some((line) => /az aks list/i.test(line)));

  const fleet = configuration();
  delete fleet.targets[0].binding;
  fleet.targetSelection = 'all-accessible-clusters';
  fleet.strategies = ['azure'];
  fleet.subscriptions.push(otherSubscription);
  fleet.targets = [];
  assert.equal(validateAuditConfig(fleet).targetSelection, 'all-accessible-clusters');
  assert.equal(buildAuditPlan(fleet).targets.length, 0);
});

test('discovery target selection materializes every authorized cluster and rejects unknown mappings', async () => {
  const { resolveAuditTargets } = await audit();
  const target = demoEvidence().target;
  const id = demoEvidence().sources.cluster.data.id;
  const inventory = async (file, args) => ({
    stdout: JSON.stringify(args[0] === 'account' ? account()
      : [{ id, name: target.cluster, resourceGroup: target.resourceGroup, location: 'eastus2' }])
  });
  const discovered = configuration();
  delete discovered.targets[0].binding;
  discovered.targetSelection = 'all-accessible-clusters';
  discovered.strategies = ['azure'];
  discovered.targets = [];
  const resolved = await resolveAuditTargets(discovered, { runner: inventory });
  assert.equal(resolved.targets.length, 1);
  assert.equal(resolved.targets[0].cluster, target.cluster);
  assert.equal(resolved.targets[0].subscription, subscription);

  const mapped = configuration();
  delete mapped.targets[0].binding;
  mapped.targetSelection = 'default-subscription-only';
  mapped.strategies = ['azure', 'kubernetes'];
  const withContext = await resolveAuditTargets(mapped, { runner: inventory });
  assert.equal(withContext.targets[0].context, mapped.targets[0].context);

  const unknown = configuration();
  delete unknown.targets[0].binding;
  unknown.targetSelection = 'all-accessible-clusters';
  unknown.strategies = ['azure'];
  unknown.targets = [{ ...unknown.targets[0], cluster: 'missing-cluster' }];
  await assert.rejects(() => resolveAuditTargets(unknown, { runner: inventory }), /does not match a discovered/i);
});

test('runtime tenant, subscriptions and target selection overlay the config without inferring defaults', async (t) => {
  const { applyRuntimeParameters, buildAuditPlan } = await audit();
  const input = configuration();
  delete input.targets[0].binding;
  input.tenant = '<tenant-guid>';
  input.subscriptions = ['<workload-subscription-guid>'];
  input.targetSelection = 'named';
  const overlay = applyRuntimeParameters(input, {
    tenant, subscriptions: [subscription], targetSelection: 'default-subscription-only'
  });
  assert.equal(input.tenant, '<tenant-guid>');
  assert.equal(overlay.tenant, tenant);
  assert.deepEqual(overlay.subscriptions, [subscription]);
  overlay.strategies = ['azure'];
  overlay.targets = [];
  assert.equal(buildAuditPlan(overlay).targetSelection, 'default-subscription-only');

  const directory = await temporary(t);
  const path = join(directory, 'config.json');
  const file = configuration();
  delete file.targets[0].binding;
  file.tenant = '<tenant-guid>';
  file.subscriptions = ['<workload-subscription-guid>'];
  file.strategies = ['azure'];
  file.targetSelection = 'named';
  file.targets = [];
  await writeFile(path, JSON.stringify(file));
  const lines = [];
  await main(['audit', '--config', path, '--tenant', tenant, '--subscriptions', `${subscription},${otherSubscription}`,
    '--target-selection', 'all-accessible-clusters', '--dry-run'], { log: (line) => lines.push(line), runner: assert.fail });
  const plan = JSON.parse(lines.join('\n'));
  assert.equal(plan.tenant, tenant);
  assert.deepEqual(plan.subscriptions, [subscription, otherSubscription]);
  assert.equal(plan.targetSelection, 'all-accessible-clusters');
});
