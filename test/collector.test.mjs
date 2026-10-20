import test from 'node:test';
import assert from 'node:assert/strict';
import { binding, collect, commandsFor } from '../src/collector.mjs';
import { defaultScope } from '../src/evidence.mjs';
import { demoRaw, demoEvidence } from '../examples/demo.mjs';
import { kubernetesResources, projectSource } from '../src/projection.mjs';
import { CommandError } from '../src/process.mjs';
import { assess } from '../src/engine.mjs';

const target = demoEvidence().target;

function mockRunner(raw, commands, { deny, malformed } = {}) {
  return async (file, args) => {
    commands.push({ file, args });
    let id;
    if (file === 'az') id = args.includes('nodepool') ? 'nodepools' : args.includes('diagnostic-settings')
      ? 'diagnostics' : args.includes('maintenanceconfiguration') ? 'maintenance' : 'cluster';
    else id = args.includes('config') ? 'context'
      : Object.keys(kubernetesResources).find((key) => kubernetesResources[key] === args[args.indexOf('get') + 1]);
    if (id === deny) throw new CommandError('COMMAND_FAILED', 'Access denied.', { stderr: 'Forbidden', exitCode: 1 });
    if (id === malformed) return { stdout: 'INVALID_SECRET_OUTPUT' };
    return { stdout: id === 'context' ? raw[id] : JSON.stringify(raw[id]), stderr: '' };
  };
}

test('cloud collection issues only read-only commands and records exact dependencies', async () => {
  const commands = [];
  const evidence = await collect(target, defaultScope(), { runner: mockRunner(demoRaw(), commands) });
  assert.equal(evidence.target.binding.status, 'verified');
  assert.ok(commands.length > 10);
  assert.ok(!commands.some(({ args }) => args.some((arg) => ['apply', 'exec', 'delete', 'create', 'get-credentials', 'login', 'install'].includes(arg))));
  assert.ok(commands.filter(({ file }) => file === 'kubectl').every(({ args }) => args.includes(target.context)));
  assert.equal(evidence.sources.activeLoad.status, 'notCollected');
  assert.equal(evidence.sources.pods.status, 'ok');
});

test('category selection avoids unrelated APIs and explicit namespaces use namespace-scoped GETs', async () => {
  const commands = [];
  const scope = defaultScope({ categories: ['storage'], namespaces: ['payments'] });
  await collect(target, scope, { runner: mockRunner(demoRaw(), commands) });
  assert.ok(!commands.some(({ args }) => args.includes('pods')));
  const pvcs = commands.find(({ args }) => args.includes('persistentvolumeclaims'));
  assert.ok(pvcs.args.includes('--namespace'));
  assert.ok(!pvcs.args.includes('--all-namespaces'));
});

test('one forbidden API is persisted as an error and blocks dependent assertions', async () => {
  const commands = [];
  const evidence = await collect(target, defaultScope(), { runner: mockRunner(demoRaw(), commands, { deny: 'pods' }) });
  assert.equal(evidence.sources.pods.status, 'error');
  assert.equal(evidence.sources.pods.error.code, 'FORBIDDEN');
  assert.equal(evidence.sources.pods.data, undefined);
  assert.equal(assess(evidence).results.find((result) => result.id === 'SEC-001').status, 'unknown');
});

test('malformed command JSON is an explicit error without exporting raw output', async () => {
  const evidence = await collect(target, defaultScope(), { runner: mockRunner(demoRaw(), [], { malformed: 'pods' }) });
  assert.equal(evidence.sources.pods.error.code, 'INVALID_JSON');
  assert.ok(!JSON.stringify(evidence).includes('INVALID_SECRET_OUTPUT'));
});

test('target mismatch stops further collection instead of mixing two clusters', async () => {
  const raw = demoRaw();
  raw.context = 'https://another-cluster.example.invalid';
  const commands = [];
  const evidence = await collect(target, defaultScope(), { runner: mockRunner(raw, commands) });
  assert.equal(evidence.target.binding.status, 'mismatch');
  assert.equal(commands.length, 2);
  assert.equal(evidence.sources.pods.status, 'notCollected');
});

test('Local invokes aksarc and never cloud node-pool or diagnostic APIs', async () => {
  const commands = [];
  const evidence = await collect({ ...target, platform: 'local' }, defaultScope(), { runner: mockRunner(demoRaw('local'), commands) });
  assert.equal(evidence.target.binding.status, 'verified');
  assert.ok(commands.some(({ args }) => args[0] === 'aksarc'));
  assert.ok(!commands.some(({ args }) => args.includes('nodepool') || args.includes('diagnostic-settings')));
});

test('Azure CLI camel-case RBAC and raw ARM acronym casing normalize identically', () => {
  const raw = demoRaw().cluster;
  assert.equal(projectSource('cluster', raw).enableRBAC, true);
  delete raw.enableRbac;
  raw.enableRBAC = true;
  assert.equal(projectSource('cluster', raw).enableRBAC, true);
  assert.equal(projectSource('cluster', { ...raw, enableRBAC: false }).enableRBAC, false);
});

test('system workloads are omitted by default and only included on explicit request', async () => {
  const raw = demoRaw();
  const system = structuredClone(raw.pods.items[0]);
  system.metadata.namespace = 'kube-system';
  system.metadata.name = 'system-only';
  raw.pods.items.push(system);
  const standard = await collect(target, defaultScope(), { runner: mockRunner(raw, []) });
  assert.ok(!standard.sources.pods.data.items.some((pod) => pod.metadata.namespace === 'kube-system'));
  const explicit = await collect(target, defaultScope({ includeSystem: true }), { runner: mockRunner(raw, []) });
  assert.ok(explicit.sources.pods.data.items.some((pod) => pod.metadata.namespace === 'kube-system'));
  assert.throws(() => defaultScope({ namespaces: ['kube-system'] }), /explicitly selected namespace/);
});

test('explicit target identifiers and supported source commands are mandatory', async () => {
  await assert.rejects(() => collect({ ...target, subscription: 'implicit' }, defaultScope()), /subscription GUID/);
  assert.throws(() => commandsFor('unknown', target, defaultScope()), /No read-only command/);
});

test('path-based proxies are not silently collapsed to a falsely verified hostname', () => {
  const evidence = demoEvidence();
  evidence.sources.context.data = projectSource('context', 'https://aks-xray-demo.example.invalid/other-cluster');
  assert.match(evidence.sources.context.data.server, /other-cluster/);
  assert.equal(binding(evidence).status, 'unverified');
});

test('equivalent Local IPv6 spellings bind to the same endpoint', () => {
  const evidence = demoEvidence('local');
  evidence.sources.context.data.server = 'https://[fd00::a]:6443';
  evidence.sources.cluster.data.controlPlane.controlPlaneEndpoint.hostIP = 'fd00:0:0:0:0:0:0:a';
  assert.equal(binding(evidence).status, 'verified');
});
