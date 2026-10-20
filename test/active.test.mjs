import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { EventEmitter, once } from 'node:events';
import { PassThrough } from 'node:stream';
import { demoEvidence } from '../examples/demo.mjs';
import { CommandError } from '../src/process.mjs';
import { cleanupNamespace, httpProbe, marker, performLoad, runActive, startPortForward, syntheticResources, validateActiveOptions } from '../src/active.mjs';
import { loadStatistics } from '../src/rules.mjs';
import { assess, exitCode } from '../src/engine.mjs';

const realInput = () => ({ ...demoEvidence(), synthetic: false });
const options = { suite: 'all', authorizeActive: true, confirmContext: 'demo-cloud',
  requests: 4, concurrency: 2, durationSeconds: 1 };

function harness({ setupFailure = false, wrongOwner = false, unrelatedDenial = false } = {}) {
  const state = { commands: [], snapshots: [], deleted: [], closed: 0 };
  const runner = async (file, args, settings = {}) => {
    assert.equal(file, 'kubectl');
    state.commands.push({ args, input: settings.input });
    if (args.includes('config')) return { stdout: realInput().sources.context.data.server };
    if (args.includes('--dry-run=server')) {
      throw new CommandError('COMMAND_FAILED', 'Server rejected dry-run.', {
        stderr: unrelatedDenial ? 'Forbidden: user may not create pods' : 'pods "negative" is forbidden: violates PodSecurity "restricted:latest": privileged',
        exitCode: 1
      });
    }
    if (args.includes('create')) {
      const body = JSON.parse(settings.input);
      if (body.kind === 'Namespace') {
        state.namespace = { ...body, metadata: { ...body.metadata, uid: 'namespace-test-uid' } };
        return { stdout: JSON.stringify(state.namespace) };
      }
      state.manifest = body;
      if (setupFailure) throw new CommandError('COMMAND_FAILED', 'Resource admission failed.', { stderr: 'Forbidden', exitCode: 1 });
      return { stdout: '{}' };
    }
    if (args.includes('get') && args.includes('pods')) return { stdout: JSON.stringify({ items: ['server', 'probe'].map((role) => ({
      metadata: { labels: { 'app.kubernetes.io/name': `aks-xray-${role}` } },
      status: { phase: 'Running', conditions: [{ type: 'Ready', status: 'True' }] }
    })) }) };
    if (args.includes('exec')) return { stdout: JSON.stringify({ resolved: true, addresses: 1, httpStatus: 200, markerMatched: true }) };
    if (args.includes('get') && args.includes('namespace')) {
      const resource = structuredClone(state.namespace);
      if (wrongOwner) resource.metadata.labels['app.kubernetes.io/instance'] = 'not-this-run';
      return { stdout: JSON.stringify(resource) };
    }
    if (args.includes('delete')) {
      state.deleted.push(args[args.indexOf('namespace') + 1]);
      return { stdout: 'deleted' };
    }
    throw new Error('Unexpected mock command.');
  };
  return {
    state, runner,
    openForward: async () => ({ url: 'http://127.0.0.1:12345/healthz', close: async () => { state.closed++; } }),
    request: async () => ({ ok: true, latencyMs: 12, status: 200 }),
    persist: async (evidence) => { state.snapshots.push(structuredClone(evidence)); }
  };
}

test('authorization, exact context, real evidence and hard caps are required before any mutation', () => {
  const evidence = realInput();
  for (const invalid of [{ authorizeActive: false }, { confirmContext: 'different' }, { requests: 201 },
    { concurrency: 5 }, { durationSeconds: 31 }, { requests: 1.1 }, { durationSeconds: 0 }, { suite: 'exploit' }]) {
    assert.throws(() => validateActiveOptions({ ...options, ...invalid }, evidence));
  }
  assert.throws(() => validateActiveOptions(options, demoEvidence()), /synthetic/);
  evidence.sources.context.data.server = 'https://other.example.invalid';
  assert.throws(() => validateActiveOptions(options, evidence), /verified/);
});

test('synthetic resources have bounded jobs, least privilege and no public exposure', () => {
  const manifest = syntheticResources('aks-xray-test', 'run-test');
  for (const job of manifest.items.filter((resource) => resource.kind === 'Job')) {
    assert.equal(job.spec.activeDeadlineSeconds, 240);
    assert.equal(job.spec.backoffLimit, 0);
    assert.equal(job.spec.template.spec.automountServiceAccountToken, false);
    assert.equal(job.spec.template.spec.securityContext.runAsNonRoot, true);
    assert.equal(job.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation, false);
    assert.deepEqual(job.spec.template.spec.containers[0].securityContext.capabilities.drop, ['ALL']);
    assert.match(job.spec.template.spec.containers[0].image, /^mcr\.microsoft\.com\/azure-cli@sha256:[0-9a-f]{64}$/);
    assert.equal(job.spec.template.spec.nodeSelector['kubernetes.io/arch'], 'amd64');
  }
  assert.equal(manifest.items.find((resource) => resource.kind === 'Service').spec.type, 'ClusterIP');
  assert.ok(!JSON.stringify(manifest).includes('hostNetwork'));
});

test('authorized suite persists measured results, exact provenance and owned cleanup', async () => {
  const mock = harness();
  const evidence = await runActive(realInput(), options, mock);
  assert.equal(evidence.activeRun.cleanup.status, 'deleted');
  assert.deepEqual(mock.state.deleted, [evidence.activeRun.namespace]);
  assert.equal(mock.state.closed, 1);
  for (const key of ['activeConnectivity', 'activeE2E', 'activeLoad', 'activeSecurity']) assert.equal(evidence.sources[key].status, 'ok');
  assert.equal(evidence.sources.activeLoad.data.statistics.attempted, 4);
  assert.equal(evidence.sources.activeLoad.data.statistics.p95Ms, 12);
  assert.ok(evidence.sources.activeSecurity.commands.some((command) => command.args.includes('--dry-run=server')));
  assert.ok(mock.state.snapshots.length >= 6);
  assert.equal(exitCode(assess(mock.state.snapshots[0])), 2);
  assert.match(assess(mock.state.snapshots[0]).results.find((result) => result.id === 'ACT-001').message, /pending or interrupted/);
  assert.equal(mock.state.snapshots.at(-1).activeRun.cleanup.status, 'deleted');
  assert.ok(assess(evidence).results.filter((result) => result.id.startsWith('ACT-')).every((result) => result.status === 'pass'));
});

test('resource creation failure still cleans only the owned namespace and records aborted tests', async () => {
  const mock = harness({ setupFailure: true });
  const evidence = await runActive(realInput(), options, mock);
  assert.equal(evidence.activeRun.cleanup.status, 'deleted');
  assert.equal(mock.state.deleted.length, 1);
  assert.equal(evidence.sources.activeLoad.status, 'error');
  assert.equal(exitCode(assess(evidence)), 2);
});

test('ownership mismatch refuses cleanup and is surfaced as an operational failure', async () => {
  const mock = harness({ wrongOwner: true });
  const evidence = await runActive(realInput(), { ...options, suite: 'security' }, mock);
  assert.equal(evidence.activeRun.cleanup.status, 'error');
  assert.match(evidence.activeRun.cleanup.error.message, /Ownership mismatch/);
  assert.deepEqual(mock.state.deleted, []);
  assert.equal(exitCode(assess(evidence)), 2);
  assert.throws(() => validateActiveOptions(options, evidence), /previous active run cleanup/);
});

test('unrelated RBAC rejection cannot be mistaken for a successful security control test', async () => {
  const mock = harness({ unrelatedDenial: true });
  const evidence = await runActive(realInput(), { ...options, suite: 'security' }, mock);
  assert.equal(evidence.sources.activeSecurity.status, 'error');
  assert.equal(assess(evidence).results.find((result) => result.id === 'ACT-004').status, 'error');
});

test('endpoint changes are detected before namespace creation', async () => {
  const mock = harness();
  const runner = async () => ({ stdout: 'https://changed.example.invalid' });
  await assert.rejects(() => runActive(realInput(), options, { ...mock, runner }), /endpoint changed/);
  assert.equal(mock.state.deleted.length, 0);
});

test('cleanup verifies UID as well as both ownership labels', async () => {
  let deleted = false;
  const kube = async (args) => {
    if (args[0] === 'delete') { deleted = true; return {}; }
    return { stdout: JSON.stringify({ metadata: { uid: 'different',
      labels: { 'app.kubernetes.io/managed-by': 'aks-xray', 'app.kubernetes.io/instance': 'run' } } }) };
  };
  const cleanup = await cleanupNamespace(kube, 'aks-xray-owned', 'run', 'expected');
  assert.equal(cleanup.status, 'error');
  assert.equal(deleted, false);
});

test('load thresholds use actual nearest-rank latency and measured error percentage', async () => {
  const limits = { requests: 3, concurrency: 1, durationSeconds: 1, workerPacingMs: 100 };
  const budgets = { p95Ms: 100, maxErrorRatePercent: 0 };
  let count = 0;
  const data = await performLoad('http://127.0.0.1:12345', limits, budgets, {
    request: async () => ({ ok: ++count !== 3, latencyMs: count === 3 ? 101 : 10, status: count === 3 ? 500 : 200 })
  });
  assert.equal(data.statistics.attempted, 3);
  assert.equal(data.statistics.failed, 1);
  assert.equal(data.statistics.p95Ms, 101);
  assert.equal(data.statistics.errorRatePercent, 1 / 3 * 100);
  assert.equal(data.statistics.withinBudgets, false);
  assert.equal(loadStatistics({ ...data, budgets: { p95Ms: 101, maxErrorRatePercent: 34 } }).withinBudgets, true);
  assert.throws(() => loadStatistics({ ...data, samples: [] }), /Invalid/);
});

test('HTTP test validates the exact marker on a real loopback endpoint and rejects external targets', async (t) => {
  const server = createServer((request, response) => { response.end(request.url === '/ok' ? marker : 'wrong marker'); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await httpProbe(`${base}/ok`)).ok, true);
  assert.equal((await httpProbe(`${base}/bad`)).ok, false);
  await assert.rejects(() => httpProbe('https://example.invalid'), /loopback/);
});

test('port-forward uses only loopback and keeps its stream alive for the full bounded test', async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  let killed = false;
  child.kill = () => { killed = true; queueMicrotask(() => child.emit('close', 0)); return true; };
  let argumentsSeen;
  const forward = await startPortForward('explicit-context', 'aks-xray-owned', {
    spawnProcess: (file, args, settings) => {
      assert.equal(file, 'kubectl');
      assert.equal(settings.shell, false);
      argumentsSeen = args;
      queueMicrotask(() => child.stdout.write('Forwarding from 127.0.0.1:34567 -> 8080\n'));
      return child;
    }
  });
  assert.equal(forward.url, 'http://127.0.0.1:34567/healthz');
  assert.ok(argumentsSeen.includes('--address=127.0.0.1'));
  assert.ok(argumentsSeen.includes('--request-timeout=0'));
  await forward.close();
  assert.equal(killed, true);
});

test('duration and pacing caps are measured, not only validated as input values', async () => {
  const limits = { requests: 200, concurrency: 4, durationSeconds: 1, workerPacingMs: 100 };
  const data = await performLoad('http://127.0.0.1:12345', limits, { p95Ms: 100, maxErrorRatePercent: 0 }, {
    request: async () => ({ ok: true, latencyMs: 0, status: 200 })
  });
  assert.equal(data.stoppedBy, 'duration-cap');
  assert.ok(data.samples.length <= 40, `Unsafe attempt count: ${data.samples.length}`);
  assert.ok(data.durationMs <= 2000, `Deadline exceeded: ${data.durationMs}`);
  for (let worker = 0; worker < 4; worker++) {
    const times = data.samples.filter((sample) => sample.worker === worker).map((sample) => sample.startedAtMs);
    for (let index = 1; index < times.length; index++) assert.ok(times[index] - times[index - 1] >= 100);
  }
});
