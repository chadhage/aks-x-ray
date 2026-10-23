import test from 'node:test';
import assert from 'node:assert/strict';
import { CommandError } from '../src/process.mjs';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';
import { diagnosisEvidence, diagnosisTenant, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';

const executor = () => import('../src/diagnosis/validation.mjs');
const runId = '60000000-0000-4000-8000-000000000001';
function settings({ tests = ['authorization-review'], intrusive = false, limit = 100 } = {}) {
  return normalizeAssessment({
    strategies: ['validation'], stages: ['passive', 'non-mutating', ...(intrusive ? ['intrusive'] : [])], maxValidationChecks: limit,
    approvals: {
      nonMutating: { approved: true, contexts: ['context-xray-demo'], namespaces: ['payments'], tests,
        expiresAt: '2026-10-23T12:00:00Z' },
      intrusive: { approved: intrusive, contexts: intrusive ? ['context-xray-demo'] : [], suites: intrusive ? ['security'] : [],
        expiresAt: intrusive ? '2026-10-23T12:00:00Z' : null }
    }
  });
}
function harness({ allowed = true, changedSubject = false, admission = 'restricted', onReview } = {}) {
  const evidence = diagnosisEvidence();
  evidence.synthetic = false;
  const calls = [];
  let identities = 0;
  const runner = async (file, args, options = {}) => {
    calls.push({ file, args, input: options.input });
    if (file === 'az') return { stdout: JSON.stringify({ id: args[args.indexOf('--subscription') + 1], tenantId: diagnosisTenant, state: 'Enabled' }) };
    if (args.includes('config')) return { stdout: evidence.sources.context.data.server };
    if (args.includes('whoami')) return { stdout: JSON.stringify({ kind: 'SelfSubjectReview', apiVersion: 'authentication.k8s.io/v1',
      status: { userInfo: { username: changedSubject && identities++ > 0 ? 'different-actor' : 'auditor', uid: 'user-id', groups: ['team'], extra: { token: ['NEVER_EXPORT'] } } } }) };
    if (args.some((arg) => arg.includes('selfsubjectaccessreviews'))) {
      const body = JSON.parse(options.input);
      assert.equal(body.kind, 'SelfSubjectAccessReview');
      assert.ok(!Object.hasOwn(body.spec, 'user'));
      onReview?.(body.spec.resourceAttributes);
      return { stdout: JSON.stringify({ kind: 'SelfSubjectAccessReview', apiVersion: 'authorization.k8s.io/v1',
        status: { allowed, denied: !allowed } }) };
    }
    if (args.includes('--dry-run=server')) {
      throw new CommandError('COMMAND_FAILED', 'Server rejected probe.', {
        stderr: admission === 'restricted' ? 'pods "negative" is forbidden: violates PodSecurity "restricted:latest": privileged' : 'Forbidden: user cannot create pods',
        exitCode: 1
      });
    }
    assert.fail(`Unexpected validation command: ${file} ${args.join(' ')}`);
  };
  return { evidence, calls, runner };
}

test('unapproved stages issue no commands and leave explicit blocked plan actions', async () => {
  const { executeValidationStages } = await executor();
  const evidence = diagnosisEvidence();
  const options = normalizeAssessment({ strategies: ['validation'], stages: ['passive', 'non-mutating', 'intrusive'] });
  const result = await executeValidationStages([evidence], options, { runner: assert.fail, now: () => new Date(diagnosisTimestamp) });
  assert.ok(result.plan.actions.filter((action) => action.stage !== 'passive').every((action) => action.status === 'blocked'));
});

test('authorization reviews validate only the current authenticated subject without reading secret content', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness();
  const result = await executeValidationStages([mock.evidence], settings(), { runner: mock.runner, now: () => new Date(diagnosisTimestamp) });
  const records = result.records.filter((record) => record.testId === 'authorization-review');
  assert.equal(records.length, 3);
  assert.ok(records.every((record) => record.status === 'completed' && record.method === 'SelfSubjectAccessReview'));
  assert.ok(records.some((record) => record.predicate === 'can-list-secrets'));
  assert.ok(!mock.calls.some(({ args }) => args.includes('get-credentials') || args.includes('--as') || args.includes('exec')
    || args.includes('get') && args.includes('secrets')));
  assert.ok(!JSON.stringify(result).includes('NEVER_EXPORT'));
});

test('changed authenticated subject invalidates permission receipts rather than reusing another actor proof', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness({ changedSubject: true });
  const result = await executeValidationStages([mock.evidence], settings(), { runner: mock.runner, now: () => new Date(diagnosisTimestamp) });
  assert.ok(result.records.some((record) => record.status === 'error'));
  assert.ok(!result.records.some((record) => record.status === 'completed'));
});

test('admission dry-run distinguishes restricted-policy rejection from unrelated authorization denial', async () => {
  const { executeValidationStages } = await executor();
  for (const admission of ['restricted', 'unrelated']) {
    const mock = harness({ admission });
    const result = await executeValidationStages([mock.evidence], settings({ tests: ['admission-dry-run'] }),
      { runner: mock.runner, now: () => new Date(diagnosisTimestamp) });
    const record = result.records.find((item) => item.testId === 'admission-dry-run');
    assert.equal(record.status, admission === 'restricted' ? 'completed' : 'error');
    if (admission === 'restricted') assert.equal(record.value, false);
    assert.ok(mock.calls.filter(({ args }) => args.includes('create')).every(({ args }) =>
      args.some((arg) => arg.includes('selfsubjectaccessreviews')) || args.includes('--dry-run=server')));
  }
});

test('denied intrusive preflight prevents namespace creation and never invokes a canary runner', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness({ allowed: false });
  let mutations = 0;
  const result = await executeValidationStages([mock.evidence], settings({ tests: ['intrusive-preflight'], intrusive: true }), {
    runner: mock.runner, now: () => new Date(diagnosisTimestamp), runIdFactory: () => runId,
    intrusiveRunner: async () => { mutations++; assert.fail('Denied preflight must block this call.'); }
  });
  assert.equal(mutations, 0);
  assert.equal(result.plan.actions.find((action) => action.stage === 'intrusive').status, 'blocked');
});

test('complete approved preflight permits only an owned, bounded canary and records its isolated scope', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness();
  let calls = 0;
  const result = await executeValidationStages([mock.evidence], settings({ tests: ['intrusive-preflight'], intrusive: true }), {
    runner: mock.runner, now: () => new Date(diagnosisTimestamp), runIdFactory: () => runId,
    intrusiveRunner: async (input, options, dependencies) => {
      calls++;
      assert.equal(options.authorizeActive, true);
      assert.equal(options.confirmContext, input.target.context);
      assert.ok(options.requests <= 200 && options.concurrency <= 4 && options.durationSeconds <= 30);
      assert.equal(dependencies.runIdFactory(), runId);
      const namespace = `aks-xray-${runId.slice(0, 18)}`;
      return { ...input, activeRun: { runId, namespace, namespaceUid: 'owned-uid', commands: [],
        cleanup: { status: 'deleted' } },
      sources: { ...input.sources, activeSecurity: { status: 'ok', data: { denied: true, dryRun: true, reason: 'restricted-pod-security' }, commands: [] } } };
    }
  });
  assert.equal(calls, 1);
  const record = result.records.find((item) => item.stage === 'intrusive');
  assert.equal(record.status, 'completed');
  assert.equal(record.namespace, `aks-xray-${runId.slice(0, 18)}`);
  assert.equal(record.value, false);
  assert.equal(record.ownership.cleanup, 'deleted');
});

test('approvals are rechecked at execution time and a bounded validation budget is never silently exceeded', async () => {
  const { executeValidationStages } = await executor();
  let time = new Date(diagnosisTimestamp);
  const mock = harness({ onReview: () => { time = new Date('2026-10-23T13:00:00Z'); } });
  let mutations = 0;
  const result = await executeValidationStages([mock.evidence], settings({ tests: ['intrusive-preflight'], intrusive: true }), {
    runner: mock.runner, now: () => time, runIdFactory: () => runId,
    intrusiveRunner: async () => { mutations++; assert.fail('Expired approvals cannot authorize mutation.'); }
  });
  assert.equal(mutations, 0);
  assert.ok(result.plan.actions.find((action) => action.stage === 'intrusive').status === 'blocked');
  const limited = harness();
  const capped = await executeValidationStages([limited.evidence], settings({ limit: 1 }), {
    runner: limited.runner, now: () => new Date(diagnosisTimestamp)
  });
  assert.equal(limited.calls.filter(({ args }) => args.some((arg) => arg.includes('selfsubjectaccessreviews'))).length, 1);
  assert.ok(capped.records.some((record) => record.status === 'blocked' && /limit/i.test(record.reason)));
});

test('a denied Pod-create permission review blocks admission probing before any dry-run is submitted', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness({ allowed: false });
  const result = await executeValidationStages([mock.evidence], settings({ tests: ['admission-dry-run'] }), {
    runner: mock.runner, now: () => new Date(diagnosisTimestamp)
  });
  assert.ok(!mock.calls.some(({ args }) => args.includes('--dry-run=server')));
  assert.ok(result.records.some((record) => record.status === 'blocked'));
});

test('expiry inside a canary runner stops resource creation rather than relying only on its initial approval check', async () => {
  const { executeValidationStages } = await executor();
  const mock = harness();
  let time = new Date(diagnosisTimestamp);
  let mutations = 0;
  const runner = async (file, args, options) => {
    if (file === 'kubectl' && args.includes('create') && !args.some((argument) => argument.includes('selfsubjectaccessreviews'))) {
      mutations++;
      return { stdout: '{}' };
    }
    return mock.runner(file, args, options);
  };
  const result = await executeValidationStages([mock.evidence], settings({ tests: ['intrusive-preflight'], intrusive: true }), {
    runner, now: () => time, runIdFactory: () => runId,
    intrusiveRunner: async (evidence, options, dependencies) => {
      time = new Date('2026-10-23T13:00:00Z');
      await dependencies.runner('kubectl', ['--context', evidence.target.context, 'create', '--filename=-'],
        { input: JSON.stringify({ kind: 'Namespace', metadata: { name: `aks-xray-${runId.slice(0, 18)}` } }) });
      throw new Error('Expired approval did not stop canary creation.');
    }
  });
  assert.equal(mutations, 0);
  assert.ok(result.records.some((record) => record.stage === 'intrusive' && record.status === 'blocked'));
});

test('the real bounded runner creates only its owned resources and still cleans them after approval expiry', async () => {
  const { executeValidationStages } = await executor();
  for (const expireAfterCreate of [false, true]) {
    let time = new Date(diagnosisTimestamp);
    const mock = harness();
    const state = { namespace: null, manifests: 0, deleted: 0 };
    const runner = async (file, args, options) => {
      if (file === 'kubectl' && args.includes('create') && !args.some((arg) => arg.includes('selfsubjectaccessreviews')) && !args.includes('--dry-run=server')) {
        const body = JSON.parse(options.input);
        if (body.kind === 'Namespace') {
          state.namespace = { ...body, metadata: { ...body.metadata, uid: 'owned-namespace-uid' } };
          if (expireAfterCreate) time = new Date('2026-10-23T13:00:00Z');
          return { stdout: JSON.stringify(state.namespace) };
        }
        state.manifests++;
        assert.ok(body.items.every((item) => item.metadata.namespace === state.namespace.metadata.name));
        return { stdout: '{}' };
      }
      if (file === 'kubectl' && args.includes('get') && args.includes('pods')) return { stdout: JSON.stringify({
        items: ['server', 'probe'].map((role) => ({ metadata: { labels: { 'app.kubernetes.io/name': `aks-xray-${role}` } },
          status: { phase: 'Running', conditions: [{ type: 'Ready', status: 'True' }] } }))
      }) };
      if (file === 'kubectl' && args.includes('get') && args.includes('namespace')) return { stdout: JSON.stringify(state.namespace) };
      if (file === 'kubectl' && args.includes('delete')) { state.deleted++; assert.ok(args.includes(state.namespace.metadata.name)); return { stdout: 'deleted' }; }
      return mock.runner(file, args, options);
    };
    const result = await executeValidationStages([mock.evidence], settings({ tests: ['intrusive-preflight'], intrusive: true }), {
      runner, now: () => time, runIdFactory: () => runId
    });
    assert.equal(state.deleted, 1);
    assert.equal(state.manifests, expireAfterCreate ? 0 : 1);
    const record = result.records.find((item) => item.stage === 'intrusive');
    assert.equal(record.status, expireAfterCreate ? 'error' : 'completed');
    assert.equal(record.ownership.cleanup, 'deleted');
  }
});
