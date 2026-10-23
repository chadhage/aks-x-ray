import test from 'node:test';
import assert from 'node:assert/strict';
import { collect, commandsFor, requiredSources } from '../src/collector.mjs';
import { validateAuditConfig } from '../src/audit.mjs';
import { kubernetesResources, projectSource } from '../src/projection.mjs';
import { CommandError } from '../src/process.mjs';
import { demoRaw } from '../examples/demo.mjs';
import { diagnosisConfig, diagnosisPrincipal, diagnosisSubscriptions, diagnosisTenant, diagnosisTimestamp, managedIdentityId } from '../examples/diagnosis-fixture.mjs';

function fixture(options = {}) {
  const input = diagnosisConfig(['graph']);
  input.strategies.push('resource-graph');
  input.assessment.maxInventoryResources = options.limit ?? 100;
  const config = validateAuditConfig(input);
  const calls = [];
  const runner = async (file, args) => {
    calls.push({ file, args });
    const raw = demoRaw();
    let value;
    if (file === 'kubectl') {
      if (args.includes('config')) return { stdout: raw.context };
      const source = Object.keys(kubernetesResources).find((id) => kubernetesResources[id] === args[args.indexOf('get') + 1]);
      value = raw[source];
    } else if (args[0] === 'account') {
      value = { id: args[args.indexOf('--subscription') + 1], tenantId: diagnosisTenant, state: 'Enabled' };
    } else if (args[0] === 'graph') {
      const token = args.includes('--skip-token') ? args[args.indexOf('--skip-token') + 1] : null;
      value = options.page ? options.page(token) : { data: [], count: 0 };
    } else if (args[0] === 'role') {
      if (args.includes('definition') && options.denyDefinitions) throw new CommandError('COMMAND_FAILED', 'Denied metadata.', { stderr: 'Forbidden NEVER_EXPORT' });
      value = args.includes('definition') ? [] : raw.roleAssignments;
    } else if (args[0] === 'identity') value = [];
    else value = raw.cluster;
    return { stdout: JSON.stringify(value) };
  };
  return { config, calls, runner };
}

const inventoryResource = (name, subscription = diagnosisSubscriptions[0]) => ({
  id: `/subscriptions/${subscription}/resourceGroups/shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${name}`,
  name, type: 'Microsoft.ManagedIdentity/userAssignedIdentities', subscriptionId: subscription,
  properties: { principalId: diagnosisPrincipal, tenantId: diagnosisTenant, clientId: '40000000-0000-0000-0000-000000000001', secret: 'NEVER_EXPORT' }
});

test('graph-specific collection does not depend on the configuration catalogue and reads IAM definitions explicitly', async () => {
  const { config, runner, calls } = fixture();
  const sources = requiredSources(config.scope, 'cloud');
  assert.ok(sources.includes('roleDefinitions'));
  assert.ok(sources.includes('federatedCredentials'));
  assert.ok(sources.includes('resourceGraph'));
  assert.ok(!sources.includes('maintenance'));
  const evidence = await collect(config.targets[0], config.scope, { runner });
  assert.equal(evidence.sources.roleDefinitions.status, 'ok');
  assert.ok(calls.filter(({ args }) => args[0] === 'role').every(({ args }) => args.includes('--subscription')));
  assert.ok(!calls.some(({ args }) => ['login', 'get-credentials', 'exec', 'apply', 'install'].some((value) => args.includes(value))));
});

test('Resource Graph pages are bounded, subscription-scoped and projected before persistence', async () => {
  const mock = fixture({ page: (token) => token === null
    ? { data: [inventoryResource('first')], skip_token: 'second-page', count: 1 }
    : { data: [inventoryResource('second', diagnosisSubscriptions[1])], count: 1 } });
  const evidence = await collect(mock.config.targets[0], mock.config.scope, { runner: mock.runner });
  assert.equal(evidence.sources.resourceGraph.status, 'ok');
  assert.equal(evidence.sources.resourceGraph.data.items.length, 2);
  const calls = mock.calls.filter(({ args }) => args[0] === 'graph');
  assert.equal(calls.length, 2);
  assert.ok(calls[0].args.includes('--subscriptions'));
  assert.ok(diagnosisSubscriptions.every((id) => calls[0].args.includes(id)));
  assert.ok(calls[1].args.includes('second-page'));
  assert.ok(!JSON.stringify(evidence).includes('NEVER_EXPORT'));
});

test('Resource Graph pagination loops and resource limits produce explicit partial errors', async () => {
  const looping = fixture({ page: () => ({ data: [inventoryResource('first')], skip_token: 'repeated' }) });
  const evidence = await collect(looping.config.targets[0], looping.config.scope, { runner: looping.runner });
  assert.equal(evidence.sources.resourceGraph.status, 'error');
  assert.equal(evidence.sources.resourceGraph.error.code, 'PAGINATION_LOOP');
  assert.ok(evidence.sources.resourceGraph.data.items.length > 0);
  assert.ok(looping.calls.filter(({ args }) => args[0] === 'graph').length <= 2);
  const limited = fixture({ limit: 1, page: () => ({ data: [inventoryResource('first'), inventoryResource('second')] }) });
  const capped = await collect(limited.config.targets[0], limited.config.scope, { runner: limited.runner });
  assert.equal(capped.sources.resourceGraph.error.code, 'RESOURCE_LIMIT');
  assert.equal(capped.sources.resourceGraph.data.items.length, 1);
});

test('an unapproved inventory subscription is not persisted or queried as a dependency', async () => {
  const mock = fixture({ page: () => ({ data: [inventoryResource('outside', '00000000-0000-0000-0000-000000000003')] }) });
  const evidence = await collect(mock.config.targets[0], mock.config.scope, { runner: mock.runner });
  assert.equal(evidence.sources.resourceGraph.status, 'error');
  assert.equal(evidence.sources.resourceGraph.error.code, 'SCOPE_DENIED');
  assert.equal(evidence.sources.resourceGraph.data.items.length, 0);
});

test('unselected inventory collection never runs and missing role-definition access is not a permission grant', async () => {
  const mock = fixture({ denyDefinitions: true });
  mock.config.scope.strategies = mock.config.scope.strategies.filter((id) => id !== 'resource-graph');
  const evidence = await collect(mock.config.targets[0], mock.config.scope, { runner: mock.runner });
  assert.equal(evidence.sources.resourceGraph.status, 'notCollected');
  assert.ok(!mock.calls.some(({ args }) => args[0] === 'graph'));
  assert.equal(evidence.sources.roleDefinitions.status, 'error');
  assert.ok(!JSON.stringify(evidence).includes('NEVER_EXPORT'));
});

test('identity, role definitions and federation projections retain relationships without credential or condition bodies', () => {
  const raw = demoRaw().cluster;
  raw.identity = { type: 'UserAssigned', tenantId: diagnosisTenant, principalId: diagnosisPrincipal,
    userAssignedIdentities: { [managedIdentityId]: { principalId: diagnosisPrincipal, clientId: 'client', secret: 'NEVER_EXPORT' } } };
  raw.identityProfile = { kubeletidentity: { objectId: diagnosisPrincipal, clientId: 'client', resourceId: managedIdentityId, token: 'NEVER_EXPORT' } };
  const cluster = projectSource('cluster', raw);
  assert.equal(cluster.identity.principalId, diagnosisPrincipal);
  assert.ok(cluster.linkedResourceIds.includes(managedIdentityId));
  assert.equal(cluster.identityProfile.kubeletidentity.objectId, diagnosisPrincipal);
  const assignment = projectSource('roleAssignments', [{ id: 'a', condition: 'NEVER_EXPORT', principalId: diagnosisPrincipal }]);
  assert.equal(assignment.items[0].hasCondition, true);
  const definitions = projectSource('roleDefinitions', [{ name: 'reader', permissions: [{ actions: ['read'], notActions: [], dataActions: [], notDataActions: [] }], token: 'NEVER_EXPORT' }]);
  assert.deepEqual(definitions.items[0].permissions[0].actions, ['read']);
  const federation = projectSource('federatedCredentials', [{ name: 'checkout', issuer: 'https://issuer.example.invalid',
    subject: 'system:serviceaccount:payments:checkout', audiences: ['api://AzureADTokenExchange'], secret: 'NEVER_EXPORT' }]);
  assert.equal(federation.items[0].subject, 'system:serviceaccount:payments:checkout');
  const sa = projectSource('serviceaccounts', { items: [{ kind: 'ServiceAccount', metadata: { name: 'checkout', namespace: 'payments',
    annotations: { 'azure.workload.identity/client-id': 'client', password: 'NEVER_EXPORT' } } }] });
  assert.equal(sa.items[0].workloadIdentity.clientId, 'client');
  assert.ok(!JSON.stringify({ cluster, assignment, definitions, federation, sa }).includes('NEVER_EXPORT'));
});

test('federated-credential commands are generated only for approved observed managed identity resources', () => {
  const { config } = fixture();
  const commands = commandsFor('federatedCredentials', config.targets[0], config.scope, 'cluster', [{
    id: managedIdentityId, name: 'shared-identity', type: 'Microsoft.ManagedIdentity/userAssignedIdentities'
  }]);
  assert.equal(commands.length, 1);
  assert.ok(commands[0].args.includes('federated-credential'));
  assert.ok(commands[0].args.includes(diagnosisSubscriptions[0]));
});

test('selecting graph analysis never widens target-only IAM collection into subscription-wide inventory', async () => {
  const mock = fixture();
  mock.config.scope.strategies = mock.config.scope.strategies.filter((id) => id !== 'iam-inventory');
  const evidence = await collect(mock.config.targets[0], mock.config.scope, { runner: mock.runner });
  assert.equal(evidence.sources.roleDefinitions.status, 'notCollected');
  assert.equal(evidence.sources.federatedCredentials.status, 'notCollected');
  assert.ok(!mock.calls.some(({ args }) => args[0] === 'role' && (args.includes('definition') || args.includes('--all'))));
  assert.ok(mock.calls.some(({ args }) => args[0] === 'role' && args.includes('assignment') && args.includes('--scope')));
});
