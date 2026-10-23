import test from 'node:test';
import assert from 'node:assert/strict';
import { collect, commandsFor } from '../src/collector.mjs';
import { defaultScope, validateEvidence } from '../src/evidence.mjs';
import { demoEvidence, demoRaw, demoTimestamp } from '../examples/demo.mjs';
import { kubernetesResources, projectSource } from '../src/projection.mjs';
import { CommandError } from '../src/process.mjs';

const tenant = '10000000-0000-0000-0000-000000000001';
const target = { ...demoEvidence().target, tenant };
const clusterId = demoRaw().cluster.id;
const resource = (type, name, subscription = target.subscription) =>
  `/subscriptions/${subscription}/resourceGroups/dependencies/providers/${type}/${name}`;
const registryId = resource('Microsoft.ContainerRegistry/registries', 'registry');
const subnetId = resource('Microsoft.Network/virtualNetworks', 'vnet/subnets/aks');
const nsgId = resource('Microsoft.Network/networkSecurityGroups', 'aks-nsg');
const strategies = ['azure', 'kubernetes', 'iam', 'policy', 'defender', 'advisor', 'dependencies'];
const scope = (options = {}) => defaultScope({
  strategies, authorization: { readOnly: true }, authorizedSubscriptions: [target.subscription],
  relatedResourceIds: [], scenario: { name: 'Private production', profile: 'production', apiAccess: 'private' },
  ...options
});

function mockRunner({ mutate, resources = {}, deny } = {}) {
  const calls = [];
  const raw = demoRaw();
  mutate?.(raw);
  const runner = async (file, args) => {
    calls.push({ file, args });
    let id;
    if (file === 'kubectl') id = args.includes('config') ? 'context'
      : Object.keys(kubernetesResources).find((key) => kubernetesResources[key] === args[args.indexOf('get') + 1]);
    else id = args[0] === 'account' ? 'accounts' : args[0] === 'role' ? 'roleAssignments'
      : args[0] === 'policy' ? 'policyStates' : args[0] === 'advisor' ? 'advisorRecommendations'
        : args.includes('pricing') ? 'defenderPricing' : args.includes('assessment') ? 'defenderAssessments'
          : args[0] === 'resource' ? 'relatedResources' : args.includes('nodepool') ? 'nodepools'
            : args.includes('diagnostic-settings') ? 'diagnostics' : args.includes('maintenanceconfiguration') ? 'maintenance' : 'cluster';
    if (id === deny) throw new CommandError('COMMAND_FAILED', 'Access denied.', { stderr: 'Forbidden NEVER_EXPORT', exitCode: 1 });
    let value = raw[id];
    if (id === 'accounts') value = { id: args[args.indexOf('--subscription') + 1], tenantId: tenant, state: 'Enabled' };
    if (id === 'relatedResources') {
      const requested = args[args.indexOf('--ids') + 1];
      value = resources[requested];
      if (value instanceof Error) throw value;
    }
    if (['roles', 'rolebindings', 'clusterroles', 'validatingwebhooks', 'mutatingwebhooks'].includes(id)) value ??= { items: [] };
    if (['roleAssignments', 'policyStates', 'advisorRecommendations', 'defenderAssessments'].includes(id)) value ??= [];
    if (id === 'defenderPricing') value ??= { name: 'Containers', pricingTier: 'Standard' };
    if (value === undefined) assert.fail(`Unexpected or unimplemented mock command: ${file} ${args.join(' ')}`);
    return { stdout: id === 'context' ? value : JSON.stringify(value) };
  };
  return { runner, calls };
}

test('authorized strategies collect expanded metadata after tenant verification, with no resource mutations or secret APIs', async () => {
  const { runner, calls } = mockRunner();
  const evidence = await collect(target, scope(), { runner, now: () => new Date(demoTimestamp) });
  assert.equal(calls[0].args[0], 'account');
  assert.equal(evidence.sources.accounts.status, 'ok');
  assert.equal(evidence.target.binding.status, 'verified');
  for (const id of ['roleAssignments', 'policyStates', 'defenderPricing', 'defenderAssessments', 'advisorRecommendations',
    'roles', 'rolebindings', 'clusterroles', 'validatingwebhooks', 'mutatingwebhooks']) {
    assert.equal(evidence.sources[id]?.status, 'ok', id);
  }
  assert.ok(!calls.some(({ args }) => args.some((arg) =>
    ['login', 'set', 'get-credentials', 'apply', 'exec', 'create', 'delete', 'secrets', 'configmaps', 'logs', 'install'].includes(arg))));
  assert.equal(validateEvidence(evidence), evidence);
});

test('Azure-only strategy never invokes kubectl and explicitly records withheld Kubernetes evidence', async () => {
  const { runner, calls } = mockRunner();
  const evidence = await collect(target, scope({ strategies: ['azure'] }), { runner });
  assert.ok(calls.every(({ file }) => file === 'az'));
  assert.equal(evidence.sources.context.status, 'notCollected');
  assert.match(evidence.sources.context.reason, /strategy.*authoriz/i);
  assert.equal(evidence.target.binding.status, 'verified');
  assert.equal(evidence.target.binding.mode, 'arm-only');
});

test('wrong tenant, disabled accounts, and account lookup failures block ARM and Kubernetes reads', async () => {
  for (const response of [
    { id: target.subscription, tenantId: '10000000-0000-0000-0000-000000000002', state: 'Enabled' },
    { id: target.subscription, tenantId: tenant, state: 'Disabled' },
    { id: '00000000-0000-0000-0000-000000000002', tenantId: tenant, state: 'Enabled' }
  ]) {
    const calls = [];
    const evidence = await collect(target, scope(), {
      runner: async (file, args) => { calls.push(args); return { stdout: JSON.stringify(response) }; }
    });
    assert.equal(calls.length, 1);
    assert.notEqual(evidence.target.binding.status, 'verified');
    assert.equal(evidence.sources.cluster.status, 'notCollected');
  }
  const { runner, calls } = mockRunner({ deny: 'accounts' });
  const evidence = await collect(target, scope(), { runner });
  assert.equal(calls.length, 1);
  assert.equal(evidence.sources.accounts.error.code, 'FORBIDDEN');
  assert.ok(!JSON.stringify(evidence).includes('NEVER_EXPORT'));
});

test('a cluster ARM ID cannot be substituted even when its endpoint matches the selected context', async () => {
  const { runner, calls } = mockRunner({ mutate: (raw) => { raw.cluster.id = raw.cluster.id.replace('/xray-demo', '/different-cluster'); } });
  const evidence = await collect(target, scope(), { runner });
  assert.equal(evidence.target.binding.status, 'mismatch');
  assert.ok(!calls.some(({ args }) => args.includes('nodepool')));
});

test('every declared subscription is tenant-verified before any target inventory is read', async () => {
  const second = '00000000-0000-0000-0000-000000000002';
  const { runner, calls } = mockRunner();
  await collect(target, scope({ authorizedSubscriptions: [target.subscription, second] }), { runner });
  const accounts = calls.filter(({ args }) => args[0] === 'account');
  assert.equal(accounts.length, 2);
  assert.ok(accounts[1].args.includes(second));
  assert.equal(calls[2].file, 'kubectl');
  assert.equal(calls[2].args[0], 'config');
});

test('expanded source commands remain explicitly scoped and Kubernetes RBAC reads honor namespace selection', () => {
  const selected = scope({ namespaces: ['payments'] });
  for (const id of ['roleAssignments', 'policyStates', 'defenderAssessments', 'defenderPricing', 'advisorRecommendations']) {
    const commands = commandsFor(id, target, selected, clusterId);
    assert.ok(commands.length > 0);
    assert.ok(commands.every((command) => command.args.includes(target.subscription)));
  }
  assert.ok(commandsFor('rolebindings', target, selected, clusterId)[0].args.includes('payments'));
  assert.ok(!commandsFor('rolebindings', target, selected, clusterId)[0].args.includes('--all-namespaces'));
});

test('Kubernetes RBAC and admission projections retain assessment rules but omit webhook credentials and CA bundles', () => {
  const role = projectSource('clusterroles', { items: [{ kind: 'ClusterRole', metadata: { name: 'workload-reader' },
    rules: [{ apiGroups: [''], resources: ['pods'], verbs: ['get'], resourceNames: ['app'] }],
    credentials: 'NEVER_EXPORT' }] });
  assert.deepEqual(role.items[0].rules[0].verbs, ['get']);
  const webhook = projectSource('validatingwebhooks', { items: [{ kind: 'ValidatingWebhookConfiguration', metadata: { name: 'policy' },
    webhooks: [{ name: 'policy.example.invalid', failurePolicy: 'Fail', timeoutSeconds: 10,
      rules: [{ apiGroups: [''], resources: ['pods'], operations: ['CREATE'] }],
      clientConfig: { url: 'https://user:NEVER_EXPORT@policy.example.invalid/path?token=NEVER_EXPORT', caBundle: 'NEVER_EXPORT' } }] }] });
  assert.equal(webhook.items[0].webhooks[0].failurePolicy, 'Fail');
  assert.ok(!JSON.stringify({ role, webhook }).includes('NEVER_EXPORT'));
});

test('Azure security, policy, IAM and Advisor projections never persist arbitrary remediation or additionalData payloads', () => {
  const marker = 'NEVER_EXPORT';
  const inputs = {
    accounts: { id: target.subscription, tenantId: tenant, state: 'Enabled', accessToken: marker },
    roleAssignments: [{ id: 'assignment', scope: clusterId, roleDefinitionId: 'definition', principalId: 'principal', credentials: marker }],
    policyStates: [{ resourceId: clusterId, complianceState: 'NonCompliant', policyAssignmentId: 'assignment', additionalData: marker }],
    defenderAssessments: [{ name: 'assessment', status: { code: 'Unhealthy', description: marker }, resourceDetails: { id: clusterId }, additionalData: marker }],
    defenderPricing: { name: 'Containers', pricingTier: 'Standard', extensions: [{ name: 'AgentlessDiscoveryForKubernetes', isEnabled: 'True', additionalExtensionProperties: marker }] },
    advisorRecommendations: [{ id: 'recommendation', impact: 'High', category: 'Security', resourceMetadata: { resourceId: clusterId }, extendedProperties: { secret: marker } }]
  };
  for (const [id, raw] of Object.entries(inputs)) {
    const projected = projectSource(id, raw);
    assert.equal(projected.items.length, 1, id);
    assert.ok(!JSON.stringify(projected).includes(marker), id);
  }
  assert.throws(() => projectSource('policyStates', {}), /explicit.*list/);
});

test('dependency traversal follows only allowlisted references, deduplicates references, and persists no resource credentials', async () => {
  const { runner, calls } = mockRunner({
    mutate: (raw) => { raw.cluster.agentPoolProfiles = [{ vnetSubnetId: subnetId }]; },
    resources: {
      [subnetId]: { id: subnetId, name: 'aks', type: 'Microsoft.Network/virtualNetworks/subnets',
        properties: { addressPrefix: '10.1.0.0/24', networkSecurityGroup: { id: nsgId }, secret: 'NEVER_EXPORT' } },
      [nsgId]: { id: nsgId, name: 'aks-nsg', type: 'Microsoft.Network/networkSecurityGroups',
        properties: { securityRules: [], credentials: 'NEVER_EXPORT' } },
      [registryId]: { id: registryId, name: 'registry', type: 'Microsoft.ContainerRegistry/registries',
        properties: { adminUserEnabled: false, publicNetworkAccess: 'Disabled', passwords: ['NEVER_EXPORT'] } }
    }
  });
  const evidence = await collect(target, scope({ relatedResourceIds: [registryId, subnetId] }), { runner });
  assert.equal(evidence.sources.relatedResources.status, 'ok');
  assert.equal(evidence.sources.relatedResources.data.items.length, 3);
  assert.equal(calls.filter(({ args }) => args[0] === 'resource' && args.includes(subnetId)).length, 1);
  assert.ok(!JSON.stringify(evidence).includes('NEVER_EXPORT'));
  const registry = evidence.sources.relatedResources.data.items.find((item) => item.id === registryId);
  assert.equal(registry.configuration.adminUserEnabled, false);
});

test('out-of-scope dependency references and resource caps are explicit errors, never silently incomplete success', async () => {
  const outside = resource('Microsoft.KeyVault/vaults', 'outside', '00000000-0000-0000-0000-000000000002');
  const { runner, calls } = mockRunner({ mutate: (raw) => { raw.cluster.diskEncryptionSetId = outside; } });
  const evidence = await collect(target, scope(), { runner });
  assert.equal(evidence.sources.relatedResources.status, 'error');
  assert.equal(evidence.sources.relatedResources.error.code, 'SCOPE_DENIED');
  assert.ok(!calls.some(({ args }) => args.includes(outside)));
  const limited = mockRunner({ resources: {
    [subnetId]: { id: subnetId, name: 'aks', type: 'Microsoft.Network/virtualNetworks/subnets',
      properties: { networkSecurityGroup: { id: nsgId } } }
  } });
  const capped = await collect(target, scope({ relatedResourceIds: [subnetId], maxRelatedResources: 1 }), { runner: limited.runner });
  assert.equal(capped.sources.relatedResources.status, 'error');
  assert.equal(capped.sources.relatedResources.error.code, 'RESOURCE_LIMIT');
  assert.equal(capped.sources.relatedResources.data.items.length, 1);
});

test('a failing dependency preserves successful projected metadata and explicit per-resource failures', async () => {
  const denied = new CommandError('COMMAND_FAILED', 'Denied resource.', { stderr: 'Forbidden NEVER_EXPORT', exitCode: 1 });
  const { runner } = mockRunner({ resources: {
    [registryId]: { id: registryId, name: 'registry', type: 'Microsoft.ContainerRegistry/registries', properties: { adminUserEnabled: false } },
    [subnetId]: denied
  } });
  const evidence = await collect(target, scope({ relatedResourceIds: [registryId, subnetId] }), { runner });
  assert.equal(evidence.sources.relatedResources.status, 'error');
  assert.equal(evidence.sources.relatedResources.data.items.length, 1);
  assert.equal(evidence.sources.relatedResources.failures[0].resourceId, subnetId);
  assert.equal(evidence.sources.relatedResources.failures[0].error.code, 'FORBIDDEN');
  assert.ok(!JSON.stringify(evidence).includes('NEVER_EXPORT'));
});

test('a substituted related resource ID is rejected instead of accepting metadata for another resource', async () => {
  const { runner } = mockRunner({ resources: {
    [registryId]: { id: registryId.replace('/registry', '/other'), name: 'other', type: 'Microsoft.ContainerRegistry/registries',
      properties: { adminUserEnabled: false } }
  } });
  const evidence = await collect(target, scope({ relatedResourceIds: [registryId] }), { runner });
  assert.equal(evidence.sources.relatedResources.status, 'error');
  assert.match(evidence.sources.relatedResources.error.message, /resource.*ID|requested/i);
});
