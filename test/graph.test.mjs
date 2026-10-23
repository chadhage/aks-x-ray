import test from 'node:test';
import assert from 'node:assert/strict';
import { diagnosisEvidence, diagnosisPrincipal, diagnosisSubscriptions, diagnosisTenant,
  diagnosisTimestamp, dependencyStorageId, managedIdentityId } from '../examples/diagnosis-fixture.mjs';

const graphModule = () => import('../src/diagnosis/graph.mjs');
const options = () => ({ tenant: diagnosisTenant, subscriptions: [...diagnosisSubscriptions], now: new Date(diagnosisTimestamp) });

test('resource and identity graph spans approved subscriptions and merges a shared Azure principal, not Kubernetes subjects', async () => {
  const { buildGraph, armId, kubeId, principalId } = await graphModule();
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  const graph = buildGraph([first, second], options());
  assert.ok(graph.nodes.some((node) => node.id === armId(dependencyStorageId)));
  assert.equal(graph.nodes.filter((node) => node.id === principalId(diagnosisTenant, diagnosisPrincipal)).length, 1);
  for (const evidence of [first, second]) {
    const clusterId = evidence.sources.cluster.data.id;
    assert.ok(graph.nodes.some((node) => node.id === kubeId(clusterId, 'ServiceAccount', 'payments', 'checkout')));
    assert.ok(graph.edges.some((edge) => edge.from === armId(clusterId) && edge.to === principalId(diagnosisTenant, diagnosisPrincipal) && edge.relationship === 'uses-identity'));
  }
  assert.equal(graph.nodes.filter((node) => node.kind === 'service-account' && node.name === 'checkout').length, 2);
  assert.ok(graph.edges.some((edge) => edge.to === armId(dependencyStorageId) && edge.relationship === 'applies-to'));
});

test('every graph relationship references existing nodes and explicit evidence provenance', async () => {
  const { buildGraph } = await graphModule();
  const graph = buildGraph([diagnosisEvidence()], options());
  const nodes = new Set(graph.nodes.map((node) => node.id));
  const sources = new Set(graph.sources.map((source) => source.id));
  assert.ok(graph.edges.length > 10);
  for (const edge of graph.edges) {
    assert.ok(nodes.has(edge.from) && nodes.has(edge.to), edge.id);
    assert.ok(edge.evidenceRefs.length > 0, edge.id);
    assert.ok(edge.evidenceRefs.every((ref) => sources.has(ref)), edge.id);
    assert.ok(['observed', 'configured', 'conditional'].includes(edge.state));
  }
});

test('the graph connects service selectors, pods, service accounts and namespace-local sensitive role grants', async () => {
  const { buildGraph, kubeId } = await graphModule();
  const evidence = diagnosisEvidence();
  const graph = buildGraph([evidence], options());
  const cluster = evidence.sources.cluster.data.id;
  const service = kubeId(cluster, 'Service', 'payments', 'checkout');
  const pod = kubeId(cluster, 'Pod', 'payments', 'checkout-example');
  const account = kubeId(cluster, 'ServiceAccount', 'payments', 'checkout');
  assert.ok(graph.edges.some((edge) => edge.from === 'external:internet' && edge.to === service && edge.relationship === 'configured-public-entry'));
  assert.ok(graph.edges.some((edge) => edge.from === service && edge.to === pod && edge.relationship === 'selects'));
  assert.ok(graph.edges.some((edge) => edge.from === pod && edge.to === account && edge.relationship === 'uses-service-account'));
  const grants = graph.edges.filter((edge) => edge.from === account && edge.relationship === 'grants-capability');
  assert.ok(grants.some((edge) => graph.nodes.find((node) => node.id === edge.to)?.capability === 'read-secrets'));
});

test('a same-named Role in another namespace is unresolved, not an inferred grant', async () => {
  const { buildGraph, kubeId } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.roles.data.items[0].metadata.namespace = 'orders';
  const graph = buildGraph([evidence], options());
  const account = kubeId(evidence.sources.cluster.data.id, 'ServiceAccount', 'payments', 'checkout');
  assert.ok(!graph.edges.some((edge) => edge.from === account && edge.relationship === 'grants-capability'));
  assert.ok(graph.gaps.some((gap) => gap.code === 'UNRESOLVED_ROLE'));
});

test('Azure permission patterns respect notActions/notDataActions instead of treating any wildcard as effective access', async () => {
  const { buildGraph, principalId } = await graphModule();
  const evidence = diagnosisEvidence();
  const permissions = evidence.sources.roleDefinitions.data.items[0].permissions[0];
  permissions.dataActions = ['Microsoft.Storage/*'];
  permissions.notDataActions = ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'];
  const graph = buildGraph([evidence], options());
  const principal = principalId(diagnosisTenant, diagnosisPrincipal);
  assert.ok(!graph.edges.some((edge) => edge.from === principal && edge.relationship === 'grants-capability'
    && graph.nodes.find((node) => node.id === edge.to)?.capability === 'read-blob-data'));
});

test('conditioned Azure role assignments remain conditional rather than proven effective grants', async () => {
  const { buildGraph, principalId } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.roleAssignments.data.items[0].hasCondition = true;
  const graph = buildGraph([evidence], options());
  const grants = graph.edges.filter((edge) => edge.from === principalId(diagnosisTenant, diagnosisPrincipal) && edge.relationship === 'grants-capability');
  assert.ok(grants.length > 0);
  assert.ok(grants.every((edge) => edge.state === 'conditional'));
});

test('unavailable definition data produces explicit evidence gaps rather than deny-or-allow guesses', async () => {
  const { buildGraph, principalId } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.roleDefinitions = { status: 'error', collectedAt: diagnosisTimestamp,
    error: { code: 'FORBIDDEN', message: 'Definitions unavailable.' } };
  const graph = buildGraph([evidence], options());
  assert.ok(graph.gaps.some((gap) => gap.sourceId === 'roleDefinitions' && gap.status === 'error'));
  assert.ok(!graph.edges.some((edge) => edge.from === principalId(diagnosisTenant, diagnosisPrincipal) && edge.relationship === 'grants-capability'));
});

test('workload identity federation requires observed issuer, subject, audience and managed identity metadata', async () => {
  const { buildGraph } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.cluster.data.oidcIssuerProfile.issuerUrl = 'https://issuer.example.invalid/';
  evidence.sources.serviceaccounts.data.items[0].workloadIdentity = { clientId: '40000000-0000-0000-0000-000000000001' };
  let graph = buildGraph([evidence], options());
  assert.ok(!graph.edges.some((edge) => edge.relationship === 'federates-as'));
  evidence.sources.federatedCredentials = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [], data: { items: [{
    name: 'checkout', identityResourceId: managedIdentityId, issuer: 'https://issuer.example.invalid/',
    subject: 'system:serviceaccount:payments:checkout', audiences: ['api://AzureADTokenExchange']
  }] } };
  graph = buildGraph([evidence], options());
  assert.ok(graph.edges.some((edge) => edge.relationship === 'federates-as' && edge.state === 'configured'));
  evidence.sources.federatedCredentials.data.items[0].issuer = 'https://different.example.invalid/';
  assert.ok(!buildGraph([evidence], options()).edges.some((edge) => edge.relationship === 'federates-as'));
});

test('conflicting dependency snapshots are preserved rather than resolved by input order', async () => {
  const { buildGraph, armId, fact } = await graphModule();
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  first.sources.relatedResources.data.items[1].configuration.allowBlobPublicAccess = false;
  second.sources.relatedResources.data.items[1].configuration.allowBlobPublicAccess = true;
  const graph = buildGraph([first, second], options());
  const resource = graph.nodes.find((node) => node.id === armId(dependencyStorageId));
  assert.equal(fact(resource, 'configuration').status, 'conflicting');
  assert.equal(fact(resource, 'configuration').value, undefined);
  assert.ok(graph.gaps.some((gap) => gap.code === 'CONFLICTING_OBSERVATIONS'));
});

test('scope and target binding prevent cross-tenant, unapproved-subscription and cross-plane graph joins', async () => {
  const { buildGraph } = await graphModule();
  const evidence = diagnosisEvidence();
  assert.throws(() => buildGraph([evidence], { ...options(), subscriptions: [diagnosisSubscriptions[0]] }), /approved subscription/i);
  assert.throws(() => buildGraph([evidence], { ...options(), tenant: '10000000-0000-0000-0000-000000000002' }), /tenant/i);
  evidence.sources.context.data.server = 'https://other.example.invalid';
  const graph = buildGraph([evidence], options());
  assert.ok(graph.gaps.some((gap) => gap.code === 'TARGET_BINDING'));
  assert.ok(!graph.nodes.some((node) => node.kind === 'workload'));
});

test('graph node/edge limits fail explicitly and preserve a valid partial graph, never a success-shaped truncation', async () => {
  const { buildGraph } = await graphModule();
  assert.throws(() => buildGraph([diagnosisEvidence()], { ...options(), maxNodes: 3 }), (error) =>
    error.code === 'GRAPH_LIMIT' && error.graph.incomplete && error.graph.gaps.some((gap) => gap.code === 'GRAPH_LIMIT'));
});

test('graph IDs and observations are deterministic across bundle and resource response ordering', async () => {
  const { buildGraph } = await graphModule();
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  const before = buildGraph([first, second], options());
  first.sources.relatedResources.data.items.reverse();
  second.sources.relatedResources.data.items.reverse();
  assert.deepEqual(buildGraph([second, first], options()), before);
});

test('native service-account group membership is represented without guessing external Entra group membership', async () => {
  const { buildGraph, kubeId } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.rolebindings.data.items[0].subjects = [{ kind: 'Group', name: 'system:serviceaccounts:payments' }];
  const graph = buildGraph([evidence], options());
  const account = kubeId(evidence.sources.cluster.data.id, 'ServiceAccount', 'payments', 'checkout');
  assert.ok(graph.edges.some((edge) => edge.from === account && edge.relationship === 'member-of'));
  assert.ok(!graph.edges.some((edge) => edge.relationship === 'member-of' && graph.nodes.find((node) => node.id === edge.to)?.name === 'demo-privileged-operators'));
});

test('resource-name restrictions remain attached to sensitive Kubernetes capability declarations', async () => {
  const { buildGraph } = await graphModule();
  const evidence = diagnosisEvidence();
  evidence.sources.roles.data.items[0].rules[0].resourceNames = ['approved-name'];
  const graph = buildGraph([evidence], options());
  const capability = graph.nodes.find((node) => node.capability === 'read-secrets' && node.namespace === 'payments');
  assert.deepEqual(capability.resourceNames, ['approved-name']);
});
