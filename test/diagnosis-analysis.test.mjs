import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, kubeId, principalId } from '../src/diagnosis/graph.mjs';
import { diagnosisEvidence, diagnosisPrincipal, diagnosisSubscriptions, diagnosisTenant, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';

const analysis = () => import('../src/diagnosis/analysis.mjs');
const options = () => ({ tenant: diagnosisTenant, subscriptions: diagnosisSubscriptions, now: new Date(diagnosisTimestamp) });
const scenario = (overrides = {}) => ({ businessCriticality: 'high', dataSensitivity: 'confidential',
  applicationExposure: 'public', assumedCompromise: [], ...overrides });

test('exposure analysis reports connected public entries and sensitive token/grant context, not a false unauthenticated takeover', async () => {
  const { analyzeExposures } = await analysis();
  const evidence = diagnosisEvidence();
  const graph = buildGraph([evidence], options());
  const output = analyzeExposures(graph, { scenario: scenario() });
  const publicEntry = output.claims.find((claim) => claim.predicate === 'public-entry');
  assert.ok(publicEntry);
  assert.equal(publicEntry.tier, 'configured-exposure');
  assert.ok(publicEntry.description.includes('reachability'));
  assert.ok(output.claims.some((claim) => claim.predicate === 'api-token-automount'));
  assert.ok(!output.claims.some((claim) => claim.predicate === 'unauthenticated-cluster-admin'));
});

test('a public service does not prove initial compromise or make the entire sensitive-access path validated', async () => {
  const { analyzeAttackPaths } = await analysis();
  const graph = buildGraph([diagnosisEvidence()], options());
  const result = analyzeAttackPaths(graph, { scenario: scenario(), maxPaths: 100 });
  const path = result.claims.find((claim) => claim.predicate === 'workload-to-kubernetes-secrets');
  assert.ok(path);
  assert.equal(path.tier, 'configured-exposure');
  assert.ok(path.path.prerequisites.some((item) => item.id === 'initial-compromise' && item.status === 'unknown'));
  assert.ok(path.path.nodes.length >= 3);
  assert.ok(path.path.edges.every((id) => graph.edges.some((edge) => edge.id === id)));
});

test('an explicitly assumed workload compromise supports a conditional plausible path, never proof of exploitation', async () => {
  const { analyzeAttackPaths } = await analysis();
  const evidence = diagnosisEvidence();
  const graph = buildGraph([evidence], options());
  const pod = kubeId(evidence.sources.cluster.data.id, 'Pod', 'payments', 'checkout-example');
  const result = analyzeAttackPaths(graph, { scenario: scenario({ assumedCompromise: [pod] }), maxPaths: 100 });
  const path = result.claims.find((claim) => claim.subject === pod && claim.predicate === 'workload-to-kubernetes-secrets');
  assert.equal(path.tier, 'plausible-exploitability');
  assert.ok(path.path.prerequisites.some((item) => item.id === 'initial-compromise' && item.status === 'assumed'));
  assert.ok(path.description.includes('conditional'));
  assert.ok(!result.claims.some((claim) => claim.tier === 'validated-behavior'));
});

test('disabling automatic API tokens blocks this specific workload credential path without claiming all access is impossible', async () => {
  const { analyzeAttackPaths } = await analysis();
  const evidence = diagnosisEvidence();
  for (const id of ['pods', 'deployments']) evidence.sources[id].data.items[0].pod.spec.automountServiceAccountToken = false;
  const graph = buildGraph([evidence], options());
  const result = analyzeAttackPaths(graph, { scenario: scenario(), maxPaths: 100 });
  const path = result.claims.find((claim) => claim.predicate === 'workload-to-kubernetes-secrets');
  assert.ok(path);
  assert.equal(path.stance, 'refutes');
  assert.ok(path.path.prerequisites.some((item) => item.id === 'api-token' && item.status === 'blocked'));
  assert.ok(path.description.includes('other credential'));
});

test('cross-subscription Azure identity paths preserve conditions and unresolved effective-access constraints', async () => {
  const { analyzeAttackPaths } = await analysis();
  const evidence = diagnosisEvidence();
  evidence.sources.roleAssignments.data.items[0].hasCondition = true;
  const graph = buildGraph([evidence], options());
  const identity = principalId(diagnosisTenant, diagnosisPrincipal);
  const result = analyzeAttackPaths(graph, { scenario: scenario({ assumedCompromise: [identity] }), maxPaths: 100 });
  const path = result.claims.find((claim) => claim.predicate === 'identity-to-azure-data');
  assert.ok(path);
  assert.equal(path.tier, 'configured-exposure');
  assert.ok(path.path.prerequisites.some((item) => item.id === 'role-conditions' && item.status === 'unknown'));
  assert.ok(path.scope.resourceId.includes(diagnosisSubscriptions[1]));
});

test('path enumeration has an explicit limit and reports incomplete analysis rather than silently omitting hypotheses', async () => {
  const { analyzeAttackPaths } = await analysis();
  const graph = buildGraph([diagnosisEvidence()], options());
  const result = analyzeAttackPaths(graph, { scenario: scenario(), maxPaths: 1 });
  assert.equal(result.claims.length, 1);
  assert.ok(result.gaps.some((gap) => gap.code === 'PATH_LIMIT'));
});

test('conflicting settings yield inconclusive exposure claims, not a selected healthy snapshot', async () => {
  const { analyzeExposures } = await analysis();
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  second.sources.relatedResources.data.items[1].configuration.allowBlobPublicAccess = true;
  const result = analyzeExposures(buildGraph([first, second], options()), { scenario: scenario() });
  assert.ok(result.claims.some((claim) => claim.predicate === 'dependency-configuration-conflict' && claim.stance === 'inconclusive'));
});

test('group-derived native RBAC grants participate in workload blast-radius paths', async () => {
  const { analyzeAttackPaths } = await analysis();
  const evidence = diagnosisEvidence();
  evidence.sources.rolebindings.data.items[0].subjects = [{ kind: 'Group', name: 'system:serviceaccounts:payments' }];
  const graph = buildGraph([evidence], options());
  const result = analyzeAttackPaths(graph, { scenario: scenario(), maxPaths: 100 });
  assert.ok(result.claims.some((claim) => claim.predicate === 'workload-to-kubernetes-secrets'
    && claim.path.edges.some((id) => graph.edges.find((edge) => edge.id === id)?.relationship === 'member-of')));
});

test('a vault using access policies blocks this specific Azure-RBAC data-access hypothesis', async () => {
  const { analyzeAttackPaths } = await analysis();
  const evidence = diagnosisEvidence();
  const vault = `/subscriptions/${diagnosisSubscriptions[1]}/resourceGroups/shared/providers/Microsoft.KeyVault/vaults/shared-vault`;
  Object.assign(evidence.sources.relatedResources.data.items[1], {
    id: vault, type: 'Microsoft.KeyVault/vaults', configuration: { enableRbacAuthorization: false }
  });
  Object.assign(evidence.sources.roleAssignments.data.items[0], {
    id: `${vault}/providers/Microsoft.Authorization/roleAssignments/50000000-0000-0000-0000-000000000001`, scope: vault
  });
  evidence.sources.roleDefinitions.data.items[0].permissions[0].dataActions = ['Microsoft.KeyVault/vaults/secrets/getSecret/action'];
  const graph = buildGraph([evidence], options());
  const result = analyzeAttackPaths(graph, { scenario: scenario({ assumedCompromise: [principalId(diagnosisTenant, diagnosisPrincipal)] }), maxPaths: 100 });
  const path = result.claims.find((claim) => claim.predicate === 'identity-to-azure-data');
  assert.equal(path.stance, 'refutes');
  assert.ok(path.path.prerequisites.some((item) => item.id === 'resource-authorization-mode' && item.status === 'blocked'));
});

test('private API intent is assessed by the exposure strategy without requiring the configuration adapter', async () => {
  const { analyzeExposures } = await analysis();
  const result = analyzeExposures(buildGraph([diagnosisEvidence()], options()), { scenario: { ...scenario(), apiAccess: 'private' } });
  assert.ok(result.claims.some((claim) => claim.predicate === 'api-scenario-exposure' && claim.stance === 'supports'));
});
