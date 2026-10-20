import test from 'node:test';
import assert from 'node:assert/strict';
import { demoEvidence } from '../examples/demo.mjs';
import { assess } from '../src/engine.mjs';

const workloads = (evidence) => ['deployments', 'pods'].map((id) => evidence.sources[id].data.items[0]);
const mutateContainers = (evidence, change) => workloads(evidence).forEach((workload) => change(workload.pod.spec.containers[0], workload.pod.spec));
const cloud = (evidence) => evidence.sources.cluster.data;
const cases = [
  ['CP-002', 'fail', (e) => { cloud(e).apiServerAccessProfile.authorizedIpRanges = ['0.0.0.0/0']; }],
  ['CP-003', 'fail', (e) => { cloud(e).sku.tier = 'Free'; }],
  ['ID-001', 'fail', (e) => { cloud(e).enableRBAC = false; }],
  ['ID-002', 'fail', (e) => { cloud(e).aadProfile.managed = false; }],
  ['ID-003', 'fail', (e) => { cloud(e).disableLocalAccounts = false; }],
  ['ID-004', 'fail', (e) => { cloud(e).oidcIssuerProfile.enabled = false; }],
  ['ID-006', 'fail', (e) => workloads(e).forEach((w) => { w.pod.spec.serviceAccountName = 'default'; })],
  ['ND-001', 'fail', (e) => { e.sources.nodes.data.items[0].conditions[0].status = 'False'; }],
  ['ND-002', 'fail', (e) => { e.sources.nodes.data.items[0].conditions[1].status = 'True'; }],
  ['ND-003', 'fail', (e) => { e.sources.nodepools.data.items[0].count = 1; }],
  ['ND-004', 'fail', (e) => { e.sources.nodepools.data.items[0].nodeTaints = []; }],
  ['NET-001', 'fail', (e) => { cloud(e).networkProfile.networkDataplane = 'azure'; cloud(e).networkProfile.networkPolicy = 'none'; }],
  ['NET-002', 'fail', (e) => { e.sources.networkpolicies.data.items[0].spec.policyTypes = ['Ingress']; }],
  ['NET-004', 'pass', (e) => { e.sources.ingresses.data.items[0].tls = [{ hosts: ['checkout.example.invalid'] }]; }],
  ['NET-005', 'fail', (e) => { e.sources.endpointslices.data.items[0].endpoints[0].ready = false; }],
  ['NET-005', 'unknown', (e) => { delete e.sources.endpointslices.data.items[0].endpoints[0].ready; }],
  ['NET-006', 'fail', (e) => { cloud(e).networkProfile.podCidr = '10.0.16.0/20'; }],
  ['NET-006', 'fail', (e) => { cloud(e).networkProfile.dnsServiceIP = '192.0.2.5'; }],
  ['SEC-001', 'fail', (e) => mutateContainers(e, (c) => { c.securityContext.privileged = true; })],
  ['SEC-001', 'fail', (e) => mutateContainers(e, (c) => { c.securityContext.windowsOptions = { hostProcess: true }; })],
  ['SEC-002', 'fail', (e) => mutateContainers(e, (c) => { delete c.securityContext.allowPrivilegeEscalation; })],
  ['SEC-003', 'fail', (e) => mutateContainers(e, (c) => { c.securityContext.runAsUser = 0; })],
  ['SEC-004', 'fail', (e) => mutateContainers(e, (c) => { c.securityContext.capabilities.add = ['NET_ADMIN']; })],
  ['SEC-005', 'fail', (e) => workloads(e).forEach((w) => { w.pod.spec.hostNetwork = true; })],
  ['SEC-006', 'fail', (e) => workloads(e).forEach((w) => { w.pod.spec.volumes = [{ name: 'host', type: 'hostPath' }]; })],
  ['SEC-007', 'fail', (e) => workloads(e).forEach((w) => { w.pod.spec.securityContext.seccompProfile.type = 'Unconfined'; })],
  ['SEC-008', 'pass', (e) => mutateContainers(e, (c) => { c.image = `example.invalid/app@sha256:${'a'.repeat(64)}`; })],
  ['SEC-008', 'fail', (e) => mutateContainers(e, (c) => { c.image = 'example.invalid:5000/untagged'; })],
  ['SEC-009', 'fail', (e) => { cloud(e).securityProfile.defender.securityMonitoring.enabled = false; }],
  ['WK-001', 'fail', (e) => mutateContainers(e, (c) => { delete c.resources.requests.memory; })],
  ['WK-002', 'fail', (e) => mutateContainers(e, (c) => { c.resources.limits.cpu = '0'; })],
  ['WK-003', 'fail', (e) => mutateContainers(e, (c) => { c.probes.readiness = false; })],
  ['WK-004', 'pass', (e) => mutateContainers(e, (c) => { c.resources.limits.cpu = '500m'; })],
  ['WK-005', 'pass', (e) => { e.sources.deployments.data.items[0].availableReplicas = 2; }],
  ['WK-006', 'fail', (e) => { e.sources.hpas.data.items[0].maxReplicas = 1; }],
  ['WK-007', 'fail', (e) => { e.sources.pods.data.items[0].containerStatuses[0].waitingReason = 'CrashLoopBackOff'; }],
  ['WK-007', 'review', (e) => { e.sources.pods.data.items[0].phase = 'Pending'; }],
  ['REL-001', 'fail', (e) => { e.sources.deployments.data.items[0].replicas = 1; }],
  ['REL-002', 'fail', (e) => { e.sources.pdbs.data.items[0].spec.selector.matchLabels.app = 'unrelated'; }],
  ['REL-003', 'pass', (e) => workloads(e).forEach((w) => { w.pod.spec.topologySpreadConstraints = [{ topologyKey: 'kubernetes.io/hostname' }]; })],
  ['REL-004', 'fail', (e) => { e.sources.nodepools.data.items[0].availabilityZones = ['1']; }],
  ['REL-005', 'pass', (e) => { e.sources.pdbs.data.items[0].spec.minAvailable = 1; }],
  ['REL-005', 'unknown', (e) => { e.sources.pdbs.data.items[0].status.expectedPods = 3; }],
  ['ST-001', 'fail', (e) => { e.sources.pvcs.data.items[0].phase = 'Pending'; }],
  ['ST-002', 'fail', (e) => { e.sources.storageclasses.data.items[0].volumeBindingMode = 'Immediate'; }],
  ['OBS-001', 'fail', (e) => { e.sources.diagnostics.data.items[0].logs[0].enabled = false; }],
  ['OBS-002', 'fail', (e) => { cloud(e).azureMonitorProfile.metrics.enabled = false; }],
  ['OBS-003', 'pass', (e) => { cloud(e).addonProfiles.omsagent.enabled = true; }],
  ['GOV-001', 'fail', (e) => { cloud(e).addonProfiles.azurepolicy.enabled = false; }],
  ['GOV-002', 'fail', (e) => { e.sources.resourcequotas.data.items = []; }],
  ['CST-001', 'fail', (e) => { e.sources.nodepools.data.items[1].enableAutoScaling = false; }],
  ['CST-002', 'fail', (e) => { e.sources.nodepools.data.items[1].minCount = 6; }],
  ['CST-002', 'pass', (e) => { e.sources.nodepools.data.items[1].count = 100; }],
  ['LC-001', 'fail', (e) => { cloud(e).autoUpgradeProfile.upgradeChannel = 'none'; }],
  ['LC-002', 'fail', (e) => { cloud(e).autoUpgradeProfile.nodeOSUpgradeChannel = 'None'; }],
  ['LC-003', 'fail', (e) => { e.sources.maintenance.data.items = [{ name: 'default', maintenanceWindow: { durationHours: 4 } }]; }]
];

for (const [index, [id, status, mutate]] of cases.entries()) {
  test(`${id}: negative/repair boundary ${index + 1} yields ${status}`, () => {
    const evidence = demoEvidence();
    mutate(evidence);
    const finding = assess(evidence).results.find((result) => result.id === id);
    assert.equal(finding.status, status, finding.message);
  });
}

test('Automatic does not inherit operator-managed system-pool assumptions', () => {
  const evidence = demoEvidence();
  cloud(evidence).sku.name = 'Automatic';
  evidence.sources.nodepools.data.items = [];
  for (const id of ['ND-003', 'ND-004', 'REL-004']) {
    assert.equal(assess(evidence).results.find((result) => result.id === id).status, 'review');
  }
});

test('Local provisioning failure and missing control-plane count remain distinct', () => {
  const evidence = demoEvidence('local');
  cloud(evidence).provisioningState = 'Failed';
  delete cloud(evidence).controlPlane.count;
  const report = assess(evidence);
  assert.equal(report.results.find((result) => result.id === 'LOC-001').status, 'fail');
  assert.equal(report.results.find((result) => result.id === 'LOC-002').status, 'unknown');
});
