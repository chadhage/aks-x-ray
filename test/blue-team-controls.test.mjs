import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../src/engine.mjs';
import { defaultScope } from '../src/evidence.mjs';
import { demoEvidence } from '../examples/demo.mjs';

function fixture() {
  return demoEvidence('cloud', defaultScope({ scenario: {
    name: 'Private production', profile: 'production', apiAccess: 'private', minimumReplicas: 3, minimumZones: 3,
    allowedRegistries: ['example.invalid']
  } }));
}
const source = (evidence, id) => evidence.sources[id].data.items;
const finding = (evidence, id) => assess(evidence).results.find((result) => result.id === id);
const containerChange = (evidence, change) => ['pods', 'deployments'].forEach((id) => {
  const spec = source(evidence, id)[0].pod.spec;
  change(spec.containers[0], spec);
});
const dependency = (evidence, type) => source(evidence, 'relatedResources').find((item) => item.type.toLowerCase() === type).configuration;

const cases = [
  ['CP-004', 'fail', () => {}],
  ['CP-004', 'pass', (e) => { e.sources.cluster.data.apiServerAccessProfile.enablePrivateCluster = true; }],
  ['REL-006', 'fail', () => {}],
  ['REL-006', 'pass', (e) => { source(e, 'deployments')[0].replicas = 3; }],
  ['REL-007', 'pass', () => {}],
  ['REL-007', 'fail', (e) => { source(e, 'nodepools')[0].availabilityZones = ['1', '2']; }],
  ['SEC-011', 'pass', (e) => containerChange(e, (c) => { c.securityContext.readOnlyRootFilesystem = true; })],
  ['SEC-011', 'fail', (e) => containerChange(e, (c) => { c.securityContext.readOnlyRootFilesystem = false; })],
  ['SEC-012', 'pass', () => {}],
  ['SEC-012', 'fail', (e) => { source(e, 'serviceaccounts')[0].automountServiceAccountToken = true; }],
  ['SEC-012', 'pass', (e) => { source(e, 'serviceaccounts')[0].automountServiceAccountToken = true; containerChange(e, (c, spec) => { spec.automountServiceAccountToken = false; }); }],
  ['SEC-013', 'pass', () => {}],
  ['SEC-013', 'fail', (e) => { source(e, 'validatingwebhooks')[0].webhooks[0].failurePolicy = 'Ignore'; }],
  ['SEC-014', 'pass', () => {}],
  ['SEC-014', 'fail', (e) => { source(e, 'defenderPricing')[0].pricingTier = 'Free'; }],
  ['SEC-014', 'unknown', (e) => { delete source(e, 'defenderPricing')[0].pricingTier; }],
  ['SEC-015', 'pass', () => {}],
  ['SEC-015', 'fail', (e) => { source(e, 'defenderAssessments')[0].status.code = 'Unhealthy'; }],
  ['SEC-015', 'review', (e) => { e.sources.defenderAssessments.data.items = []; }],
  ['SEC-015', 'unknown', (e) => { source(e, 'defenderAssessments')[0].status.code = 'Unknown'; }],
  ['SEC-016', 'pass', () => {}],
  ['SEC-016', 'fail', (e) => containerChange(e, (c) => { c.image = 'unapproved.example.invalid/app:v1'; })],
  ['ID-007', 'review', () => {}],
  ['ID-008', 'pass', () => {}],
  ['ID-008', 'fail', (e) => { source(e, 'clusterrolebindings')[0].subjects = [{ kind: 'Group', name: 'system:unauthenticated' }]; }],
  ['ID-008', 'unknown', (e) => { source(e, 'clusterrolebindings')[0].subjects = [{ kind: 'Group', name: 'system:unauthenticated' }];
    source(e, 'clusterrolebindings')[0].roleRef.name = 'unresolved-custom-role'; }],
  ['GOV-004', 'pass', () => {}],
  ['GOV-004', 'fail', (e) => { source(e, 'policyStates')[0].complianceState = 'NonCompliant'; }],
  ['GOV-004', 'review', (e) => { source(e, 'policyStates')[0].complianceState = 'Exempt'; }],
  ['GOV-004', 'review', (e) => { e.sources.policyStates.data.items = []; }],
  ['GOV-005', 'pass', () => {}],
  ['GOV-005', 'fail', (e) => { source(e, 'namespaces')[0].metadata.labels['pod-security.kubernetes.io/enforce'] = 'baseline'; }],
  ['CST-004', 'review', () => {}],
  ['DEP-001', 'pass', () => {}],
  ['DEP-001', 'fail', (e) => { dependency(e, 'microsoft.containerregistry/registries').adminUserEnabled = true; }],
  ['DEP-001', 'unknown', (e) => { delete dependency(e, 'microsoft.containerregistry/registries').adminUserEnabled; }],
  ['DEP-002', 'pass', () => {}],
  ['DEP-002', 'fail', (e) => { dependency(e, 'microsoft.keyvault/vaults').enablePurgeProtection = false; }],
  ['DEP-003', 'pass', () => {}],
  ['DEP-003', 'fail', (e) => { dependency(e, 'microsoft.storage/storageaccounts').minimumTlsVersion = 'TLS1_0'; }],
  ['DEP-003', 'unknown', (e) => { delete dependency(e, 'microsoft.storage/storageaccounts').supportsHttpsTrafficOnly; }],
  ['DEP-004', 'pass', () => {}],
  ['DEP-004', 'fail', (e) => { dependency(e, 'microsoft.network/networksecuritygroups').securityRules.push({
    name: 'public-ssh', direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: '*', destinationPortRange: '22'
  }); }],
  ['DEP-004', 'fail', (e) => { dependency(e, 'microsoft.network/networksecuritygroups').securityRules.push({
    name: 'public-rdp-range', direction: 'Inbound', access: 'Allow', protocol: '*', sourceAddressPrefixes: ['Internet'], destinationPortRanges: ['3000-4000']
  }); }],
  ['DEP-004', 'unknown', (e) => { dependency(e, 'microsoft.network/networksecuritygroups').securityRules.push({
    name: 'missing-protocol', direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '*', destinationPortRange: '22'
  }); }],
  ['DEP-004', 'fail', (e) => { dependency(e, 'microsoft.network/networksecuritygroups').securityRules.push({
    name: 'expanded-ipv6-default', direction: 'Inbound', access: 'Allow', protocol: 'Tcp',
    sourceAddressPrefix: '0:0:0:0:0:0:0:0/0', destinationPortRange: '22'
  }); }],
  ['DEP-005', 'pass', () => {}],
  ['DEP-005', 'fail', (e) => { delete dependency(e, 'microsoft.network/virtualnetworks/subnets').networkSecurityGroupId; }],
  ['DEP-006', 'pass', () => {}],
  ['DEP-006', 'fail', (e) => { dependency(e, 'microsoft.keyvault/vaults').enableRbacAuthorization = false; }]
];

for (const [index, [id, expected, change]] of cases.entries()) {
  test(`${id}: Blue Team boundary ${index + 1} yields ${expected}`, () => {
    const evidence = fixture();
    change(evidence);
    const result = finding(evidence, id);
    assert.ok(result, `${id} must exist in the control catalogue.`);
    assert.equal(result.status, expected, result.message);
  });
}

test('scenario controls do not invent workload intent when no scenario was supplied', () => {
  const evidence = demoEvidence();
  for (const id of ['CP-004', 'REL-006', 'REL-007', 'SEC-016']) assert.equal(finding(evidence, id).status, 'notApplicable');
});

test('dependency failures preserve evidence gaps instead of passing secure defaults', () => {
  const evidence = fixture();
  evidence.sources.relatedResources = { status: 'error', collectedAt: evidence.collectedAt,
    error: { code: 'FORBIDDEN', message: 'Dependency permissions are unavailable.' } };
  for (const id of ['DEP-001', 'DEP-002', 'DEP-003', 'DEP-004', 'DEP-005', 'DEP-006']) {
    const result = finding(evidence, id);
    assert.equal(result.status, 'unknown');
    assert.equal(result.score, null);
  }
});

test('dependency inventory remains an explicit review, including unsupported resource types', () => {
  const evidence = fixture();
  source(evidence, 'relatedResources').push({ id: '/subscriptions/synthetic/unsupported', name: 'unsupported',
    type: 'Microsoft.Example/unsupported', supported: false, configuration: {}, linkedResourceIds: [] });
  const report = assess(evidence);
  const result = report.results.find((item) => item.id === 'DEP-007');
  assert.ok(result);
  assert.equal(result.status, 'review');
  assert.equal(result.score, null);
  assert.equal(result.observed.relatedResources.count, 6);
  assert.ok(report.ratings.areas.find((area) => area.id === 'dependencies').coveragePercent < 100);
});

test('known insecure dependency settings remain failures while missing companion settings suppress scoring', () => {
  const evidence = fixture();
  const storage = dependency(evidence, 'microsoft.storage/storageaccounts');
  storage.allowBlobPublicAccess = true;
  delete storage.supportsHttpsTrafficOnly;
  const result = finding(evidence, 'DEP-003');
  assert.equal(result.status, 'fail');
  assert.equal(result.incomplete, true);
  assert.equal(result.score, null);
});
