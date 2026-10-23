import { binding, targetClusterId } from '../collector.mjs';
import { inScope } from '../projection.mjs';
import { canonical, stableId } from './graph.mjs';
import { isGuid } from '../scope.mjs';
import { syntheticResources } from '../active.mjs';

export function intrusiveRequirements(suite, namespace) {
  const requirements = [
    { group: '', resource: 'namespaces', verb: 'create', namespace: null },
    { group: '', resource: 'namespaces', verb: 'get', namespace: null, name: namespace },
    { group: '', resource: 'namespaces', verb: 'delete', namespace: null, name: namespace },
    { group: '', resource: 'resourcequotas', verb: 'create', namespace },
    { group: 'networking.k8s.io', resource: 'networkpolicies', verb: 'create', namespace },
    { group: '', resource: 'services', verb: 'create', namespace },
    { group: 'batch', resource: 'jobs', verb: 'create', namespace },
    { group: '', resource: 'pods', verb: 'list', namespace }
  ];
  if (suite === 'security' || suite === 'all') requirements.push({ group: '', resource: 'pods', verb: 'create', namespace });
  if (suite === 'connectivity' || suite === 'all') requirements.push({ group: '', resource: 'pods', subresource: 'exec', verb: 'create', namespace });
  if (['end-to-end', 'load', 'all'].includes(suite)) requirements.push(
    { group: '', resource: 'services', verb: 'get', namespace,
      name: syntheticResources(namespace, 'preflight').items.find((item) => item.kind === 'Service').metadata.name },
    { group: '', resource: 'pods', subresource: 'portforward', verb: 'create', namespace });
  return requirements;
}

export function approvalReasons(approval, target, now, namespace) {
  const reasons = [];
  if (!approval.approved) reasons.push('Separate stage approval was not supplied.');
  if (!approval.contexts.includes(target.context)) reasons.push('Exact Kubernetes context was not approved.');
  if (!approval.expiresAt || Date.parse(approval.expiresAt) <= now.getTime()) reasons.push('Stage approval is missing or expired.');
  const correlated = binding(target.evidence);
  if (correlated.status !== 'verified' || correlated.mode === 'arm-only') reasons.push('Verified context-to-ARM identity is required.');
  if (namespace !== undefined && (!approval.namespaces.includes(namespace) || !inScope(namespace, target.evidence.scope))) {
    reasons.push('Namespace is outside the explicit approval or assessment scope.');
  }
  return reasons;
}

export function planAssessment(bundles, assessment, { now = new Date(), records = [] } = {}) {
  const actions = [];
  const add = (target, stage, testId, namespace, reasons, extra = {}) => {
    const id = stableId('action', [target.clusterId, target.context, stage, testId,
      testId === 'intrusive-preflight' ? extra.forActionId : namespace ?? null]);
    const previous = records.filter((record) => record.actionId === id).at(-1);
    const action = { id, stage, testId, clusterId: target.clusterId, context: target.context,
      namespace: namespace ?? null, status: reasons.length ? 'blocked' : 'ready',
      permissionStatus: 'unknown', reasons, ...extra };
    if (previous && !reasons.length) action.status = previous.status === 'completed' ? 'completed' : previous.status;
    actions.push(action);
    return action;
  };
  for (const evidence of [...bundles].sort((a, b) => a.target.context.localeCompare(b.target.context, 'en'))) {
    const clusterId = (evidence.sources.cluster?.data?.id ?? targetClusterId(evidence.target)).toLowerCase();
    const target = { clusterId, context: evidence.target.context, evidence };
    const passive = add(target, 'passive', 'collect-passive-evidence', null, []);
    passive.status = Object.values(evidence.sources).some((record) => record.status === 'error') ? 'partial' : 'collected';
    passive.permissions = Object.entries(evidence.sources).map(([sourceId, record]) => ({
      sourceId, status: record.status === 'ok' ? 'observed-read' : record.error?.code === 'FORBIDDEN' ? 'denied' : 'unknown',
      commands: record.commands ?? []
    }));
    if (!assessment.strategies.includes('validation')) continue;
    const nonMutating = assessment.approvals.nonMutating;
    const intrusive = assessment.approvals.intrusive;
    if (assessment.stages.includes('non-mutating')) {
      const tests = nonMutating.tests.filter((id) => id !== 'intrusive-preflight');
      if (!nonMutating.tests.length) add(target, 'non-mutating', 'non-mutating-stage', null, approvalReasons(nonMutating, target, now));
      for (const testId of tests) {
        for (const namespace of nonMutating.namespaces.length ? nonMutating.namespaces : [null]) {
          add(target, 'non-mutating', testId, namespace,
            approvalReasons(nonMutating, target, now, namespace ?? undefined).concat(namespace === null ? ['An exact namespace approval is required.'] : []),
            { purpose: testId === 'authorization-review' ? 'Self-subject permission reviews; no secret content is requested.' : 'Privileged Pod server-side dry-run; no Pod is persisted.' });
        }
      }
    }
    if (!assessment.stages.includes('intrusive')) continue;
    const suites = intrusive.suites.length === 4 ? ['all'] : intrusive.suites.length ? intrusive.suites : ['intrusive-stage'];
    for (const suite of suites) {
      const actionId = stableId('action', [target.clusterId, target.context, 'intrusive', suite, null]);
      const preflight = records.filter((record) => record.testId === 'intrusive-preflight' && record.forActionId === actionId).at(-1);
      const reasons = approvalReasons(intrusive, target, now);
      if (!assessment.stages.includes('non-mutating') || !nonMutating.tests.includes('intrusive-preflight')
        || approvalReasons(nonMutating, target, now).length) reasons.push('An approved non-mutating intrusive-preflight stage is required.');
      let permissionStatus = 'unknown';
      if (preflight && preflight.status === 'completed' && preflight.context === target.context && preflight.clusterId === clusterId
        && isGuid(preflight.runId)
        && preflight.namespace === `aks-xray-${preflight.runId.slice(0, 18)}`
        && Date.parse(preflight.completedAt) <= now.getTime() + 300_000
        && now.getTime() - Date.parse(preflight.completedAt) <= assessment.maxEvidenceAgeHours * 3_600_000) {
        const requirements = intrusiveRequirements(suite, preflight.namespace);
        const checked = requirements.map((request) => preflight.checks?.find((check) => canonical(check.request) === canonical(request)));
        if (checked.some((check) => check?.allowed === false)) permissionStatus = 'denied';
        else if (checked.every((check) => check?.allowed === true && check.evaluationErrorPresent === false)) permissionStatus = 'allowed';
      }
      if (permissionStatus !== 'allowed') reasons.push(`Intrusive permission matrix is ${permissionStatus}; no mutation is authorized by an approval alone.`);
      const action = add(target, 'intrusive', suite, null, reasons, { permissionStatus, ownedNamespace: preflight?.namespace ?? null,
        purpose: 'Only new owned synthetic resources; fixed request, duration and cleanup limits.' });
      if (assessment.stages.includes('non-mutating') && nonMutating.tests.includes('intrusive-preflight')) {
        add(target, 'non-mutating', 'intrusive-preflight', null,
          approvalReasons(nonMutating, target, now).concat(approvalReasons(intrusive, target, now)),
          { forActionId: action.id, suite, purpose: 'Review exact future canary namespace/create/delete/exec/forward permissions before mutation.' });
      }
    }
  }
  return {
    schemaVersion: '1.0', strategies: assessment.strategies, stages: assessment.stages, actions,
    summary: { blocked: actions.filter((action) => action.status === 'blocked').length,
      ready: actions.filter((action) => action.status === 'ready').length,
      completed: actions.filter((action) => action.status === 'completed').length },
    limitations: ['Approvals do not grant API permissions. Permission reviews are point-in-time observations, not authorization locks.',
      'Intrusive validation targets only newly owned canary resources, not arbitrary workload exploitation.']
  };
}
