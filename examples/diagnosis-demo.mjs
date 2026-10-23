import { diagnosisEvidence, diagnosisSubscriptions, diagnosisTenant, diagnosisPrincipal, diagnosisTimestamp } from './diagnosis-fixture.mjs';
import { kubeId, principalId } from '../src/diagnosis/graph.mjs';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';

export function diagnosisDemo(strategies) {
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  for (const id of ['pods', 'deployments']) first.sources[id].data.items[0].pod.spec.containers[0].securityContext.privileged = true;
  const cluster = first.sources.cluster.data.id.toLowerCase();
  const actor = 'synthetic-auditor';
  const subject = kubeId(cluster, 'Identity-User', undefined, actor);
  const validations = [{
    id: 'synthetic-authorization-receipt', actionId: 'synthetic-review', testId: 'authorization-review',
    stage: 'non-mutating', status: 'completed', method: 'SelfSubjectAccessReview', synthetic: true,
    clusterId: cluster, context: first.target.context, namespace: 'payments', subject, predicate: 'can-list-secrets',
    value: true, startedAt: diagnosisTimestamp, completedAt: diagnosisTimestamp,
    authenticatedSubject: { username: actor, uid: 'synthetic-user' },
    authenticatedSubjectAfter: { username: actor, uid: 'synthetic-user' },
    request: { group: '', resource: 'secrets', verb: 'list', namespace: 'payments' },
    response: { allowed: true, denied: false, evaluationErrorPresent: false },
    commands: [
      { file: 'kubectl', args: ['--context', first.target.context, 'auth', 'whoami', '--output=json'] },
      { file: 'kubectl', args: ['--context', first.target.context, 'create', '--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', '--filename=-'] },
      { file: 'kubectl', args: ['--context', first.target.context, 'auth', 'whoami', '--output=json'] }
    ]
  }];
  return {
    bundles: [first, second], tenant: diagnosisTenant, subscriptions: [...diagnosisSubscriptions],
    assessment: normalizeAssessment({ strategies, stages: ['passive'] }), validations,
    scenario: { ...first.scope.scenario, name: 'SYNTHETIC public API with sensitive shared data',
      businessCriticality: 'critical', dataSensitivity: 'restricted', applicationExposure: 'public',
      assumedCompromise: [kubeId(cluster, 'Pod', 'payments', 'checkout-example'), principalId(diagnosisTenant, diagnosisPrincipal)] },
    now: new Date(diagnosisTimestamp)
  };
}
